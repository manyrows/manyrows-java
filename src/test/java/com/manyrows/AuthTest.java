package com.manyrows;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AuthTest covers:
 * <ul>
 *   <li>{@link Auth#bearerToken(String)} — Authorization header parsing.</li>
 *   <li>{@link Auth#mrAtCookie(String, String)} — Cookie header parsing.</li>
 *   <li>{@link Auth#verifyToken(String, String, String, String)} —
 *       end-to-end JWKS fetch + ES256 verification, exercised against a
 *       loopback {@link HttpServer} that serves a real JWKS payload.</li>
 *   <li>{@link Auth#verifyToken(String, String, JWKSource)} — the test seam
 *       that takes an in-memory JWKSource (used for negative cases that
 *       don't need an HTTP round trip).</li>
 * </ul>
 */
class AuthTest {

    private static final String WORKSPACE = "acme";
    private static final String APP_ID = "app_123";

    private ECKey signingKey;
    private JWKSet jwks;
    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void setup() throws Exception {
        signingKey = new ECKeyGenerator(Curve.P_256)
                .keyID("test-kid-" + System.nanoTime())
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        jwks = new JWKSet(signingKey.toPublicJWK());

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/.well-known/jwks.json", exchange -> {
            byte[] body = jwks.toJSONObject().toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        // Each test gets a clean processor cache so a previous test's
        // server (different port) doesn't bleed into the current test.
        Auth.resetCacheForTest();
    }

    @AfterEach
    void teardown() {
        if (server != null) {
            server.stop(0);
        }
        Auth.resetCacheForTest();
    }

    private String signToken(String sub, long expSecondsFromNow) throws JOSEException {
        return signToken(sub, expSecondsFromNow, APP_ID);
    }

    private String signToken(String sub, long expSecondsFromNow, String aud) throws JOSEException {
        return signToken(sub, expSecondsFromNow, aud, baseUrl);
    }

    private String signToken(String sub, long expSecondsFromNow, String aud, String iss) throws JOSEException {
        long now = System.currentTimeMillis() / 1000;
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub)
                .audience(aud)
                .issuer(iss)
                .issueTime(new Date(now * 1000))
                .expirationTime(new Date((now + expSecondsFromNow) * 1000))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    // ===== bearerToken =====

    @Nested
    class BearerToken {

        @Test
        void extractsTokenAfterBearerPrefix() {
            assertEquals(Optional.of("abc123"), Auth.bearerToken("Bearer abc123"));
        }

        @Test
        void isCaseInsensitiveOnPrefix() {
            assertEquals(Optional.of("abc"), Auth.bearerToken("bearer abc"));
            assertEquals(Optional.of("abc"), Auth.bearerToken("BEARER abc"));
            assertEquals(Optional.of("abc"), Auth.bearerToken("BeArEr abc"));
        }

        @Test
        void trimsSurroundingWhitespace() {
            assertEquals(Optional.of("abc"), Auth.bearerToken("  Bearer   abc   "));
        }

        @Test
        void returnsEmptyForMissingOrWrongInput() {
            assertTrue(Auth.bearerToken(null).isEmpty());
            assertTrue(Auth.bearerToken("").isEmpty());
            assertTrue(Auth.bearerToken("Basic xyz").isEmpty());
            assertTrue(Auth.bearerToken("Bearer ").isEmpty());
            assertTrue(Auth.bearerToken("Bearer").isEmpty());
        }
    }

    // ===== mrAtCookie =====

    @Nested
    class MrAtCookie {

        private static final String COOKIE_NAME = "mr_at_app_123";

        @Test
        void extractsPerAppValue() {
            assertEquals(Optional.of("abc123"), Auth.mrAtCookie(COOKIE_NAME + "=abc123", APP_ID));
        }

        @Test
        void ignoresOtherCookiesAndWhitespace() {
            assertEquals(Optional.of("abc"),
                    Auth.mrAtCookie("foo=1; " + COOKIE_NAME + "=abc; bar=2", APP_ID));
            assertEquals(Optional.of("abc"),
                    Auth.mrAtCookie("  " + COOKIE_NAME + "=abc  ", APP_ID));
        }

        @Test
        void handlesValuesContainingEquals() {
            assertEquals(Optional.of("eyJ.payload=xyz"),
                    Auth.mrAtCookie(COOKIE_NAME + "=eyJ.payload=xyz", APP_ID));
        }

        @Test
        void ignoresADifferentAppsCookie() {
            assertTrue(Auth.mrAtCookie("mr_at_app_other=abc", APP_ID).isEmpty());
        }

        @Test
        void returnsEmptyWhenAbsentOrEmpty() {
            assertTrue(Auth.mrAtCookie(null, APP_ID).isEmpty());
            assertTrue(Auth.mrAtCookie("", APP_ID).isEmpty());
            assertTrue(Auth.mrAtCookie("foo=1; bar=2", APP_ID).isEmpty());
            assertTrue(Auth.mrAtCookie(COOKIE_NAME + "=", APP_ID).isEmpty());
        }
    }

    // ===== verifyToken (against the loopback HTTP server) =====

    @Nested
    class VerifyTokenLive {

        @Test
        void returnsSubOnAValidToken() throws Exception {
            String tok = signToken("user_xyz", 300);
            assertEquals(Optional.of("user_xyz"),
                    Auth.verifyToken(tok, baseUrl, WORKSPACE, APP_ID));
        }

        @Test
        void returnsEmptyForEmptyTokenWithNoNetworkCall() {
            // No HTTP server interaction expected — Auth short-circuits
            // on empty/null and the cache is also empty here, so a
            // network call would have happened if it was going to.
            assertTrue(Auth.verifyToken("", baseUrl, WORKSPACE, APP_ID).isEmpty());
            assertTrue(Auth.verifyToken(null, baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void returnsEmptyForMalformedJwt() {
            assertTrue(Auth.verifyToken("not.a.jwt", baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void returnsEmptyForExpiredToken() throws Exception {
            // Far past the 60s default leeway.
            String tok = signToken("user_xyz", -3600);
            assertTrue(Auth.verifyToken(tok, baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void returnsEmptyWhenSubMissing() throws Exception {
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience(APP_ID)
                    .issueTime(new Date(now * 1000))
                    .expirationTime(new Date((now + 300) * 1000))
                    .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(signingKey.getKeyID())
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(signingKey));
            assertTrue(Auth.verifyToken(jwt.serialize(), baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void rejectsTokenMintedForDifferentApp() throws Exception {
            // Cross-app cookie ride-along: a token with aud=app_other
            // must not authenticate a request landing on the middleware
            // configured for APP_ID. Catches sibling-subdomain cookie
            // reuse between two ManyRows apps on the same eTLD.
            String tok = signToken("user_xyz", 300, "app_other");
            assertTrue(Auth.verifyToken(tok, baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void rejectsIssMismatch() throws Exception {
            // iss check: a token signed by this install but claiming
            // a different issuer must be rejected. Defends against
            // cross-install replay if a signing key ever leaked across
            // deployments.
            String tok = signToken("user_xyz", 300, APP_ID, "https://other-install.example.com");
            assertTrue(Auth.verifyToken(tok, baseUrl, WORKSPACE, APP_ID).isEmpty());
        }

        @Test
        void toleratesTrailingSlashOnIss() throws Exception {
            // iss with a trailing slash matches a baseUrl without one
            // (and vice versa) — operator shouldn't have to think
            // about which form the server emits.
            String tok = signToken("user_xyz", 300, APP_ID, baseUrl + "/");
            assertEquals(Optional.of("user_xyz"),
                    Auth.verifyToken(tok, baseUrl, WORKSPACE, APP_ID));
        }

        @Test
        void rejectsPlainHttpBaseUrl() {
            // H5: plaintext JWKS fetches are MITM-able. Misconfigured
            // baseURL is a fatal config error, not a per-request
            // failure mode — surfaces as IllegalArgumentException so
            // the deploy fails at first verify.
            assertThrows(IllegalArgumentException.class,
                    () -> Auth.verifyToken("any.token.value", "http://app.example.com", WORKSPACE, APP_ID));
        }

        @Test
        void allowsLocalhostHttpForDev() {
            // Localhost loops are routinely plaintext; allow them so
            // dev iterations don't need self-signed certs.
            assertDoesNotThrow(() ->
                    Auth.verifyToken("any.token.value", "http://localhost:8080", WORKSPACE, APP_ID));
        }
    }

    // ===== verifyToken (test seam — in-memory JWKSource) =====

    @Nested
    class VerifyTokenInMemory {

        @Test
        void returnsEmptyWhenKidNotInJwks() throws Exception {
            String tok = signToken("user_xyz", 300);
            // JWKSource published from a *different* keypair.
            ECKey other = new ECKeyGenerator(Curve.P_256)
                    .keyID("other-kid")
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            JWKSource<SecurityContext> src = new ImmutableJWKSet<>(new JWKSet(other.toPublicJWK()));
            assertTrue(Auth.verifyToken(tok, APP_ID, src).isEmpty());
        }

        @Test
        void returnsEmptyWhenSignatureInvalid() throws Exception {
            // JWKS publishes pubA under kid_a. JWT carries kid_a in
            // its header but is signed with privB — verifier looks up
            // pubA successfully, then signature verification fails.
            ECKey keyA = new ECKeyGenerator(Curve.P_256)
                    .keyID("kid-a")
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            ECKey keyB = new ECKeyGenerator(Curve.P_256)
                    .keyID("kid-b")
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();

            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user_xyz")
                    .issueTime(new Date(now * 1000))
                    .expirationTime(new Date((now + 300) * 1000))
                    .build();
            // Header claims kid-a; body signed with key B.
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID("kid-a")
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(keyB));

            JWKSource<SecurityContext> src = new ImmutableJWKSet<>(
                    new JWKSet(List.of(keyA.toPublicJWK())));
            assertTrue(Auth.verifyToken(jwt.serialize(), APP_ID, src).isEmpty());
        }
    }

    // ===== stripTrailingSlashes =====

    @Test
    void stripTrailingSlashesHandlesEmptyAndMultiple() {
        assertEquals("", Auth.stripTrailingSlashes(""));
        assertEquals("a", Auth.stripTrailingSlashes("a"));
        assertEquals("a", Auth.stripTrailingSlashes("a/"));
        assertEquals("a", Auth.stripTrailingSlashes("a////"));
        assertEquals("https://app.manyrows.com", Auth.stripTrailingSlashes("https://app.manyrows.com//"));
    }

    @Test
    void mrAtCookieDistinguishesEmptyValueFromAbsent() {
        // Cookie present but empty value → empty Optional (not "string").
        Optional<String> empty = Auth.mrAtCookie("mr_at_app_123=", APP_ID);
        assertFalse(empty.isPresent());
    }

    // Suppress IDE warning for unused IOException import — kept for
    // future test additions that exercise IO error handling.
    @SuppressWarnings("unused")
    private static void _unused() throws IOException {}
}
