package com.manyrows;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local JWT verification against the install's JWKS, with cookie-mode
 * fallback for browsers that hold the session in an HttpOnly cookie
 * instead of a Bearer header. Mirrors the Go SDK's
 * {@code auth.Middleware}.
 *
 * <p>Tokens are signed ES256. The verifier fetches
 * {@code ${baseUrl}/.well-known/jwks.json} on first verify, caches the
 * keys for the Nimbus default (5 min refresh, 30s cooldown), and
 * refetches on a kid mismatch. No round trip per request; no shared
 * secret on the customer side.
 */
public final class Auth {

    static final String USER_AGENT = "manyrows-auth-java-auth/1.0";

    /** JWKS cache lifespan (ms) — aligned with Go/Node/Python SDKs at 10 minutes. */
    private static final long JWKS_CACHE_LIFESPAN_MS = 10L * 60L * 1000L;

    /** JWKS refetch timeout (ms) — Nimbus default; bounds the wait when a refetch races. */
    private static final long JWKS_REFRESH_TIMEOUT_MS = 30L * 1000L;

    /**
     * Cookie name prefix; the full name is {@code "mr_at_" + appId}. Per-app
     * naming keeps two ManyRows apps on the same eTLD from colliding in the
     * browser cookie jar. Mirrors manyrows-core's
     * {@code clientauth.AccessCookieName(appID)} — duplicated here rather
     * than imported because manyrows-auth-java doesn't depend on the core repo.
     * Keep in sync if the server-side naming ever changes.
     */
    static final String ACCESS_COOKIE_PREFIX = "mr_at_";

    static String accessCookieName(String appId) {
        return ACCESS_COOKIE_PREFIX + appId;
    }

    /**
     * Module-level cache keyed by "<jwksUrl>::<appId>". Each entry holds a
     * fully configured Nimbus JWT processor — JWKS fetcher, ES256 verifier,
     * standard claim checks bound to the app-specific aud expectation.
     * Sharing one processor across calls means concurrent verifications
     * hit the same in-memory key cache.
     */
    private static final Map<String, ConfigurableJWTProcessor<SecurityContext>> PROCESSORS =
            new ConcurrentHashMap<>();

    private Auth() {}

    /**
     * Verify a user's bearer JWT against the install's JWKS.
     *
     * @return Optional containing the user ID ({@code sub} claim) on
     *         success; empty if the token is empty, malformed,
     *         expired, fails signature verification, or carries an
     *         {@code aud} claim that doesn't include {@code appId}.
     *         Caller should treat empty as "not authenticated" and
     *         401 the request.
     *
     * <p>The {@code aud} check catches the cross-app cookie ride-along
     * between two ManyRows apps on the same eTLD — a token minted for
     * one app is rejected by another app's middleware.
     *
     * <p>{@code workspaceSlug} is currently unused; kept on the signature
     * for forward-compat (e.g. a future per-workspace check).
     */
    public static Optional<String> verifyToken(
            String token,
            String baseUrl,
            String workspaceSlug,
            String appId
    ) {
        // Reject baseURLs that would make JWKS fetches MITM-able. This
        // is a fatal config error, not a per-request failure mode — an
        // IllegalArgumentException surfaces it loudly at first verify.
        requireSecureBaseUrl(baseUrl);
        if (token == null || token.isEmpty() || appId == null || appId.isEmpty()) {
            return Optional.empty();
        }
        ConfigurableJWTProcessor<SecurityContext> processor;
        try {
            processor = processorFor(baseUrl, appId);
        } catch (MalformedURLException e) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(token, null);
            // iss check: defence-in-depth against cross-install token
            // replay. Signature already binds the token to the install,
            // but if a signing key ever leaked across deployments —
            // operator error, "promoted from staging," whatever — this
            // catch surfaces it. Trailing-slash tolerant.
            if (!issMatches(claims.getIssuer(), baseUrl)) {
                return Optional.empty();
            }
            String sub = claims.getSubject();
            return (sub != null && !sub.isEmpty()) ? Optional.of(sub) : Optional.empty();
        } catch (Exception e) {
            // Bad signature, expired, audience mismatch, malformed,
            // unknown kid, etc. — all collapse to "not authenticated."
            return Optional.empty();
        }
    }

    /**
     * Reject baseURLs that would make JWKS fetches MITM-able. Only
     * {@code https://} is accepted, with the usual localhost /
     * 127.0.0.1 / [::1] dev exceptions so local round-trips don't
     * force operators into self-signed cert dances. Throws
     * IllegalArgumentException so a misconfigured deploy fails at
     * first verify rather than silently accepting forged keys.
     */
    static void requireSecureBaseUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("manyrows auth: baseUrl is empty");
        }
        String s = raw.trim().toLowerCase();
        if (s.startsWith("https://")) {
            return;
        }
        if (s.startsWith("http://localhost")
                || s.startsWith("http://127.0.0.1")
                || s.startsWith("http://[::1]")) {
            return;
        }
        throw new IllegalArgumentException(
                "manyrows auth: baseUrl must use https:// (got \"" + raw
                        + "\") — refusing to fetch JWKS over plaintext"
        );
    }

    /**
     * Compare the JWT's iss claim to the configured baseUrl,
     * tolerating an optional trailing "/" on either side.
     */
    static boolean issMatches(String claim, String expected) {
        if (claim == null) {
            return false;
        }
        return stripTrailingSlashes(claim).equals(stripTrailingSlashes(expected));
    }

    /**
     * Test seam — verify against a caller-supplied JWKSource instead of
     * fetching from the network. Production code should use the
     * baseUrl overload.
     */
    static Optional<String> verifyToken(
            String token,
            String appId,
            JWKSource<SecurityContext> jwkSource
    ) {
        if (token == null || token.isEmpty() || appId == null || appId.isEmpty()) {
            return Optional.empty();
        }
        ConfigurableJWTProcessor<SecurityContext> processor = newProcessor(jwkSource, appId);
        try {
            JWTClaimsSet claims = processor.process(token, null);
            String sub = claims.getSubject();
            return (sub != null && !sub.isEmpty()) ? Optional.of(sub) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static ConfigurableJWTProcessor<SecurityContext> processorFor(String baseUrl, String appId)
            throws MalformedURLException {
        String jwksUrl = stripTrailingSlashes(baseUrl) + "/.well-known/jwks.json";
        // Cache key includes appId so two apps on the same install get
        // separate processors with their own aud expectations.
        String cacheKey = jwksUrl + "::" + appId;
        ConfigurableJWTProcessor<SecurityContext> cached = PROCESSORS.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        // Build outside the cache to avoid holding the cache's compute
        // lock while doing URL parsing. Race between two threads is
        // benign — both build the same processor; whichever wins gets
        // cached, the loser is GC'd.
        URL url = new URL(jwksUrl);
        // Aligned with the other-language SDKs at a 10-minute JWKS
        // cache lifespan. Nimbus's default is shorter (~5 min) which
        // is also safe, but explicit is preferable so a future Nimbus
        // upgrade can't surprise an operator who relied on rotation
        // timing. The 30-second refreshTimeout matches Nimbus's
        // default and bounds the wait when a refetch races.
        JWKSource<SecurityContext> source = JWKSourceBuilder.create(url)
                .cache(JWKS_CACHE_LIFESPAN_MS, JWKS_REFRESH_TIMEOUT_MS)
                .retrying(true)
                .build();
        ConfigurableJWTProcessor<SecurityContext> processor = newProcessor(source, appId);
        ConfigurableJWTProcessor<SecurityContext> existing = PROCESSORS.putIfAbsent(cacheKey, processor);
        return existing != null ? existing : processor;
    }

    private static ConfigurableJWTProcessor<SecurityContext> newProcessor(
            JWKSource<SecurityContext> source,
            String appId
    ) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, source));
        // Default verifier checks exp/nbf with 60s leeway. Pass the
        // expected audience (a Set<String> with the single appId) so
        // Nimbus rejects tokens minted for a different app.
        processor.setJWTClaimsSetVerifier(
                new DefaultJWTClaimsVerifier<SecurityContext>(appId, null, null)
        );
        return processor;
    }

    /**
     * Extract the bearer token from an Authorization header value.
     * Case-insensitive on the {@code Bearer } prefix; trims whitespace.
     *
     * @return Optional containing the token, or empty for missing /
     *         malformed / wrong-prefix / empty input.
     */
    public static Optional<String> bearerToken(String headerValue) {
        if (headerValue == null) {
            return Optional.empty();
        }
        String trimmed = headerValue.trim();
        if (trimmed.length() < 7) {
            return Optional.empty();
        }
        if (!trimmed.substring(0, 7).equalsIgnoreCase("Bearer ")) {
            return Optional.empty();
        }
        String tok = trimmed.substring(7).trim();
        return tok.isEmpty() ? Optional.empty() : Optional.of(tok);
    }

    /**
     * Extract the {@code mr_at_<appId>} session cookie from a Cookie
     * header value. Used as a fallback when the SDK is in cookie mode
     * and no Authorization header is present. The cookie name is
     * per-app so two ManyRows apps on the same eTLD don't collide —
     * pass the configured {@code appId} to read the right one.
     *
     * @return Optional containing the cookie value, or empty when
     *         absent / malformed / empty.
     */
    public static Optional<String> mrAtCookie(String cookieHeaderValue, String appId) {
        if (cookieHeaderValue == null || cookieHeaderValue.isEmpty()
                || appId == null || appId.isEmpty()) {
            return Optional.empty();
        }
        String target = accessCookieName(appId);
        for (String raw : cookieHeaderValue.split(";")) {
            int eq = raw.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = raw.substring(0, eq).trim();
            if (!name.equals(target)) {
                continue;
            }
            String value = raw.substring(eq + 1).trim();
            return value.isEmpty() ? Optional.empty() : Optional.of(value);
        }
        return Optional.empty();
    }

    static String stripTrailingSlashes(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return s.substring(0, end);
    }

    /**
     * Default HTTP transport used by {@link Client}'s convenience
     * constructor. Wraps Java's built-in {@link HttpClient} with a
     * 10-second connect timeout.
     *
     * <p>Not used by {@link #verifyToken} — that path goes through
     * Nimbus's internal JWKS fetcher.
     */
    static HttpTransport defaultTransport() {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        return req -> client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Test seam — clear the in-process JWKS processor cache. Production
     * code should never call this.
     */
    static void resetCacheForTest() {
        PROCESSORS.clear();
    }
}
