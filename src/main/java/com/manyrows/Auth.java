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

    static final String USER_AGENT = "manyrows-java-auth/1.0";

    /**
     * Mirrors manyrows-core's {@code clientauth.AccessCookieName()}.
     * Duplicated here rather than imported because manyrows-java doesn't
     * depend on the core repo. Keep in sync if the server-side name
     * ever changes.
     */
    static final String ACCESS_COOKIE_NAME = "mr_at";

    /**
     * Module-level cache keyed by JWKS URL. Each entry holds a fully
     * configured Nimbus JWT processor — JWKS fetcher, ES256 verifier,
     * standard claim checks. Sharing one processor across calls means
     * concurrent verifications hit the same in-memory key cache.
     */
    private static final Map<String, ConfigurableJWTProcessor<SecurityContext>> PROCESSORS =
            new ConcurrentHashMap<>();

    private Auth() {}

    /**
     * Verify a user's bearer JWT against the install's JWKS.
     *
     * @return Optional containing the user ID ({@code sub} claim) on
     *         success; empty if the token is empty, malformed,
     *         expired, or fails signature verification. Caller should
     *         treat empty as "not authenticated" and 401 the request.
     *
     * <p>{@code workspaceSlug} and {@code appId} are accepted for
     * source-compat with the previous {@code /a/me}-based API and
     * forward-compat (e.g. a future audience check); the local-verify
     * path doesn't currently use them.
     */
    public static Optional<String> verifyToken(
            String token,
            String baseUrl,
            String workspaceSlug,
            String appId
    ) {
        if (token == null || token.isEmpty()) {
            return Optional.empty();
        }
        ConfigurableJWTProcessor<SecurityContext> processor;
        try {
            processor = processorFor(baseUrl);
        } catch (MalformedURLException e) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(token, null);
            String sub = claims.getSubject();
            return (sub != null && !sub.isEmpty()) ? Optional.of(sub) : Optional.empty();
        } catch (Exception e) {
            // Bad signature, expired, malformed, unknown kid, etc. —
            // all collapse to "not authenticated."
            return Optional.empty();
        }
    }

    /**
     * Test seam — verify against a caller-supplied JWKSource instead of
     * fetching from the network. Production code should use the
     * baseUrl overload.
     */
    static Optional<String> verifyToken(
            String token,
            JWKSource<SecurityContext> jwkSource
    ) {
        if (token == null || token.isEmpty()) {
            return Optional.empty();
        }
        ConfigurableJWTProcessor<SecurityContext> processor = newProcessor(jwkSource);
        try {
            JWTClaimsSet claims = processor.process(token, null);
            String sub = claims.getSubject();
            return (sub != null && !sub.isEmpty()) ? Optional.of(sub) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static ConfigurableJWTProcessor<SecurityContext> processorFor(String baseUrl)
            throws MalformedURLException {
        String jwksUrl = stripTrailingSlashes(baseUrl) + "/.well-known/jwks.json";
        ConfigurableJWTProcessor<SecurityContext> cached = PROCESSORS.get(jwksUrl);
        if (cached != null) {
            return cached;
        }
        // Build outside the cache to avoid holding the cache's compute
        // lock while doing URL parsing. Race between two threads is
        // benign — both build the same processor; whichever wins gets
        // cached, the loser is GC'd.
        URL url = new URL(jwksUrl);
        JWKSource<SecurityContext> source = JWKSourceBuilder.create(url).retrying(true).build();
        ConfigurableJWTProcessor<SecurityContext> processor = newProcessor(source);
        ConfigurableJWTProcessor<SecurityContext> existing = PROCESSORS.putIfAbsent(jwksUrl, processor);
        return existing != null ? existing : processor;
    }

    private static ConfigurableJWTProcessor<SecurityContext> newProcessor(
            JWKSource<SecurityContext> source
    ) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, source));
        // Default verifier checks exp/nbf with 60s leeway.
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(null, null));
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
     * Extract the {@code mr_at} session cookie from a Cookie header
     * value. Used as a fallback when the SDK is in cookie mode and no
     * Authorization header is present.
     *
     * @return Optional containing the cookie value, or empty when
     *         absent / malformed / empty.
     */
    public static Optional<String> mrAtCookie(String cookieHeaderValue) {
        if (cookieHeaderValue == null || cookieHeaderValue.isEmpty()) {
            return Optional.empty();
        }
        for (String raw : cookieHeaderValue.split(";")) {
            int eq = raw.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String name = raw.substring(0, eq).trim();
            if (!name.equals(ACCESS_COOKIE_NAME)) {
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
     * Default HTTP transport used by the {@link Client}, {@link BffClient},
     * and {@link PublicProxy} convenience constructors. Wraps Java's
     * built-in {@link HttpClient} with a 10-second connect timeout.
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
