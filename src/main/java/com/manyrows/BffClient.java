package com.manyrows;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.manyrows.Types.BffSession;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Synchronous client for the ManyRows full-BFF endpoints under {@code /bff/*}.
 *
 * <p>The customer's backend constructs one of these and calls it from the
 * server-side handlers wired to {@code /auth/login}, {@code /auth/google},
 * {@code /auth/verify}, etc. — the exact shape of the customer-facing route
 * is intentionally left to the framework in use (servlet filter, Spring
 * controller, Quarkus resource); this SDK only provides the typed HTTP
 * calls to ManyRows and the {@link BffSession} record returned.
 *
 * <p>Authenticates with HTTP Basic ({@code clientId:clientSecret}). The
 * end-user's IP and User-Agent ride as {@code X-BFF-Client-IP} and
 * {@code X-BFF-Client-User-Agent} headers — pass them on each call so per-IP
 * rate limits and audit logs in ManyRows attribute to the real browser
 * instead of the customer backend's egress.
 *
 * <pre>{@code
 * BffClient bff = new BffClient(
 *     "https://app.manyrows.com",
 *     System.getenv("MANYROWS_BFF_CLIENT_ID"),
 *     System.getenv("MANYROWS_BFF_CLIENT_SECRET"));
 *
 * BffSession s = bff.loginPassword("alice@example.com", "hunter2", true,
 *     request.getRemoteAddr(), request.getHeader("User-Agent"));
 * if (s.totpRequired()) {
 *     // Show the TOTP form, then call bff.verifyTotp(s.challengeToken(), code, ...)
 * } else {
 *     // Issue your own session cookie carrying s.sessionId().
 * }
 * }</pre>
 */
public class BffClient {

    static final String USER_AGENT = "manyrows-java-bff/1.0";

    static final String HEADER_SESSION_ID = "X-BFF-Session-ID";
    static final String HEADER_CLIENT_IP = "X-BFF-Client-IP";
    static final String HEADER_CLIENT_UA = "X-BFF-Client-User-Agent";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String basicAuth;
    private final HttpTransport transport;

    public BffClient(String baseUrl, String clientId, String clientSecret) {
        this(baseUrl, clientId, clientSecret, Auth.defaultTransport());
    }

    public BffClient(String baseUrl, String clientId, String clientSecret, HttpTransport transport) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("manyrows: baseUrl is required");
        }
        if (clientId == null || clientId.isEmpty()) {
            throw new IllegalArgumentException("manyrows: clientId is required");
        }
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new IllegalArgumentException("manyrows: clientSecret is required");
        }
        if (transport == null) {
            throw new IllegalArgumentException("manyrows: transport is required");
        }
        this.baseUrl = Auth.stripTrailingSlashes(baseUrl);
        this.basicAuth = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        this.transport = transport;
    }

    // ===== Login flows =====

    /**
     * Password login. Returns a {@link BffSession}; if {@code totpRequired()}
     * is set the customer's UI should prompt for the code and call
     * {@link #verifyTotp}.
     */
    public BffSession loginPassword(String email, String password, boolean rememberMe,
                                    String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("password", password);
        body.put("rememberMe", rememberMe);
        return postSession("/bff/login", body, clientIp, clientUserAgent);
    }

    /**
     * Google sign-in. {@code credential} is the Google ID token returned by
     * the GSI button / One Tap flow on the browser side.
     */
    public BffSession loginGoogle(String credential, boolean rememberMe,
                                  String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("credential", credential);
        body.put("rememberMe", rememberMe);
        return postSession("/bff/google", body, clientIp, clientUserAgent);
    }

    /**
     * Email-OTP code verification. Used for both fresh-account registration
     * verification AND ongoing OTP-as-primary sign-in. Pass {@code appId}
     * non-null to flip ManyRows into register mode (matches the Tier 1 path).
     */
    public BffSession verifyOtp(String email, String code, String appId, boolean rememberMe,
                                String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("code", code);
        body.put("rememberMe", rememberMe);
        if (appId != null && !appId.isEmpty()) {
            body.put("appId", appId);
        }
        return postSession("/bff/verify", body, clientIp, clientUserAgent);
    }

    /** Complete a TOTP step-up after {@link #loginPassword} / {@link #loginGoogle} returned {@code totpRequired}. */
    public BffSession verifyTotp(String challengeToken, String code,
                                 String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challengeToken", challengeToken);
        body.put("code", code);
        return postSession("/bff/totp/verify", body, clientIp, clientUserAgent);
    }

    /**
     * Start a discoverable WebAuthn login. Returns the raw
     * {@code {challengeId, publicKeyOptions}} payload — pass it through to
     * the browser unchanged for {@code navigator.credentials.get}.
     */
    public JsonNode passkeyLoginBegin(String clientIp, String clientUserAgent) {
        return postRaw("/bff/passkey/login/begin", Map.of(), clientIp, clientUserAgent);
    }

    /** Verify the WebAuthn assertion the browser returned and land a session. */
    public BffSession passkeyLoginFinish(String challengeId, JsonNode response, boolean rememberMe,
                                         String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challengeId", challengeId);
        body.put("response", response);
        body.put("rememberMe", rememberMe);
        return postSession("/bff/passkey/login/finish", body, clientIp, clientUserAgent);
    }

    /**
     * Exchange a one-time auth code (from an OAuth provider redirect) for a
     * session. {@code redirectUri} MUST match what the OAuth flow was
     * started with — same protection as any standard OAuth code exchange.
     */
    public BffSession exchangeAuthCode(String code, String redirectUri,
                                       String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("redirectUri", redirectUri);
        return postSession("/bff/exchange", body, clientIp, clientUserAgent);
    }

    // ===== Misc =====

    /**
     * Email-OTP "forgot password" — emails the user a code if the address is
     * registered. Returns silently regardless of existence (anti-enumeration).
     */
    public void forgotPassword(String email, String appId,
                               String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        if (appId != null && !appId.isEmpty()) {
            body.put("appId", appId);
        }
        postVoid("/bff/forgot-password", body, clientIp, clientUserAgent);
    }

    /** Complete the email-OTP password-reset flow. */
    public void resetPassword(String email, String code, String newPassword, String appId, boolean logoutAll,
                              String clientIp, String clientUserAgent) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("code", code);
        body.put("newPassword", newPassword);
        body.put("logoutAll", logoutAll);
        if (appId != null && !appId.isEmpty()) {
            body.put("appId", appId);
        }
        postVoid("/bff/reset-password", body, clientIp, clientUserAgent);
    }

    /** Revoke a session in ManyRows. Idempotent. */
    public void logout(String sessionId, String clientIp, String clientUserAgent) {
        postVoid("/bff/logout", Map.of("sessionId", sessionId), clientIp, clientUserAgent);
    }

    // ===== Authenticated proxy =====

    /**
     * Proxy a single GET request to ManyRows {@code /bff/proxy{path}} with
     * the given session ID. The customer's backend uses this to forward
     * authed AppKit data calls (e.g. {@code /a/me/sessions}, {@code /a/runtime})
     * server-to-server. Returns the raw response body and status; the caller
     * decides whether to forward the body / errors / headers.
     */
    public ProxyResponse proxyGet(String sessionId, String pathAndQuery,
                                  String clientIp, String clientUserAgent) {
        return proxy("GET", sessionId, pathAndQuery, null, clientIp, clientUserAgent);
    }

    /** POST counterpart of {@link #proxyGet}. */
    public ProxyResponse proxyPost(String sessionId, String pathAndQuery, String body,
                                   String clientIp, String clientUserAgent) {
        return proxy("POST", sessionId, pathAndQuery, body, clientIp, clientUserAgent);
    }

    /** PUT/PATCH/DELETE counterpart. */
    public ProxyResponse proxy(String method, String sessionId, String pathAndQuery, String body,
                               String clientIp, String clientUserAgent) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("manyrows: sessionId is required");
        }
        String url = baseUrl + "/bff/proxy" + pathAndQuery;
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", basicAuth)
                .header(HEADER_SESSION_ID, sessionId)
                .header("User-Agent", USER_AGENT);
        if (clientIp != null && !clientIp.isEmpty()) b.header(HEADER_CLIENT_IP, clientIp);
        if (clientUserAgent != null && !clientUserAgent.isEmpty()) b.header(HEADER_CLIENT_UA, clientUserAgent);
        if (body != null) {
            b.header("Content-Type", "application/json");
            b.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> resp = send(b.build());
        return new ProxyResponse(resp.statusCode(), resp.body(), resp.headers().map());
    }

    /** Raw proxy response — the caller decides what to forward to the browser. */
    public record ProxyResponse(int status, String body, Map<String, java.util.List<String>> headers) {}

    // ===== internals =====

    private BffSession postSession(String path, Object body, String clientIp, String clientUserAgent) {
        HttpResponse<String> resp = send(buildPost(path, body, clientIp, clientUserAgent));
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new ManyRowsException(
                    "manyrows " + path + " failed: " + resp.body(),
                    resp.statusCode(),
                    resp.body());
        }
        try {
            return MAPPER.readValue(resp.body(), BffSession.class);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: decode session response", e);
        }
    }

    private JsonNode postRaw(String path, Object body, String clientIp, String clientUserAgent) {
        HttpResponse<String> resp = send(buildPost(path, body, clientIp, clientUserAgent));
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new ManyRowsException(
                    "manyrows " + path + " failed: " + resp.body(),
                    resp.statusCode(),
                    resp.body());
        }
        try {
            return MAPPER.readTree(resp.body());
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: decode raw response", e);
        }
    }

    private void postVoid(String path, Object body, String clientIp, String clientUserAgent) {
        HttpResponse<String> resp = send(buildPost(path, body, clientIp, clientUserAgent));
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new ManyRowsException(
                    "manyrows " + path + " failed: " + resp.body(),
                    resp.statusCode(),
                    resp.body());
        }
    }

    private HttpRequest buildPost(String path, Object body, String clientIp, String clientUserAgent) {
        String json;
        try {
            json = MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new ManyRowsException("manyrows: encode request body", e);
        }
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .header("Authorization", basicAuth)
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
        if (clientIp != null && !clientIp.isEmpty()) b.header(HEADER_CLIENT_IP, clientIp);
        if (clientUserAgent != null && !clientUserAgent.isEmpty()) b.header(HEADER_CLIENT_UA, clientUserAgent);
        return b.build();
    }

    private HttpResponse<String> send(HttpRequest req) {
        try {
            return transport.send(req);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ManyRowsException("manyrows: request interrupted", e);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: request failed: " + e.getMessage(), e);
        }
    }
}
