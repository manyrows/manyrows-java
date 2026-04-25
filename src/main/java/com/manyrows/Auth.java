package com.manyrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

/**
 * Bearer-token verification for server-side auth.
 *
 * <p>Mirrors the Go SDK's {@code auth.Middleware} pattern: validate the
 * user's JWT against the ManyRows {@code /a/app/me} endpoint, then return
 * the authenticated user ID.
 */
public final class Auth {

    static final String USER_AGENT = "manyrows-java-auth/1.0";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Auth() {}

    /**
     * Verify a user's bearer token by calling the ManyRows
     * {@code /a/app/me} endpoint.
     *
     * @return Optional containing the user ID on success; empty if the
     *         token is empty or rejected by ManyRows (401/403).
     * @throws ManyRowsException on network errors or unexpected (5xx,
     *         malformed) responses. Callers in security-sensitive contexts
     *         should treat thrown exceptions the same as an empty Optional —
     *         fail closed, don't let a flaky upstream become an auth bypass.
     */
    public static Optional<String> verifyToken(
            String token,
            String baseUrl,
            String workspaceSlug,
            String appId
    ) {
        return verifyToken(token, baseUrl, workspaceSlug, appId, defaultTransport());
    }

    public static Optional<String> verifyToken(
            String token,
            String baseUrl,
            String workspaceSlug,
            String appId,
            HttpTransport transport
    ) {
        if (token == null || token.isEmpty()) {
            return Optional.empty();
        }

        String url = meUrl(baseUrl, workspaceSlug, appId);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();

        HttpResponse<String> response;
        try {
            response = transport.send(request);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ManyRowsException("manyrows: request interrupted", e);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: request failed: " + e.getMessage(), e);
        }

        int status = response.statusCode();
        if (status == 401 || status == 403) {
            return Optional.empty();
        }
        if (status < 200 || status >= 300) {
            throw new ManyRowsException(
                    "manyrows: /me returned " + status,
                    status,
                    response.body()
            );
        }

        JsonNode root;
        try {
            root = MAPPER.readTree(response.body());
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: failed to decode response", e);
        }

        JsonNode userNode = root.path("user");
        if (userNode.isMissingNode() || !userNode.isObject()) {
            return Optional.empty();
        }
        JsonNode idNode = userNode.path("id");
        if (!idNode.isTextual()) {
            return Optional.empty();
        }
        String id = idNode.asText();
        return id.isEmpty() ? Optional.empty() : Optional.of(id);
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

    static String meUrl(String baseUrl, String workspaceSlug, String appId) {
        String base = stripTrailingSlashes(baseUrl);
        return base + "/x/" + workspaceSlug + "/apps/" + appId + "/a/app/me";
    }

    static String stripTrailingSlashes(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '/') {
            end--;
        }
        return s.substring(0, end);
    }

    static HttpTransport defaultTransport() {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        return req -> client.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
