package com.manyrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.manyrows.Types.Delivery;
import com.manyrows.Types.MembersResult;
import com.manyrows.Types.PermissionResult;
import com.manyrows.Types.UserField;
import com.manyrows.Types.UserFieldsResponse;
import com.manyrows.Types.UserResult;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Synchronous client for the ManyRows Server API.
 *
 * <p>Construct once and reuse; the underlying {@link java.net.http.HttpClient}
 * pools connections.
 *
 * <pre>{@code
 * Client client = new Client(
 *     "https://app.manyrows.com",
 *     "your-workspace",
 *     "your-app-id",
 *     System.getenv("MANYROWS_API_KEY"));
 *
 * UserResult user = client.getUser("u_123");
 * }</pre>
 */
public class Client {

    static final String USER_AGENT = "manyrows-java/1.0";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String workspaceSlug;
    private final String appId;
    private final String apiKey;
    private final HttpTransport transport;

    public Client(String baseUrl, String workspaceSlug, String appId, String apiKey) {
        this(baseUrl, workspaceSlug, appId, apiKey, Auth.defaultTransport());
    }

    public Client(
            String baseUrl,
            String workspaceSlug,
            String appId,
            String apiKey,
            HttpTransport transport
    ) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("manyrows: baseUrl is required");
        }
        if (workspaceSlug == null || workspaceSlug.isEmpty()) {
            throw new IllegalArgumentException("manyrows: workspaceSlug is required");
        }
        if (appId == null || appId.isEmpty()) {
            throw new IllegalArgumentException("manyrows: appId is required");
        }
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException("manyrows: apiKey is required");
        }
        if (transport == null) {
            throw new IllegalArgumentException("manyrows: transport is required");
        }
        this.baseUrl = Auth.stripTrailingSlashes(baseUrl);
        this.workspaceSlug = workspaceSlug;
        this.appId = appId;
        this.apiKey = apiKey;
        this.transport = transport;
    }

    private String apiUrl(String path) {
        return baseUrl + "/x/" + workspaceSlug + "/api/apps/" + appId + path;
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String buildQuery(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (e.getValue() == null) continue;
            if (!first) sb.append('&');
            sb.append(encode(e.getKey())).append('=').append(encode(e.getValue()));
            first = false;
        }
        return sb.toString();
    }

    private <T> T doGet(String path, Map<String, String> params, Class<T> cls) {
        String url = apiUrl(path);
        if (params != null && !params.isEmpty()) {
            String query = buildQuery(params);
            if (!query.isEmpty()) {
                url = url + "?" + query;
            }
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("X-API-Key", apiKey)
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
        String body = response.body();
        if (status < 200 || status >= 300) {
            throw new ManyRowsException(
                    "manyrows: " + (body == null || body.isEmpty() ? "request failed" : body)
                            + " (status " + status + ")",
                    status,
                    body
            );
        }

        try {
            return MAPPER.readValue(body, cls);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: failed to decode response", e);
        }
    }

    // === Delivery ===

    /** Returns config keys + feature flags for this app. */
    public Delivery getDelivery() {
        return doGet("/", null, Delivery.class);
    }

    // === Permissions ===

    /** Checks whether a user has a specific permission. */
    public PermissionResult checkPermission(String accountId, String permission) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("accountId", accountId);
        params.put("permission", permission);
        return doGet("/check-permission", params, PermissionResult.class);
    }

    /** Convenience: returns just the boolean from {@link #checkPermission}. */
    public boolean hasPermission(String accountId, String permission) {
        return checkPermission(accountId, permission).allowed();
    }

    // === Members ===

    /** {@code listMembers(0, 50, null)}. */
    public MembersResult listMembers() {
        return listMembers(0, 50, null);
    }

    /** {@code listMembers(page, pageSize, null)}. */
    public MembersResult listMembers(int page, int pageSize) {
        return listMembers(page, pageSize, null);
    }

    /**
     * Returns paginated members for the app. {@code email} (optional) is a
     * substring filter applied server-side.
     */
    public MembersResult listMembers(int page, int pageSize, String email) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("page", Integer.toString(page));
        params.put("pageSize", Integer.toString(pageSize));
        if (email != null && !email.isEmpty()) {
            params.put("email", email);
        }
        return doGet("/members", params, MembersResult.class);
    }

    /** Convenience for {@code listMembers(0, 50, email)}. */
    public MembersResult listMembersByEmail(String email) {
        return listMembers(0, 50, email);
    }

    /** Convenience for {@code listMembers(page, pageSize, email)}. */
    public MembersResult listMembersByEmail(String email, int page, int pageSize) {
        return listMembers(page, pageSize, email);
    }

    // === Users ===

    /** Look up a user by ID. */
    public UserResult getUser(String userId) {
        return doGet("/users", Map.of("id", userId), UserResult.class);
    }

    /** Look up a user by email within the app's auth scope. */
    public UserResult getUserByEmail(String email) {
        return doGet("/users", Map.of("email", email), UserResult.class);
    }

    // === User Fields ===

    /** Returns all user field definitions for the app. */
    public List<UserField> listUserFields() {
        UserFieldsResponse r = doGet("/user-fields", null, UserFieldsResponse.class);
        if (r == null || r.userFields() == null) {
            return List.of();
        }
        return r.userFields();
    }
}
