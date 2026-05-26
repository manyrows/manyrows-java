package com.manyrows;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.manyrows.Types.AuthLogsPage;
import com.manyrows.Types.BatchUserResult;
import com.manyrows.Types.ConfigKey;
import com.manyrows.Types.ConfigKeyInput;
import com.manyrows.Types.ConfigKeyUpdate;
import com.manyrows.Types.CreateUserResult;
import com.manyrows.Types.Delivery;
import com.manyrows.Types.FeatureFlagDefinition;
import com.manyrows.Types.FeatureFlagInput;
import com.manyrows.Types.FeatureFlagOverride;
import com.manyrows.Types.FeatureFlagUpdate;
import com.manyrows.Types.Identity;
import com.manyrows.Types.MagicLinkResult;
import com.manyrows.Types.MembersResult;
import com.manyrows.Types.Passkey;
import com.manyrows.Types.PermissionResult;
import com.manyrows.Types.PermissionSummary;
import com.manyrows.Types.RemoveUserResult;
import com.manyrows.Types.RoleSummary;
import com.manyrows.Types.Session;
import com.manyrows.Types.UserField;
import com.manyrows.Types.UserFieldValue;
import com.manyrows.Types.UserResult;
import com.manyrows.Types.UserStatus;
import com.manyrows.Types.Webhook;
import com.manyrows.Types.WebhookInput;
import com.manyrows.Types.WebhookUpdate;

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
 * Synchronous client for the ManyRows server-to-server API. Every call is
 * scoped to one app and authenticated with a workspace API key.
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
 * boolean ok = client.hasPermission("u_123", "posts:edit");
 * }</pre>
 */
public class Client {

    static final String USER_AGENT = "manyrows-java/1.0";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

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
        return baseUrl + "/x/" + pathSegment(workspaceSlug) + "/api/v1/apps/" + pathSegment(appId) + path;
    }

    /** Percent-encode a value destined for a query parameter. */
    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /**
     * Percent-encode a value destined for a single path segment. {@link URLEncoder}
     * targets query strings, so it renders space as {@code +} and leaves {@code +}
     * untouched; fix both up to the path-segment rules (RFC 3986) so ids/slugs with
     * those characters resolve correctly. Mirrors Go's {@code url.PathEscape}.
     */
    private static String pathSegment(String s) {
        return encode(s).replace("+", "%20");
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

    // === request plumbing ===

    /**
     * Sends a request and returns the raw response body, throwing
     * {@link ManyRowsException} for non-2xx responses or transport failures.
     * Shared by every typed method below.
     */
    private String send(String method, String path, Map<String, String> params, Object body) {
        String url = apiUrl(path);
        if (params != null && !params.isEmpty()) {
            String query = buildQuery(params);
            if (!query.isEmpty()) {
                url = url + "?" + query;
            }
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("X-API-Key", apiKey)
                .header("User-Agent", USER_AGENT)
                .header("Accept", "application/json");

        HttpRequest.BodyPublisher publisher;
        if (body != null) {
            String json;
            try {
                json = MAPPER.writeValueAsString(body);
            } catch (IOException e) {
                throw new ManyRowsException("manyrows: failed to encode request", e);
            }
            publisher = HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8);
            builder.header("Content-Type", "application/json");
        } else {
            publisher = HttpRequest.BodyPublishers.noBody();
        }
        builder.method(method, publisher);

        HttpResponse<String> response;
        try {
            response = transport.send(builder.build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ManyRowsException("manyrows: request interrupted", e);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: request failed: " + e.getMessage(), e);
        }

        int status = response.statusCode();
        String responseBody = response.body();
        if (status < 200 || status >= 300) {
            throw new ManyRowsException(
                    "manyrows: " + (responseBody == null || responseBody.isEmpty() ? "request failed" : responseBody)
                            + " (status " + status + ")",
                    status,
                    responseBody
            );
        }
        return responseBody;
    }

    private <T> T request(String method, String path, Map<String, String> params, Object body, Class<T> cls) {
        String responseBody = send(method, path, params, body);
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        try {
            return MAPPER.readValue(responseBody, cls);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: failed to decode response", e);
        }
    }

    private <T> T request(String method, String path, Map<String, String> params, Object body, TypeReference<T> type) {
        String responseBody = send(method, path, params, body);
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        try {
            return MAPPER.readValue(responseBody, type);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: failed to decode response", e);
        }
    }

    private <T> T doGet(String path, Map<String, String> params, Class<T> cls) {
        return request("GET", path, params, null, cls);
    }

    /** GET returning a single envelope key as a typed list, e.g. {@code {"roles":[...]}}. */
    @SuppressWarnings("unchecked")
    private <T> List<T> getList(String path, Map<String, String> params, String key, Class<T> elementType) {
        Map<String, Object> out = request("GET", path, params, null, MAP_TYPE);
        return extractList(out, key, elementType);
    }

    @SuppressWarnings("unchecked")
    private <T> List<T> extractList(Map<String, Object> out, String key, Class<T> elementType) {
        if (out == null) {
            return List.of();
        }
        Object raw = out.get(key);
        if (raw == null) {
            return List.of();
        }
        // Re-bind through Jackson so element objects become the requested record
        // type rather than LinkedHashMaps. Cheap (in-memory) and keeps the wire
        // mapping in one place.
        return MAPPER.convertValue(raw, MAPPER.getTypeFactory().constructCollectionType(List.class, elementType));
    }

    /** Extract a {@code List<String>} from an envelope key (no element re-binding needed). */
    @SuppressWarnings("unchecked")
    private List<String> extractStrings(Map<String, Object> out, String key) {
        if (out == null || out.get(key) == null) {
            return List.of();
        }
        return (List<String>) out.get(key);
    }

    // === Delivery ===

    /** Returns config keys + feature flags for this app. */
    public Delivery getDelivery() {
        return doGet("/", null, Delivery.class);
    }

    // === Permissions (authorization check) ===

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

    // === Authorization catalog: roles ===

    /** Returns the product's roles, each with the permission slugs it grants. */
    public List<RoleSummary> listRoles() {
        return getList("/roles", null, "roles", RoleSummary.class);
    }

    /** Fetches one role (with its permission slugs) by slug. */
    public RoleSummary getRole(String slug) {
        return doGet("/roles/" + pathSegment(slug), null, RoleSummary.class);
    }

    /** Defines a new role, optionally with permission slugs ({@code null} for none). */
    public RoleSummary createRole(String slug, String name, List<String> permissions) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", slug);
        body.put("name", name);
        if (permissions != null) {
            body.put("permissions", permissions);
        }
        return request("POST", "/roles", null, body, RoleSummary.class);
    }

    /**
     * Updates a role's name and/or permissions. A {@code null} arg leaves that
     * field unchanged; a non-null (even empty) permissions list replaces the set.
     */
    public RoleSummary updateRole(String slug, String name, List<String> permissions) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (name != null) {
            body.put("name", name);
        }
        if (permissions != null) {
            body.put("permissions", permissions);
        }
        return request("PATCH", "/roles/" + pathSegment(slug), null, body, RoleSummary.class);
    }

    /** Deletes a role. */
    public void deleteRole(String slug) {
        send("DELETE", "/roles/" + pathSegment(slug), null, null);
    }

    // === Authorization catalog: permissions ===

    /** Returns the product's permissions. */
    public List<PermissionSummary> listPermissions() {
        return getList("/permissions", null, "permissions", PermissionSummary.class);
    }

    /** Fetches one permission by slug. */
    public PermissionSummary getPermission(String slug) {
        return doGet("/permissions/" + pathSegment(slug), null, PermissionSummary.class);
    }

    /** Defines a new permission. */
    public PermissionSummary createPermission(String slug, String name) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slug", slug);
        body.put("name", name);
        return request("POST", "/permissions", null, body, PermissionSummary.class);
    }

    /** Renames a permission. */
    public PermissionSummary updatePermission(String slug, String name) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        return request("PATCH", "/permissions/" + pathSegment(slug), null, body, PermissionSummary.class);
    }

    /** Deletes a permission. */
    public void deletePermission(String slug) {
        send("DELETE", "/permissions/" + pathSegment(slug), null, null);
    }

    // === Users: read ===

    /** {@code listUsers(null, 0, 0)} — first page, server default page size. */
    public MembersResult listUsers() {
        return listUsers(null, 0, 0);
    }

    /** {@code listUsers(null, page, pageSize)}. */
    public MembersResult listUsers(int page, int pageSize) {
        return listUsers(null, page, pageSize);
    }

    /**
     * Lists the app's members. {@code search} (optional) is an email substring
     * filter applied server-side. {@code page}/{@code pageSize} are omitted when
     * {@code <= 0} so the server's defaults apply.
     */
    public MembersResult listUsers(String search, int page, int pageSize) {
        Map<String, String> params = new LinkedHashMap<>();
        if (search != null && !search.isEmpty()) {
            params.put("search", search);
        }
        if (page > 0) {
            params.put("page", Integer.toString(page));
        }
        if (pageSize > 0) {
            params.put("pageSize", Integer.toString(pageSize));
        }
        return doGet("/users", params, MembersResult.class);
    }

    /**
     * Alias for {@link #listUsers()}.
     *
     * @deprecated Prefer {@link #listUsers()}; {@code listMembers} is kept for
     *             source compatibility with the older SDK.
     */
    @Deprecated
    public MembersResult listMembers() {
        return listUsers(null, 0, 0);
    }

    /**
     * Alias for {@link #listUsers(int, int)}.
     *
     * @deprecated Prefer {@link #listUsers(int, int)}.
     */
    @Deprecated
    public MembersResult listMembers(int page, int pageSize) {
        return listUsers(null, page, pageSize);
    }

    /**
     * Alias for {@link #listUsers(String, int, int)} (the {@code search} substring
     * filter).
     *
     * @deprecated Prefer {@link #listUsers(String, int, int)}.
     */
    @Deprecated
    public MembersResult listMembers(int page, int pageSize, String search) {
        return listUsers(search, page, pageSize);
    }

    /** Look up a user by ID (deep: roles, permissions, fields). */
    public UserResult getUser(String userId) {
        return doGet("/users/" + pathSegment(userId), null, UserResult.class);
    }

    /** Look up a user by exact email within the app's auth scope (deep). */
    public UserResult getUserByEmail(String email) {
        return doGet("/users", Map.of("email", email), UserResult.class);
    }

    // === Users: provisioning & lifecycle ===

    /**
     * Provisions a user: create-or-find by email in the pool and add to the app.
     * Idempotent. {@code roles} may be {@code null}. Set {@code sendInvite} to
     * email the user a branded invitation (requires an App URL configured).
     */
    public CreateUserResult createUser(String email, boolean emailVerified, List<String> roles, boolean sendInvite) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        if (emailVerified) {
            body.put("emailVerified", true);
        }
        if (roles != null) {
            body.put("roles", roles);
        }
        if (sendInvite) {
            body.put("sendInvite", true);
        }
        return request("POST", "/users", null, body, CreateUserResult.class);
    }

    /** Convenience for {@code createUser(email, false, null, false)}. */
    public CreateUserResult createUser(String email) {
        return createUser(email, false, null, false);
    }

    /**
     * Provisions up to 100 users in one call, all with the same optional roles.
     * Each email is reported independently, so one bad email doesn't sink the
     * rest. Idempotent per email. {@code roles} may be {@code null}.
     */
    public List<BatchUserResult> batchCreateUsers(List<String> emails, boolean emailVerified, List<String> roles) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("emails", emails);
        if (emailVerified) {
            body.put("emailVerified", true);
        }
        if (roles != null) {
            body.put("roles", roles);
        }
        Map<String, Object> out = request("POST", "/users:batch", null, body, MAP_TYPE);
        return extractList(out, "results", BatchUserResult.class);
    }

    /** Suspends ({@code "disabled"}) or re-enables ({@code "active"}) a member in this app. */
    public UserStatus setUserStatus(String userId, String status) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        return request("PATCH", "/users/" + pathSegment(userId), null, body, UserStatus.class);
    }

    /**
     * Removes a member from the app; the pool identity is deleted too if the
     * user is left in no other app.
     */
    public RemoveUserResult removeUser(String userId) {
        return request("DELETE", "/users/" + pathSegment(userId), null, null, RemoveUserResult.class);
    }

    // === Users: roles ===

    /**
     * Replaces a member's roles (full set of slugs; an empty list clears them and
     * revokes the user's sessions). {@code null} is treated as empty. Returns the
     * resulting slugs.
     */
    public List<String> replaceUserRoles(String userId, List<String> roles) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("roles", roles == null ? List.of() : roles);
        Map<String, Object> out = request("PUT", "/users/" + pathSegment(userId) + "/roles", null, body, MAP_TYPE);
        return extractStrings(out, "roles");
    }

    /**
     * Grants one role to a member without disturbing the others (idempotent) and
     * returns the resulting role slugs.
     */
    public List<String> addUserRole(String userId, String roleSlug) {
        String path = "/users/" + pathSegment(userId) + "/roles/" + pathSegment(roleSlug);
        Map<String, Object> out = request("POST", path, null, null, MAP_TYPE);
        return extractStrings(out, "roles");
    }

    /**
     * Revokes one role from a member (idempotent) and returns the resulting role
     * slugs.
     */
    public List<String> removeUserRole(String userId, String roleSlug) {
        String path = "/users/" + pathSegment(userId) + "/roles/" + pathSegment(roleSlug);
        Map<String, Object> out = request("DELETE", path, null, null, MAP_TYPE);
        return extractStrings(out, "roles");
    }

    // === Users: direct permission overrides ===

    /**
     * Lists a member's direct permission overrides (slugs), separate from the
     * permissions inherited via roles.
     */
    public List<String> getUserPermissions(String userId) {
        return getList("/users/" + pathSegment(userId) + "/permissions", null, "permissions", String.class);
    }

    /**
     * Replaces a member's direct permission overrides (full set of slugs;
     * {@code null} is treated as empty) and returns the result.
     */
    public List<String> setUserPermissions(String userId, List<String> permissions) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("permissions", permissions == null ? List.of() : permissions);
        Map<String, Object> out =
                request("PUT", "/users/" + pathSegment(userId) + "/permissions", null, body, MAP_TYPE);
        return extractStrings(out, "permissions");
    }

    // === Users: auth logs ===

    /**
     * Returns a member's authentication-event history for this app (newest first,
     * paginated). Pass {@code page}/{@code pageSize} {@code <= 0} for the defaults.
     */
    public AuthLogsPage getUserAuthLogs(String userId, int page, int pageSize) {
        Map<String, String> params = new LinkedHashMap<>();
        if (page > 0) {
            params.put("page", Integer.toString(page));
        }
        if (pageSize > 0) {
            params.put("pageSize", Integer.toString(pageSize));
        }
        return doGet("/users/" + pathSegment(userId) + "/auth-logs", params, AuthLogsPage.class);
    }

    /**
     * Returns the app's auth-event history (all users), newest first — for
     * ingesting into a SIEM/analytics pipeline. {@code since}/{@code until} are
     * RFC3339; {@code outcome} is {@code "success"} or {@code "failure"}. Any
     * argument may be {@code null}/{@code <= 0} to omit it.
     */
    public AuthLogsPage listAuthLogs(String since, String until, String outcome, int page, int pageSize) {
        Map<String, String> params = new LinkedHashMap<>();
        if (since != null && !since.isEmpty()) {
            params.put("since", since);
        }
        if (until != null && !until.isEmpty()) {
            params.put("until", until);
        }
        if (outcome != null && !outcome.isEmpty()) {
            params.put("outcome", outcome);
        }
        if (page > 0) {
            params.put("page", Integer.toString(page));
        }
        if (pageSize > 0) {
            params.put("pageSize", Integer.toString(pageSize));
        }
        return doGet("/auth-logs", params, AuthLogsPage.class);
    }

    /** {@code listAuthLogs(null, null, null, 0, 0)}. */
    public AuthLogsPage listAuthLogs() {
        return listAuthLogs(null, null, null, 0, 0);
    }

    // === Users: sessions ===

    /** Force-logs-out a member from this app and returns the count revoked. */
    public long revokeUserSessions(String userId) {
        Map<String, Object> out =
                request("DELETE", "/users/" + pathSegment(userId) + "/sessions", null, null, MAP_TYPE);
        if (out == null || out.get("revoked") == null) {
            return 0L;
        }
        return ((Number) out.get("revoked")).longValue();
    }

    /** Lists a member's active sessions for this app. */
    public List<Session> listUserSessions(String userId) {
        return getList("/users/" + pathSegment(userId) + "/sessions", null, "sessions", Session.class);
    }

    /** Revokes a single session of a member. */
    public void revokeUserSession(String userId, String sessionId) {
        send("DELETE", "/users/" + pathSegment(userId) + "/sessions/" + pathSegment(sessionId), null, null);
    }

    // === Users: credentials & identity ===

    /** Sets or replaces a member's password (enforced against the app's policy). */
    public void setUserPassword(String userId, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("password", password);
        send("PUT", "/users/" + pathSegment(userId) + "/password", null, body);
    }

    /** Removes a member's password (email+password sign-in disabled until reset). */
    public void clearUserPassword(String userId) {
        send("DELETE", "/users/" + pathSegment(userId) + "/password", null, null);
    }

    /**
     * Marks a member's email verified or unverified (a pool-level attribute, so
     * it applies across every app sharing the pool).
     */
    public void setUserEmailVerified(String userId, boolean verified) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("verified", verified);
        send("PUT", "/users/" + pathSegment(userId) + "/email-verified", null, body);
    }

    /**
     * Enables/disables a user's identity pool-wide (ban). Disabling blocks sign-in
     * to every app sharing the pool and revokes the user's sessions.
     */
    public void setUserEnabled(String userId, boolean enabled) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", enabled);
        send("PUT", "/users/" + pathSegment(userId) + "/enabled", null, body);
    }

    /**
     * Changes a member's email and marks it verified. Throws a
     * {@link ManyRowsException} with status 409 if the address is already in use
     * in the pool.
     */
    public void changeUserEmail(String userId, String email) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        send("PUT", "/users/" + pathSegment(userId) + "/email", null, body);
    }

    /**
     * Generates a one-time passwordless sign-in link for a member (requires the
     * app's primary auth method to be Magic Link).
     */
    public MagicLinkResult createMagicLink(String userId, boolean rememberMe) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("rememberMe", rememberMe);
        return request("POST", "/users/" + pathSegment(userId) + "/magic-link", null, body, MagicLinkResult.class);
    }

    /** Disables a member's 2FA (for a user who lost their authenticator). */
    public void resetUserTOTP(String userId) {
        send("DELETE", "/users/" + pathSegment(userId) + "/totp", null, null);
    }

    /** Clears a failed-login lockout on a member. */
    public void unlockUser(String userId) {
        send("POST", "/users/" + pathSegment(userId) + "/unlock", null, null);
    }

    /** Returns a member's linked SSO/OAuth identities. */
    public List<Identity> listUserIdentities(String userId) {
        return getList("/users/" + pathSegment(userId) + "/identities", null, "identities", Identity.class);
    }

    /** Unlinks a member's SSO identity for a provider (e.g. {@code "google"}). */
    public void deleteUserIdentity(String userId, String provider) {
        send("DELETE", "/users/" + pathSegment(userId) + "/identities/" + pathSegment(provider), null, null);
    }

    /** Returns a member's passkeys (WebAuthn credentials) for this app. */
    public List<Passkey> listUserPasskeys(String userId) {
        return getList("/users/" + pathSegment(userId) + "/passkeys", null, "passkeys", Passkey.class);
    }

    /** Removes one of a member's passkeys. */
    public void deleteUserPasskey(String userId, String passkeyId) {
        send("DELETE", "/users/" + pathSegment(userId) + "/passkeys/" + pathSegment(passkeyId), null, null);
    }

    // === User fields ===

    /** Returns all user field definitions for the app. */
    public List<UserField> listUserFields() {
        return getList("/user-fields", null, "userFields", UserField.class);
    }

    /** Returns a member's field values. */
    public List<UserFieldValue> getUserFieldValues(String userId) {
        return getList("/user-fields/users/" + pathSegment(userId), null, "values", UserFieldValue.class);
    }

    /**
     * Sets a member's value for a field (validated server-side against the field's
     * type). {@code value} is JSON-encoded as sent.
     */
    public UserFieldValue setUserFieldValue(String fieldId, String userId, Object value) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        String path = "/user-fields/" + pathSegment(fieldId) + "/users/" + pathSegment(userId);
        Map<String, Object> out = request("PUT", path, null, body, MAP_TYPE);
        if (out == null || out.get("value") == null) {
            return null;
        }
        return MAPPER.convertValue(out.get("value"), UserFieldValue.class);
    }

    /** Clears a member's value for a field. */
    public void deleteUserFieldValue(String fieldId, String userId) {
        String path = "/user-fields/" + pathSegment(fieldId) + "/users/" + pathSegment(userId);
        send("DELETE", path, null, null);
    }

    // === Per-app config values & feature-flag overrides ===

    /**
     * Sets this app's value for a public/private config key and returns the stored
     * value as decoded JSON. {@code value} is JSON-encoded as sent.
     */
    public Object setConfigValue(String configKey, Object value) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        Map<String, Object> out = request("PUT", "/config/" + pathSegment(configKey), null, body, MAP_TYPE);
        return out == null ? null : out.get("value");
    }

    /**
     * Reads this app's value for a config key as decoded JSON. Throws a
     * {@link ManyRowsException} with status 404 if no value is set, or 400 for a
     * secret key.
     */
    public Object getConfigValue(String configKey) {
        Map<String, Object> out = request("GET", "/config/" + pathSegment(configKey), null, null, MAP_TYPE);
        return out == null ? null : out.get("value");
    }

    /** Clears this app's value for a config key. */
    public void deleteConfigValue(String configKey) {
        send("DELETE", "/config/" + pathSegment(configKey), null, null);
    }

    /**
     * Reads this app's override for a flag. Throws a {@link ManyRowsException} with
     * status 404 if no override is set.
     */
    public FeatureFlagOverride getFeatureFlagOverride(String flagKey) {
        return doGet("/features/" + pathSegment(flagKey), null, FeatureFlagOverride.class);
    }

    /**
     * Sets this app's override for a feature flag, optionally targeting a set of
     * role slugs ({@code null}/empty applies to everyone), and returns the
     * resulting override.
     */
    public FeatureFlagOverride setFeatureFlagOverride(String flagKey, boolean enabled, List<String> roles) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", enabled);
        if (roles != null) {
            body.put("roles", roles);
        }
        return request("PUT", "/features/" + pathSegment(flagKey), null, body, FeatureFlagOverride.class);
    }

    /** Clears this app's override for a flag (falls back to default). */
    public void clearFeatureFlagOverride(String flagKey) {
        send("DELETE", "/features/" + pathSegment(flagKey), null, null);
    }

    // === Config-key definitions (schema) ===

    /** Lists the product's config-key definitions. */
    public List<ConfigKey> listConfigKeys() {
        return getList("/config-keys", null, "configKeys", ConfigKey.class);
    }

    /** Fetches one config-key definition by key. */
    public ConfigKey getConfigKey(String key) {
        return doGet("/config-keys/" + pathSegment(key), null, ConfigKey.class);
    }

    /** Defines a config key. */
    public ConfigKey createConfigKey(ConfigKeyInput input) {
        return request("POST", "/config-keys", null, input, ConfigKey.class);
    }

    /** Updates a config key's metadata ({@code null} fields are left unchanged). */
    public ConfigKey updateConfigKey(String key, ConfigKeyUpdate patch) {
        return request("PATCH", "/config-keys/" + pathSegment(key), null, patch, ConfigKey.class);
    }

    /** Deletes a config key and its per-app values. */
    public void deleteConfigKey(String key) {
        send("DELETE", "/config-keys/" + pathSegment(key), null, null);
    }

    // === Feature-flag definitions (schema) ===

    /** Lists the product's feature-flag definitions. */
    public List<FeatureFlagDefinition> listFeatureFlags() {
        return getList("/feature-flags", null, "featureFlags", FeatureFlagDefinition.class);
    }

    /** Fetches one feature-flag definition by key. */
    public FeatureFlagDefinition getFeatureFlag(String key) {
        return doGet("/feature-flags/" + pathSegment(key), null, FeatureFlagDefinition.class);
    }

    /** Defines a feature flag. */
    public FeatureFlagDefinition createFeatureFlag(FeatureFlagInput input) {
        return request("POST", "/feature-flags", null, input, FeatureFlagDefinition.class);
    }

    /** Updates a feature flag's metadata ({@code null} fields are left unchanged). */
    public FeatureFlagDefinition updateFeatureFlag(String key, FeatureFlagUpdate patch) {
        return request("PATCH", "/feature-flags/" + pathSegment(key), null, patch, FeatureFlagDefinition.class);
    }

    /** Deletes a feature flag and its per-app overrides. */
    public void deleteFeatureFlag(String key) {
        send("DELETE", "/feature-flags/" + pathSegment(key), null, null);
    }

    // === Webhooks ===

    /** Lists the app's webhook subscriptions (signing secrets redacted). */
    public List<Webhook> listWebhooks() {
        return getList("/webhooks", null, "webhooks", Webhook.class);
    }

    /**
     * Registers a webhook. The returned {@link Webhook#secret()} is populated only
     * here — store it; it's redacted on every later read.
     */
    public Webhook createWebhook(WebhookInput input) {
        return request("POST", "/webhooks", null, input, Webhook.class);
    }

    /** Fetches one webhook (secret redacted). */
    public Webhook getWebhook(String webhookId) {
        return doGet("/webhooks/" + pathSegment(webhookId), null, Webhook.class);
    }

    /** Patches a webhook (URL, events, status, description). */
    public Webhook updateWebhook(String webhookId, WebhookUpdate patch) {
        return request("PATCH", "/webhooks/" + pathSegment(webhookId), null, patch, Webhook.class);
    }

    /** Removes a webhook. */
    public void deleteWebhook(String webhookId) {
        send("DELETE", "/webhooks/" + pathSegment(webhookId), null, null);
    }

    /**
     * Issues a fresh signing secret; the returned {@link Webhook#secret()} is
     * populated only here.
     */
    public Webhook rotateWebhookSecret(String webhookId) {
        return request("POST", "/webhooks/" + pathSegment(webhookId) + "/rotate-secret", null, null, Webhook.class);
    }
}
