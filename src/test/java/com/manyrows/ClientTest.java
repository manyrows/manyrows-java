package com.manyrows;

import com.manyrows.Types.AuthLogsPage;
import com.manyrows.Types.BatchUserResult;
import com.manyrows.Types.ConfigKey;
import com.manyrows.Types.ConfigKeyInput;
import com.manyrows.Types.CreateUserResult;
import com.manyrows.Types.Delivery;
import com.manyrows.Types.FeatureFlagOverride;
import com.manyrows.Types.MembersResult;
import com.manyrows.Types.PermissionResult;
import com.manyrows.Types.RoleSummary;
import com.manyrows.Types.Session;
import com.manyrows.Types.UserField;
import com.manyrows.Types.UserResult;
import com.manyrows.Types.UserStatus;
import com.manyrows.Types.Webhook;
import com.manyrows.Types.WebhookInput;
import com.manyrows.Types.WebhookUpdate;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientTest {

    private static final String BASE_URL = "https://app.manyrows.com";
    private static final String WORKSPACE = "acme";
    private static final String APP_ID = "app_123";
    private static final String API_KEY = "mr_test_key";

    private static final String EMPTY_DELIVERY_JSON = """
            {"workspaceId":"ws","productId":"p","appId":"app_123","updatedAt":"",
             "config":{"public":[],"private":[],"secrets":[]},
             "flags":{"client":[],"server":[]}}""";

    private static Client client(MockTransport t) {
        return new Client(BASE_URL, WORKSPACE, APP_ID, API_KEY, t);
    }

    // ===== Constructor =====

    @Nested
    class Constructor {

        @Test
        void throwsWhenRequiredOptionsMissing() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            assertThrows(IllegalArgumentException.class,
                    () -> new Client("", WORKSPACE, APP_ID, API_KEY, t));
            assertThrows(IllegalArgumentException.class,
                    () -> new Client(BASE_URL, "", APP_ID, API_KEY, t));
            assertThrows(IllegalArgumentException.class,
                    () -> new Client(BASE_URL, WORKSPACE, "", API_KEY, t));
            assertThrows(IllegalArgumentException.class,
                    () -> new Client(BASE_URL, WORKSPACE, APP_ID, "", t));
            assertThrows(IllegalArgumentException.class,
                    () -> new Client(BASE_URL, WORKSPACE, APP_ID, API_KEY, null));
        }

        @Test
        void stripsTrailingSlashesAndUsesV1BasePath() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(EMPTY_DELIVERY_JSON)));
            Client c = new Client("https://app.manyrows.com///", WORKSPACE, APP_ID, API_KEY, t);
            c.getDelivery();
            String url = t.captured().get(0).uri().toString();
            assertEquals("https://app.manyrows.com/x/acme/api/v1/apps/app_123/", url);
            assertFalse(url.contains(".com//"));
        }
    }

    // ===== getDelivery =====

    @Nested
    class GetDelivery {

        @Test
        void parsesDeliveryBody() {
            String body = """
                    {
                      "workspaceId": "ws_1",
                      "productId": "p_1",
                      "appId": "app_123",
                      "updatedAt": "2026-01-15T10:30:00Z",
                      "config": {
                        "public": [{"key":"theme","type":"string","value":"dark"}],
                        "private": [],
                        "secrets": [{"key":"stripe","type":"secret","isSet":true}]
                      },
                      "flags": {
                        "client": [],
                        "server": [{"key":"beta","enabled":true,"roleIds":["r_1"]}]
                      }
                    }
                    """;
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(body)));
            Delivery d = client(t).getDelivery();
            assertEquals("ws_1", d.workspaceId());
            assertEquals("p_1", d.productId());
            assertEquals(1, d.config().publicItems().size());
            assertEquals("theme", d.config().publicItems().get(0).key());
            assertEquals("dark", d.config().publicItems().get(0).value());
            assertEquals(Boolean.TRUE, d.config().secrets().get(0).isSet());
            assertTrue(d.flags().server().get(0).enabled());
            assertEquals(List.of("r_1"), d.flags().server().get(0).roleIds());
        }

        @Test
        void sendsApiKeyAndUserAgentHeaders() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(EMPTY_DELIVERY_JSON)));
            client(t).getDelivery();
            var headers = t.captured().get(0).headers().map();
            assertEquals("mr_test_key", headers.get("X-API-Key").get(0));
            assertTrue(headers.get("User-Agent").get(0).startsWith("manyrows-java/"));
            assertEquals("application/json", headers.get("Accept").get(0));
        }
    }

    // ===== Error handling =====

    @Nested
    class ErrorHandling {

        @Test
        void raisesManyRowsExceptionWithStatusAndBody() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(401, "invalid api key")));
            ManyRowsException ex = assertThrows(ManyRowsException.class, () -> client(t).getDelivery());
            assertEquals(401, ex.getStatus());
            assertEquals("invalid api key", ex.getBody());
        }

        @Test
        void wrapsIoExceptionsInManyRowsException() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.error(new IOException("ECONNREFUSED"))
            ));
            ManyRowsException ex = assertThrows(ManyRowsException.class, () -> client(t).getDelivery());
            assertTrue(ex.getMessage().contains("ECONNREFUSED"));
        }

        @Test
        void surfaces404FromGetConfigValue() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(404, "{\"error\":\"not_found\"}")));
            ManyRowsException ex = assertThrows(ManyRowsException.class, () -> client(t).getConfigValue("missing"));
            assertEquals(404, ex.getStatus());
        }
    }

    // ===== Permissions =====

    @Nested
    class Permissions {

        @Test
        void checkPermissionEncodesQueryParams() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"allowed\":true,\"permission\":\"posts:edit\",\"accountId\":\"u_1\"}"
            )));
            PermissionResult r = client(t).checkPermission("u_1", "posts:edit");
            assertTrue(r.allowed());
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("/check-permission?"));
            assertTrue(url.contains("accountId=u_1"));
            assertTrue(url.contains("permission=posts%3Aedit"));
        }

        @Test
        void hasPermissionReturnsJustTheBoolean() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"allowed\":false,\"permission\":\"x\",\"accountId\":\"u_1\"}"
            )));
            assertFalse(client(t).hasPermission("u_1", "x"));
        }
    }

    // ===== listUsers (list + paging) =====

    @Nested
    class ListUsers {

        @Test
        void noArgsOmitsPagingAndSearch() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":1,\"pageSize\":50}"
            )));
            client(t).listUsers();
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.endsWith("/users"));
            assertFalse(url.contains("page="));
            assertFalse(url.contains("search="));
        }

        @Test
        void passesSearchPageAndPageSize() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":2,\"pageSize\":100}"
            )));
            client(t).listUsers("alice@example.com", 2, 100);
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("search=alice%40example.com"));
            assertTrue(url.contains("page=2"));
            assertTrue(url.contains("pageSize=100"));
        }

        @Test
        void parsesMembersList() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    """
                    {"members":[
                      {"userId":"u_1","email":"a@b.com","enabled":true,"source":"registered","addedAt":"2026-01-01","roles":["admin"]}
                    ],"total":1,"page":1,"pageSize":50}
                    """
            )));
            MembersResult r = client(t).listUsers();
            assertEquals(1, r.members().size());
            assertEquals("u_1", r.members().get(0).userId());
            assertEquals(List.of("admin"), r.members().get(0).roles());
        }

        @Test
        void deprecatedListMembersStillForwards() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":1,\"pageSize\":50}"
            )));
            client(t).listMembers(3, 25, "bob");
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("search=bob"));
            assertTrue(url.contains("page=3"));
            assertTrue(url.contains("pageSize=25"));
        }
    }

    // ===== getUser (GET by path-param id) =====

    @Nested
    class GetUser {

        @Test
        void getUserHitsUsersWithPathId() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"user\":{\"id\":\"u_1\",\"email\":\"a@b.com\",\"enabled\":true,\"source\":\"registered\"}," +
                            "\"roles\":[],\"permissions\":[],\"fields\":[]}"
            )));
            UserResult r = client(t).getUser("u_1");
            assertEquals("u_1", r.user().id());
            assertEquals("a@b.com", r.user().email());
            assertTrue(t.captured().get(0).uri().toString().endsWith("/users/u_1"));
        }

        @Test
        void getUserByEmailHitsUsersWithEmailParam() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"user\":{\"id\":\"u_1\",\"email\":\"a@b.com\",\"enabled\":true,\"source\":\"registered\"}," +
                            "\"roles\":[],\"permissions\":[],\"fields\":[]}"
            )));
            client(t).getUserByEmail("a@b.com");
            assertTrue(t.captured().get(0).uri().toString().contains("/users?email=a%40b.com"));
        }
    }

    // ===== createUser (POST + body) =====

    @Nested
    class CreateUser {

        @Test
        void postsEmailRolesAndFlags() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"user\":{\"id\":\"u_9\",\"email\":\"new@x.com\",\"enabled\":true,\"source\":\"invited\"}," +
                            "\"created\":true,\"roles\":[\"admin\"],\"invited\":true}"
            )));
            CreateUserResult r = client(t).createUser("new@x.com", true, List.of("admin"), true);
            assertTrue(r.created());
            assertTrue(r.invited());
            assertEquals("u_9", r.user().id());

            HttpRequest req = t.captured().get(0);
            assertEquals("POST", req.method());
            assertTrue(req.uri().toString().endsWith("/users"));
            assertEquals("application/json", req.headers().map().get("Content-Type").get(0));
            String body = t.body(0);
            assertTrue(body.contains("\"email\":\"new@x.com\""));
            assertTrue(body.contains("\"emailVerified\":true"));
            assertTrue(body.contains("\"sendInvite\":true"));
            assertTrue(body.contains("\"roles\":[\"admin\"]"));
        }

        @Test
        void simpleOverloadOmitsOptionalFields() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"user\":{\"id\":\"u_9\",\"email\":\"new@x.com\",\"enabled\":true,\"source\":\"invited\"}," +
                            "\"created\":true,\"roles\":[]}"
            )));
            client(t).createUser("new@x.com");
            String body = t.body(0);
            assertTrue(body.contains("\"email\":\"new@x.com\""));
            assertFalse(body.contains("emailVerified"));
            assertFalse(body.contains("sendInvite"));
        }

        @Test
        void batchCreateUsersExtractsResultsEnvelope() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"results\":[{\"email\":\"a@x.com\",\"userId\":\"u_1\",\"created\":true}," +
                            "{\"email\":\"bad\",\"created\":false,\"error\":\"invalid email\"}]}"
            )));
            List<BatchUserResult> results = client(t).batchCreateUsers(List.of("a@x.com", "bad"), false, null);
            assertEquals(2, results.size());
            assertEquals("u_1", results.get(0).userId());
            assertEquals("invalid email", results.get(1).error());
            assertTrue(t.captured().get(0).uri().toString().endsWith("/users:batch"));
        }
    }

    // ===== setUserStatus (PATCH) =====

    @Nested
    class PatchAndPut {

        @Test
        void setUserStatusPatchesWithBody() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"userId\":\"u_1\",\"status\":\"disabled\"}"
            )));
            UserStatus r = client(t).setUserStatus("u_1", "disabled");
            assertEquals("disabled", r.status());
            HttpRequest req = t.captured().get(0);
            assertEquals("PATCH", req.method());
            assertTrue(req.uri().toString().endsWith("/users/u_1"));
            assertTrue(t.body(0).contains("\"status\":\"disabled\""));
        }

        @Test
        void replaceUserRolesPutsAndReturnsResultingSlugs() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"roles\":[\"editor\",\"viewer\"]}"
            )));
            List<String> roles = client(t).replaceUserRoles("u_1", List.of("editor", "viewer"));
            assertEquals(List.of("editor", "viewer"), roles);
            HttpRequest req = t.captured().get(0);
            assertEquals("PUT", req.method());
            assertTrue(req.uri().toString().endsWith("/users/u_1/roles"));
            assertTrue(t.body(0).contains("\"roles\":[\"editor\",\"viewer\"]"));
        }

        @Test
        void replaceUserRolesTreatsNullAsEmptyArray() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{\"roles\":[]}")));
            client(t).replaceUserRoles("u_1", null);
            assertTrue(t.body(0).contains("\"roles\":[]"));
        }

        @Test
        void setConfigValueReturnsStoredValue() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"key\":\"maxItems\",\"value\":42}"
            )));
            Object v = client(t).setConfigValue("maxItems", 42);
            assertEquals(42, ((Number) v).intValue());
            HttpRequest req = t.captured().get(0);
            assertEquals("PUT", req.method());
            assertTrue(req.uri().toString().endsWith("/config/maxItems"));
            assertTrue(t.body(0).contains("\"value\":42"));
        }
    }

    // ===== Roles (list-envelope GET, create, delete) =====

    @Nested
    class Roles {

        @Test
        void listRolesExtractsRolesEnvelope() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"roles\":[{\"slug\":\"admin\",\"name\":\"Admin\",\"permissions\":[\"posts:edit\"]}," +
                            "{\"slug\":\"viewer\",\"name\":\"Viewer\",\"permissions\":[]}]}"
            )));
            List<RoleSummary> roles = client(t).listRoles();
            assertEquals(2, roles.size());
            assertEquals("admin", roles.get(0).slug());
            assertEquals(List.of("posts:edit"), roles.get(0).permissions());
            assertTrue(t.captured().get(0).uri().toString().endsWith("/roles"));
        }

        @Test
        void createRolePostsBody() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"slug\":\"editor\",\"name\":\"Editor\",\"permissions\":[\"posts:edit\"]}"
            )));
            RoleSummary r = client(t).createRole("editor", "Editor", List.of("posts:edit"));
            assertEquals("editor", r.slug());
            HttpRequest req = t.captured().get(0);
            assertEquals("POST", req.method());
            String body = t.body(0);
            assertTrue(body.contains("\"slug\":\"editor\""));
            assertTrue(body.contains("\"name\":\"Editor\""));
            assertTrue(body.contains("\"permissions\":[\"posts:edit\"]"));
        }

        @Test
        void deleteRoleSendsDeleteAndEscapesSlug() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(204, "")));
            client(t).deleteRole("a b/c");
            HttpRequest req = t.captured().get(0);
            assertEquals("DELETE", req.method());
            // space -> %20, slash escaped -> %2F (path-segment escaping, not query)
            assertTrue(req.uri().toString().endsWith("/roles/a%20b%2Fc"),
                    "expected escaped slug, got " + req.uri());
        }
    }

    // ===== Sessions (DELETE returning a count; list-envelope) =====

    @Nested
    class Sessions {

        @Test
        void revokeUserSessionsReturnsCount() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{\"revoked\":3}")));
            long n = client(t).revokeUserSessions("u_1");
            assertEquals(3L, n);
            HttpRequest req = t.captured().get(0);
            assertEquals("DELETE", req.method());
            assertTrue(req.uri().toString().endsWith("/users/u_1/sessions"));
        }

        @Test
        void listUserSessionsParsesEnvelope() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"sessions\":[{\"id\":\"s_1\",\"createdAt\":\"t0\",\"lastSeenAt\":\"t1\",\"expiresAt\":\"t2\",\"ip\":\"1.2.3.4\"}]}"
            )));
            List<Session> sessions = client(t).listUserSessions("u_1");
            assertEquals(1, sessions.size());
            assertEquals("s_1", sessions.get(0).id());
            assertEquals("1.2.3.4", sessions.get(0).ip());
        }

        @Test
        void revokeSingleSessionVoidPathBuilds() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(204, "")));
            client(t).revokeUserSession("u_1", "s_9");
            assertTrue(t.captured().get(0).uri().toString().endsWith("/users/u_1/sessions/s_9"));
        }
    }

    // ===== Webhooks (create with input record, update patch, secret semantics) =====

    @Nested
    class Webhooks {

        @Test
        void createWebhookReturnsSecretOnce() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"id\":\"wh_1\",\"appId\":\"app_123\",\"url\":\"https://x/hook\",\"secret\":\"whsec_abc\"," +
                            "\"events\":[\"user.created\"],\"status\":\"active\",\"description\":\"\"," +
                            "\"createdAt\":\"t\",\"updatedAt\":\"t\",\"createdBy\":\"u\"}"
            )));
            Webhook w = client(t).createWebhook(new WebhookInput("https://x/hook", List.of("user.created"), null));
            assertEquals("wh_1", w.id());
            assertEquals("whsec_abc", w.secret());
            HttpRequest req = t.captured().get(0);
            assertEquals("POST", req.method());
            String body = t.body(0);
            assertTrue(body.contains("\"url\":\"https://x/hook\""));
            assertTrue(body.contains("\"events\":[\"user.created\"]"));
            // description is null -> omitted by @JsonInclude(NON_NULL)
            assertFalse(body.contains("description"));
        }

        @Test
        void updateWebhookPatchOmitsNullFields() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"id\":\"wh_1\",\"appId\":\"app_123\",\"url\":\"https://x/hook\"," +
                            "\"events\":[\"user.created\"],\"status\":\"paused\",\"description\":\"\"," +
                            "\"createdAt\":\"t\",\"updatedAt\":\"t\",\"createdBy\":\"u\"}"
            )));
            Webhook w = client(t).updateWebhook("wh_1", new WebhookUpdate(null, null, "paused", null));
            assertEquals("paused", w.status());
            HttpRequest req = t.captured().get(0);
            assertEquals("PATCH", req.method());
            assertTrue(req.uri().toString().endsWith("/webhooks/wh_1"));
            String body = t.body(0);
            assertEquals("{\"status\":\"paused\"}", body);
        }

        @Test
        void rotateSecretPostsToRotatePath() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"id\":\"wh_1\",\"appId\":\"app_123\",\"url\":\"https://x/hook\"," +
                            "\"events\":[],\"secret\":\"whsec_new\",\"status\":\"active\",\"description\":\"\"," +
                            "\"createdAt\":\"t\",\"updatedAt\":\"t\",\"createdBy\":\"u\"}"
            )));
            Webhook w = client(t).rotateWebhookSecret("wh_1");
            assertEquals("whsec_new", w.secret());
            assertTrue(t.captured().get(0).uri().toString().endsWith("/webhooks/wh_1/rotate-secret"));
        }
    }

    // ===== Config-key definitions & feature-flag overrides =====

    @Nested
    class ConfigAndFeatures {

        @Test
        void createConfigKeySerializesInputRecord() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"key\":\"theme\",\"exposure\":\"public\",\"valueType\":\"string\",\"status\":\"active\"}"
            )));
            ConfigKey k = client(t).createConfigKey(new ConfigKeyInput("theme", "public", "string", null));
            assertEquals("theme", k.key());
            assertEquals("public", k.exposure());
            HttpRequest req = t.captured().get(0);
            assertEquals("POST", req.method());
            assertTrue(req.uri().toString().endsWith("/config-keys"));
            String body = t.body(0);
            assertTrue(body.contains("\"key\":\"theme\""));
            assertTrue(body.contains("\"valueType\":\"string\""));
            assertFalse(body.contains("description"));
        }

        @Test
        void setFeatureFlagOverridePutsEnabledAndRoles() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"enabled\":true,\"roles\":[\"beta\"],\"status\":\"active\"}"
            )));
            FeatureFlagOverride o = client(t).setFeatureFlagOverride("new-ui", true, List.of("beta"));
            assertTrue(o.enabled());
            assertEquals(List.of("beta"), o.roles());
            HttpRequest req = t.captured().get(0);
            assertEquals("PUT", req.method());
            assertTrue(req.uri().toString().endsWith("/features/new-ui"));
            String body = t.body(0);
            assertTrue(body.contains("\"enabled\":true"));
            assertTrue(body.contains("\"roles\":[\"beta\"]"));
        }

        @Test
        void getConfigValueUnwrapsValue() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"key\":\"maxItems\",\"value\":[1,2,3]}"
            )));
            Object v = client(t).getConfigValue("maxItems");
            assertEquals(List.of(1, 2, 3), v);
        }
    }

    // ===== Auth logs (paged GET) =====

    @Nested
    class AuthLogs {

        @Test
        void listAuthLogsAppliesFilters() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"logs\":[{\"id\":\"l_1\",\"createdAt\":\"t\",\"event\":\"login\",\"outcome\":\"success\",\"actorType\":\"user\"}]," +
                            "\"total\":1,\"page\":1,\"pageSize\":50}"
            )));
            AuthLogsPage page = client(t).listAuthLogs("2026-01-01T00:00:00Z", null, "success", 1, 50);
            assertEquals(1, page.logs().size());
            assertEquals("login", page.logs().get(0).event());
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("/auth-logs?"));
            assertTrue(url.contains("since=2026-01-01"));
            assertTrue(url.contains("outcome=success"));
            assertFalse(url.contains("until="));
        }
    }

    // ===== listUserFields =====

    @Nested
    class ListUserFields {

        @Test
        void returnsUserFieldsArray() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    """
                    {"userFields":[
                      {"id":"f_1","key":"name","valueType":"string","label":"Name","status":"active"},
                      {"id":"f_2","key":"verified","valueType":"bool","status":"active"}
                    ]}
                    """
            )));
            List<UserField> fields = client(t).listUserFields();
            assertEquals(2, fields.size());
            assertEquals("name", fields.get(0).key());
            assertEquals("string", fields.get(0).valueType());
        }

        @Test
        void returnsEmptyListWhenUserFieldsMissing() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            List<UserField> fields = client(t).listUserFields();
            assertNotNull(fields);
            assertTrue(fields.isEmpty());
        }
    }
}
