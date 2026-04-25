package com.manyrows;

import com.manyrows.Types.Delivery;
import com.manyrows.Types.MembersResult;
import com.manyrows.Types.PermissionResult;
import com.manyrows.Types.UserField;
import com.manyrows.Types.UserResult;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
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
            {"workspaceId":"ws","projectId":"p","appId":"app_123","updatedAt":"",
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
        void stripsTrailingSlashesFromBaseUrl() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(EMPTY_DELIVERY_JSON)));
            Client c = new Client("https://app.manyrows.com///", WORKSPACE, APP_ID, API_KEY, t);
            c.getDelivery();
            String url = t.captured().get(0).uri().toString();
            assertEquals("https://app.manyrows.com/x/acme/api/apps/app_123/", url);
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
                      "projectId": "p_1",
                      "appId": "app_123",
                      "updatedAt": "2026-01-15T10:30:00Z",
                      "config": {
                        "public": [{"key":"theme","type":"string","value":"dark"}],
                        "private": [],
                        "secrets": [{"key":"stripe","type":"secret","isSet":true}]
                      },
                      "flags": {
                        "client": [],
                        "server": [{"key":"beta","enabled":true}]
                      }
                    }
                    """;
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(body)));
            Delivery d = client(t).getDelivery();
            assertEquals("ws_1", d.workspaceId());
            assertEquals(1, d.config().publicItems().size());
            assertEquals("theme", d.config().publicItems().get(0).key());
            assertEquals("dark", d.config().publicItems().get(0).value());
            assertEquals(Boolean.TRUE, d.config().secrets().get(0).isSet());
            assertTrue(d.flags().server().get(0).enabled());
        }

        @Test
        void sendsApiKeyAndUserAgentHeaders() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(EMPTY_DELIVERY_JSON)));
            client(t).getDelivery();
            var headers = t.captured().get(0).headers().map();
            assertEquals("mr_test_key", headers.get("X-API-Key").get(0));
            assertTrue(headers.get("User-Agent").get(0).startsWith("manyrows-java/"));
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

    // ===== listMembers =====

    @Nested
    class ListMembers {

        @Test
        void defaultsPage0PageSize50() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":0,\"pageSize\":50}"
            )));
            client(t).listMembers();
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("page=0"));
            assertTrue(url.contains("pageSize=50"));
            assertFalse(url.contains("email="));
        }

        @Test
        void passesProvidedPagePageSizeEmail() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":2,\"pageSize\":100}"
            )));
            client(t).listMembers(2, 100, "alice@example.com");
            String url = t.captured().get(0).uri().toString();
            assertTrue(url.contains("page=2"));
            assertTrue(url.contains("pageSize=100"));
            assertTrue(url.contains("email=alice%40example.com"));
        }

        @Test
        void listMembersByEmailForwardsToListMembers() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"members\":[],\"total\":0,\"page\":0,\"pageSize\":50}"
            )));
            client(t).listMembersByEmail("bob");
            assertTrue(t.captured().get(0).uri().toString().contains("email=bob"));
        }

        @Test
        void parsesMembersList() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    """
                    {"members":[
                      {"userId":"u_1","email":"a@b.com","enabled":true,"source":"registered","addedAt":"2026-01-01","roles":["admin"]}
                    ],"total":1,"page":0,"pageSize":50}
                    """
            )));
            MembersResult r = client(t).listMembers();
            assertEquals(1, r.members().size());
            assertEquals("u_1", r.members().get(0).userId());
            assertEquals(List.of("admin"), r.members().get(0).roles());
        }
    }

    // ===== getUser =====

    @Nested
    class GetUser {

        @Test
        void getUserHitsUsersWithIdParam() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok(
                    "{\"user\":{\"id\":\"u_1\",\"email\":\"a@b.com\",\"enabled\":true,\"source\":\"registered\"}," +
                            "\"roles\":[],\"permissions\":[],\"fields\":[]}"
            )));
            UserResult r = client(t).getUser("u_1");
            assertEquals("u_1", r.user().id());
            assertEquals("a@b.com", r.user().email());
            assertTrue(t.captured().get(0).uri().toString().contains("/users?id=u_1"));
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
