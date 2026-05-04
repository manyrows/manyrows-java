package com.manyrows;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTest {

    private static final String BASE_URL = "https://app.manyrows.com";
    private static final String WORKSPACE = "acme";
    private static final String APP_ID = "app_123";

    private static Optional<String> verify(String token, MockTransport transport) {
        return Auth.verifyToken(token, BASE_URL, WORKSPACE, APP_ID, transport);
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

    // ===== verifyToken =====

    @Nested
    class VerifyToken {

        @Test
        void returnsUserIdOn200() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"user\":{\"id\":\"user_xyz\"}}")
            ));
            assertEquals(Optional.of("user_xyz"), verify("tok", t));
        }

        @Test
        void returnsEmptyForEmptyTokenWithNoNetworkCall() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            assertTrue(verify("", t).isEmpty());
            assertTrue(verify(null, t).isEmpty());
            assertTrue(t.captured().isEmpty());
        }

        @Test
        void returnsEmptyOn401() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(401, "")));
            assertTrue(verify("tok", t).isEmpty());
        }

        @Test
        void returnsEmptyOn403() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(403, "")));
            assertTrue(verify("tok", t).isEmpty());
        }

        @Test
        void throwsOn5xx() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(500, "oops")));
            ManyRowsException ex = assertThrows(ManyRowsException.class, () -> verify("tok", t));
            assertEquals(500, ex.getStatus());
        }

        @Test
        void wrapsIoExceptionInManyRowsException() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.error(new IOException("ECONNREFUSED"))
            ));
            ManyRowsException ex = assertThrows(ManyRowsException.class, () -> verify("tok", t));
            assertTrue(ex.getMessage().contains("ECONNREFUSED"));
        }

        @Test
        void returnsEmptyWhenResponseHasNoUserId() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{\"user\":{}}")));
            assertTrue(verify("tok", t).isEmpty());
        }

        @Test
        void sendsAuthorizationAndUserAgentHeaders() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"user\":{\"id\":\"u\"}}")
            ));
            verify("tok123", t);
            var headers = t.captured().get(0).headers().map();
            assertEquals("Bearer tok123", headers.get("Authorization").get(0));
            assertTrue(headers.get("User-Agent").get(0).startsWith("manyrows-java-auth/"));
        }

        @Test
        void stripsTrailingSlashesOnBaseUrl() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"user\":{\"id\":\"u\"}}")
            ));
            Auth.verifyToken("tok", "https://app.manyrows.com///", WORKSPACE, APP_ID, t);
            assertEquals(
                    "https://app.manyrows.com/x/acme/apps/app_123/a/me",
                    t.captured().get(0).uri().toString()
            );
        }
    }

    // ===== meUrl helper =====

    @Test
    void meUrlBuildsExpectedPath() {
        assertEquals(
                "https://app.manyrows.com/x/acme/apps/app_123/a/me",
                Auth.meUrl("https://app.manyrows.com", "acme", "app_123")
        );
    }

    @Test
    void stripTrailingSlashesHandlesEmptyAndMultiple() {
        assertEquals("", Auth.stripTrailingSlashes(""));
        assertEquals("a", Auth.stripTrailingSlashes("a"));
        assertEquals("a", Auth.stripTrailingSlashes("a/"));
        assertEquals("a", Auth.stripTrailingSlashes("a////"));
        assertEquals("https://app.manyrows.com", Auth.stripTrailingSlashes("https://app.manyrows.com//"));
    }

    @Test
    void verifyTokenDoesNotShortCircuitWhenTokenIsBlank() {
        // Blank but non-empty (just a space) should still hit the network and
        // be rejected — only empty/null short-circuits.
        MockTransport t = new MockTransport(List.of(MockTransport.Reply.status(401, "")));
        assertTrue(verify(" ", t).isEmpty());
        assertFalse(t.captured().isEmpty());
    }
}
