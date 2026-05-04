package com.manyrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.manyrows.Types.BffSession;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BffClientTest {

    private static final String BASE = "https://app.manyrows.com";
    private static final String CID = "client_abc";
    private static final String CSECRET = "secret_xyz";
    private static final String EXPECTED_BASIC =
            "Basic " + Base64.getEncoder().encodeToString((CID + ":" + CSECRET).getBytes());

    private BffClient newBff(MockTransport t) {
        return new BffClient(BASE, CID, CSECRET, t);
    }

    @Nested
    class Constructor {
        @Test void rejectsEmptyArgs() {
            assertThrows(IllegalArgumentException.class, () -> new BffClient("", CID, CSECRET));
            assertThrows(IllegalArgumentException.class, () -> new BffClient(BASE, "", CSECRET));
            assertThrows(IllegalArgumentException.class, () -> new BffClient(BASE, CID, ""));
            assertThrows(IllegalArgumentException.class, () -> new BffClient(BASE, CID, CSECRET, null));
        }
    }

    @Nested
    class LoginPassword {
        @Test void postsBffLoginAndDecodesSession() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"sessionId\":\"sess_1\",\"userId\":\"u_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}")
            ));
            BffSession s = newBff(t).loginPassword("a@b.com", "pw", true, "1.2.3.4", "Mozilla");

            assertEquals("sess_1", s.sessionId());
            assertEquals("u_1", s.userId());
            assertFalse(s.isTotpRequired());

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/bff/login", req.uri().toString());
            assertEquals("POST", req.method());
            assertEquals(EXPECTED_BASIC, req.headers().firstValue("Authorization").orElse(""));
            assertEquals("1.2.3.4", req.headers().firstValue("X-BFF-Client-IP").orElse(""));
            assertEquals("Mozilla", req.headers().firstValue("X-BFF-Client-User-Agent").orElse(""));
        }

        @Test void surfacesTotpRequiredBranch() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"totpRequired\":true,\"challengeToken\":\"ct_xyz\"}")
            ));
            BffSession s = newBff(t).loginPassword("a@b.com", "pw", false, null, null);
            assertTrue(s.isTotpRequired());
            assertEquals("ct_xyz", s.challengeToken());
            assertNull(s.sessionId());
        }

        @Test void omitsForwardedHeadersWhenNullOrEmpty() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"sessionId\":\"sess_1\",\"userId\":\"u_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}")
            ));
            newBff(t).loginPassword("a@b.com", "pw", false, null, "");
            HttpRequest req = t.captured().get(0);
            assertTrue(req.headers().firstValue("X-BFF-Client-IP").isEmpty());
            assertTrue(req.headers().firstValue("X-BFF-Client-User-Agent").isEmpty());
        }
    }

    @Nested
    class VerifyOtp {
        @Test void omitsAppIdWhenNull() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"sessionId\":\"sess_1\",\"userId\":\"u_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}")
            ));
            newBff(t).verifyOtp("a@b.com", "123456", null, false, "1.2.3.4", "ua");

            String body = bodyOf(t.captured().get(0));
            assertFalse(body.contains("appId"), "appId should be omitted when null");
        }

        @Test void includesAppIdAndPasswordAlreadySetFlagOnRegister() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"sessionId\":\"s\",\"userId\":\"u\",\"expiresAt\":\"x\",\"passwordAlreadySet\":true}")
            ));
            BffSession s = newBff(t).verifyOtp("a@b.com", "123456", "app_42", true, "1.2.3.4", "ua");

            assertTrue(s.isPasswordAlreadySet());
            assertTrue(bodyOf(t.captured().get(0)).contains("app_42"));
        }
    }

    @Nested
    class Proxy {
        @Test void getAddsSessionHeader() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{\"ok\":true}")));
            BffClient.ProxyResponse r = newBff(t).proxyGet("sess_42", "/me", "1.2.3.4", "ua");
            assertEquals(200, r.status());

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/bff/proxy/me", req.uri().toString());
            assertEquals("sess_42", req.headers().firstValue("X-BFF-Session-ID").orElse(""));
        }

        @Test void rejectsEmptySessionId() {
            BffClient bff = newBff(new MockTransport(List.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> bff.proxyGet("", "/me", null, null));
        }
    }

    @Nested
    class Logout {
        @Test void postsSessionId() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            newBff(t).logout("sess_99", null, null);

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/bff/logout", req.uri().toString());
            assertTrue(bodyOf(req).contains("sess_99"));
        }
    }

    @Nested
    class Errors {
        @Test void wrapsNon2xxAsManyRowsException() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.status(401, "{\"error\":\"error.invalidCredentials\"}")
            ));
            ManyRowsException ex = assertThrows(ManyRowsException.class,
                    () -> newBff(t).loginPassword("a@b.com", "wrong", false, null, null));
            assertEquals(401, ex.getStatus());
            assertTrue(ex.getBody().contains("invalidCredentials"));
        }
    }

    private static String bodyOf(HttpRequest req) {
        // jdk.internal HttpRequest doesn't expose body directly — round-trip
        // through the publisher subscriber. Simpler: re-encode the same body
        // that BffClient would have written, using the captured arguments.
        // For tests we instead introspect headers to verify behavior; body
        // contents are re-derived from the call signature in tests above
        // when needed. This helper exists for the "contains" checks below.
        java.util.concurrent.atomic.AtomicReference<String> ref = new java.util.concurrent.atomic.AtomicReference<>();
        req.bodyPublisher().ifPresent(bp -> {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
            bp.subscribe(new java.util.concurrent.Flow.Subscriber<>() {
                @Override public void onSubscribe(java.util.concurrent.Flow.Subscription s) { s.request(Long.MAX_VALUE); }
                @Override public void onNext(java.nio.ByteBuffer b) {
                    byte[] bytes = new byte[b.remaining()];
                    b.get(bytes);
                    out.write(bytes, 0, bytes.length);
                }
                @Override public void onError(Throwable t) { latch.countDown(); }
                @Override public void onComplete() { latch.countDown(); }
            });
            try { latch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            ref.set(out.toString(java.nio.charset.StandardCharsets.UTF_8));
        });
        return ref.get() == null ? "" : ref.get();
    }

    @SuppressWarnings("unused")
    private static String prettyJson(String json) {
        try { return new ObjectMapper().readTree(json).toPrettyString(); }
        catch (Exception e) { return json; }
    }

    @SuppressWarnings("unused")
    private static JsonNode parse(String json) {
        try { return new ObjectMapper().readTree(json); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
