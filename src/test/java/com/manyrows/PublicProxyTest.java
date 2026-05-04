package com.manyrows;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PublicProxyTest {

    private static final String BASE = "https://app.manyrows.com";
    private static final String SLUG = "acme";
    private static final String APP = "app_42";

    private PublicProxy newPp(MockTransport t) {
        return new PublicProxy(BASE, SLUG, t);
    }

    @Nested
    class Constructor {
        @Test void rejectsEmptyArgs() {
            assertThrows(IllegalArgumentException.class, () -> new PublicProxy("", SLUG));
            assertThrows(IllegalArgumentException.class, () -> new PublicProxy(BASE, ""));
            assertThrows(IllegalArgumentException.class, () -> new PublicProxy(BASE, SLUG, null));
        }
    }

    @Nested
    class AppBootGet {
        @Test void buildsExpectedUpstreamUrl() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{\"name\":\"X\"}")));
            PublicProxy.Response r = newPp(t).appBootGet(APP);

            assertEquals(200, r.status());
            assertEquals("{\"name\":\"X\"}", r.body());

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/x/" + SLUG + "/apps/" + APP, req.uri().toString());
            assertEquals("GET", req.method());
            assertTrue(req.headers().firstValue("Authorization").isEmpty(),
                    "no Basic auth on public proxy");
        }

        @Test void rejectsEmptyAppId() {
            assertThrows(IllegalArgumentException.class, () -> newPp(new MockTransport(List.of())).appBootGet(""));
        }
    }

    @Nested
    class AuthForward {
        @Test void postsToFullSuffixWithQueryString() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            newPp(t).authForward(APP, "POST", "/microsoft/authorize",
                    "openerOrigin=http%3A%2F%2Flocalhost", "{}", "application/json");

            HttpRequest req = t.captured().get(0);
            assertEquals(
                    BASE + "/x/" + SLUG + "/apps/" + APP + "/auth/microsoft/authorize?openerOrigin=http%3A%2F%2Flocalhost",
                    req.uri().toString());
            assertEquals("POST", req.method());
            assertEquals("application/json", req.headers().firstValue("Content-Type").orElse(""));
        }

        @Test void supportsBareAuthPathForOtpRequest() {
            // AppKit's onRequestCode posts to /apps/{appId}/auth (no suffix)
            // for the email-OTP send step. Empty suffix must hit
            // /x/{slug}/apps/{appId}/auth on ManyRows.
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            newPp(t).authForward(APP, "POST", "", null, "{\"email\":\"a@b.com\"}", "application/json");

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/x/" + SLUG + "/apps/" + APP + "/auth", req.uri().toString());
        }

        @Test void normalisesLeadingSlashOnSuffix() {
            // suffix "google/authorize" without leading slash should still
            // produce the right URL — be forgiving.
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            newPp(t).authForward(APP, "GET", "google/authorize", null, null, null);

            HttpRequest req = t.captured().get(0);
            assertEquals(BASE + "/x/" + SLUG + "/apps/" + APP + "/auth/google/authorize",
                    req.uri().toString());
        }

        @Test void getRequestOmitsContentType() {
            MockTransport t = new MockTransport(List.of(MockTransport.Reply.ok("{}")));
            newPp(t).authForward(APP, "GET", "/microsoft/authorize", null, null, null);

            HttpRequest req = t.captured().get(0);
            assertTrue(req.headers().firstValue("Content-Type").isEmpty());
        }

        @Test void preservesUpstreamStatusOnNon2xx() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.status(409, "{\"error\":\"error.emailAlreadyRegistered\"}")));
            PublicProxy.Response r = newPp(t).authForward(APP, "POST", "/register",
                    null, "{\"email\":\"a@b.com\"}", "application/json");
            assertEquals(409, r.status());
            assertTrue(r.body().contains("emailAlreadyRegistered"));
        }

        @Test void rejectsEmptyArgs() {
            PublicProxy pp = newPp(new MockTransport(List.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> pp.authForward("", "GET", "/x", null, null, null));
            assertThrows(IllegalArgumentException.class,
                    () -> pp.authForward(APP, "", "/x", null, null, null));
        }
    }
}
