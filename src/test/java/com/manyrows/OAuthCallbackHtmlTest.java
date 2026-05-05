package com.manyrows;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OAuthCallbackHtmlTest {

    @Test
    void successPayloadIncludesUserIdAndOk() {
        String html = OAuthCallbackHtml.success("u_42", false, "/");
        assertTrue(html.contains("\"ok\":true"), "ok flag");
        assertTrue(html.contains("\"userId\":\"u_42\""), "userId");
        assertFalse(html.contains("totpSetupRequired"), "no setup flag when false");
        assertTrue(html.contains("redirectURL = \"/\""), "redirect");
    }

    @Test
    void successWithTotpSetupRequiredFlagsIt() {
        String html = OAuthCallbackHtml.success("u_42", true, "/welcome");
        assertTrue(html.contains("\"totpSetupRequired\":true"), "setup flag");
    }

    @Test
    void totpAppendsChallengeTokenToRedirect() {
        String html = OAuthCallbackHtml.totp("ct_abc", "/login/totp", "/login?failed=1");
        assertTrue(html.contains("\"totpRequired\":true"));
        assertTrue(html.contains("\"challengeToken\":\"ct_abc\""));
        assertTrue(html.contains("/login/totp?challengeToken=ct_abc"),
                "redirect URL should include challengeToken");
    }

    @Test
    void totpFallsBackToErrorWhenTotpUrlMissing() {
        String html = OAuthCallbackHtml.totp("ct_abc", "", "/login?failed=1");
        assertTrue(html.contains("totp_redirect_not_configured"));
        assertTrue(html.contains("/login?failed=1&error=totp_redirect_not_configured"));
    }

    @Test
    void errorEncodesCodeIntoQuery() {
        String html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1");
        assertTrue(html.contains("\"error\":\"exchange_failed\""));
        assertTrue(html.contains("/login?failed=1&error=exchange_failed"));
    }

    @Test
    void errorAddsQueryStartWhenRedirectHasNoneYet() {
        String html = OAuthCallbackHtml.error("missing_code", "/login");
        assertTrue(html.contains("/login?error=missing_code"));
    }

    @Test
    void errorWithEmptyRedirectStillRendersHtmlAndOmitsRedirect() {
        String html = OAuthCallbackHtml.error("missing_code", "");
        assertTrue(html.contains("\"error\":\"missing_code\""));
        assertTrue(html.contains("redirectURL = \"\""), "empty redirect placeholder");
    }

    @Test
    void htmlIsPopupAware() {
        String html = OAuthCallbackHtml.success("u_42", false, "/");
        assertTrue(html.contains("if (window.opener)"), "popup branch");
        assertTrue(html.contains("window.location.replace"), "full-page redirect branch");
        assertTrue(html.contains("manyrows-oauth-callback"), "postMessage type");
        assertTrue(html.contains("window.close()"), "self-close after postMessage");
    }

    @Test
    void scriptTagInjectionIsEscaped() {
        // Edge case: error code like "</script><script>alert(1)</script>"
        // would terminate our <script> block if not escaped.
        String html = OAuthCallbackHtml.error("</script><script>alert(1)</script>", "/oops");
        // The literal </script> sequence MUST NOT appear inside the inline JS.
        // The opening <script> tag is the legit one we serve; check there's no
        // closing </script> before the legit one at the end.
        int firstClose = html.indexOf("</script>");
        int lastClose = html.lastIndexOf("</script>");
        assertEquals(firstClose, lastClose,
                "only the wrapping </script> may appear; payload escapes < to \\u003c");
    }

    @Test
    void appendQueryHelperBehaves() {
        assertEquals("/x?a=b", OAuthCallbackHtml.appendQuery("/x", "a", "b"));
        assertEquals("/x?y=1&a=b", OAuthCallbackHtml.appendQuery("/x?y=1", "a", "b"));
        // URLEncoder.encode is form-style: spaces become '+'. Browsers
        // decode '+' as space in query values, so functionally equivalent
        // to %20 for our use case.
        assertEquals("/x?a=hello+world", OAuthCallbackHtml.appendQuery("/x", "a", "hello world"));
    }

    @Nested
    class Dispatch {
        private static final String BASE = "https://app.manyrows.com";
        private static final String REDIRECT = "https://yourapp.com/auth/oauth/callback";
        private static final String SUCCESS = "/";
        private static final String ERR = "/login?failed=1";
        private static final String TOTP = "/login/totp";

        private BffClient newBff(MockTransport t) {
            return new BffClient(BASE, "cid", "csecret", t);
        }

        private Map<String, String> q(String... kv) {
            Map<String, String> m = new LinkedHashMap<>();
            for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
            return m;
        }

        @Test
        void errorBranchShortCircuits() {
            MockTransport t = new MockTransport(List.of()); // no upstream call
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("error", "provider_exchange_failed"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Error.class, out);
            assertEquals("provider_exchange_failed", ((OAuthCallbackHtml.Error) out).error());
            assertTrue(out.html().contains("provider_exchange_failed"));
            assertEquals(0, t.captured().size());
        }

        @Test
        void challengeRequiredShortCircuits() {
            MockTransport t = new MockTransport(List.of());
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("challengeRequired", "1", "challengeToken", "ct_abc", "state", "s"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Totp.class, out);
            assertEquals("ct_abc", ((OAuthCallbackHtml.Totp) out).challengeToken());
            assertTrue(out.html().contains("\"totpRequired\":true"));
            assertTrue(out.html().contains("/login/totp?challengeToken=ct_abc"));
            assertEquals(0, t.captured().size());
        }

        @Test
        void missingCodeWhenQueryIsEmpty() {
            MockTransport t = new MockTransport(List.of());
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q(), newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Error.class, out);
            assertEquals("missing_code", ((OAuthCallbackHtml.Error) out).error());
        }

        @Test
        void successReturnsSessionAndHtml() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok(
                            "{\"sessionId\":\"sess_123\",\"userId\":\"u_42\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}")));
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("code", "abc123", "state", "s"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Success.class, out);
            OAuthCallbackHtml.Success s = (OAuthCallbackHtml.Success) out;
            assertEquals("sess_123", s.session().sessionId());
            assertEquals("u_42", s.session().userId());
            assertTrue(out.html().contains("\"userId\":\"u_42\""));
        }

        @Test
        void postExchangeTotpRequired() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.ok("{\"totpRequired\":true,\"challengeToken\":\"ct_xyz\"}")));
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("code", "abc123"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Totp.class, out);
            assertEquals("ct_xyz", ((OAuthCallbackHtml.Totp) out).challengeToken());
        }

        @Test
        void exchangeErrorSurfacesUpstreamCode() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.status(401, "{\"error\":\"exchange_token_invalid\"}")));
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("code", "abc123"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Error.class, out);
            assertEquals("exchange_token_invalid", ((OAuthCallbackHtml.Error) out).error());
        }

        @Test
        void exchangeErrorFallsBackWhenBodyIsNotJson() {
            MockTransport t = new MockTransport(List.of(
                    MockTransport.Reply.status(500, "not json")));
            OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
                    q("code", "abc123"),
                    newBff(t), REDIRECT, SUCCESS, ERR, TOTP, "1.2.3.4", "ua");
            assertInstanceOf(OAuthCallbackHtml.Error.class, out);
            assertEquals("exchange_failed", ((OAuthCallbackHtml.Error) out).error());
        }

        @Test
        void firstValueFlattensServletParamMap() {
            Map<String, String[]> params = new LinkedHashMap<>();
            params.put("code", new String[]{"abc123"});
            params.put("state", new String[]{"s1", "s2"});
            params.put("empty", new String[]{});
            params.put("nullVal", null);
            Map<String, String> flat = OAuthCallbackHtml.firstValue(params);
            assertEquals("abc123", flat.get("code"));
            assertEquals("s1", flat.get("state"));
            assertFalse(flat.containsKey("empty"));
            assertFalse(flat.containsKey("nullVal"));
        }
    }
}
