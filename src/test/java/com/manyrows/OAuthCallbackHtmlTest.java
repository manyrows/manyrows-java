package com.manyrows;

import org.junit.jupiter.api.Test;

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
}
