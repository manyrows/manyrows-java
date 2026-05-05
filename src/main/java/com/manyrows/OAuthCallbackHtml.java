package com.manyrows;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.manyrows.Types.BffSession;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the popup-aware HTML page that the customer's
 * {@code /auth/oauth/callback} handler writes to the browser after
 * {@link BffClient#exchangeAuthCode} (or one of the totp/error branches).
 *
 * <p>The page's inline script branches on {@code window.opener} at runtime:
 * if the callback ran inside a popup opened by AppKit, it
 * {@code postMessage}s a {@code manyrows-oauth-callback} payload to the
 * opener (which AppKit's listener decodes to complete the login) and
 * closes itself. If there's no opener — i.e. the callback ran as a
 * full-page redirect — the script navigates the current tab to the
 * configured success / totp / error URL instead.
 *
 * <p>The Set-Cookie that {@link BffClient#exchangeAuthCode} caused you to
 * land on the response stays on this same response, so the opener finds
 * the session valid the moment it acts on the {@code postMessage}; for
 * the full-page case the cookie is set just before the JS-driven navigate.
 *
 * <p>Customer pattern, inside the {@code /auth/oauth/callback} handler:
 *
 * <pre>{@code
 * String code = req.getParameter("code");
 * String error = req.getParameter("error");
 * String html;
 *
 * if (error != null) {
 *     html = OAuthCallbackHtml.error(error, "/login?failed=1");
 * } else {
 *     try {
 *         BffSession s = bff.exchangeAuthCode(code, redirectUri,
 *             req.getRemoteAddr(), req.getHeader("User-Agent"));
 *         if (s.isTotpRequired()) {
 *             html = OAuthCallbackHtml.totp(s.challengeToken(),
 *                 "/login/totp", "/login?failed=1");
 *         } else {
 *             // Stash s.sessionId() in your own cookie before writing HTML.
 *             session.setAttribute("manyrowsSessionId", s.sessionId());
 *             html = OAuthCallbackHtml.success(s.userId(),
 *                 s.isTotpSetupRequired(), "/");
 *         }
 *     } catch (ManyRowsException ex) {
 *         html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1");
 *     }
 * }
 *
 * res.setContentType("text/html; charset=utf-8");
 * res.setHeader("Cache-Control", "no-store");
 * res.getWriter().write(html);
 * }</pre>
 */
public final class OAuthCallbackHtml {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private OAuthCallbackHtml() {}

    /**
     * Successful login outcome. {@code redirectSuccessUrl} is used when
     * the callback ran as a full-page redirect (no popup opener).
     */
    public static String success(String userId, boolean totpSetupRequired, String redirectSuccessUrl) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("ok", true);
        if (userId != null && !userId.isEmpty()) {
            payload.put("userId", userId);
        }
        if (totpSetupRequired) {
            payload.put("totpSetupRequired", true);
        }
        return render(200, payload, redirectSuccessUrl);
    }

    /**
     * TOTP-required outcome. The opener's listener routes the user to
     * the TOTP code prompt; a full-page caller is sent to
     * {@code redirectTotpUrl} with {@code ?challengeToken=...} appended.
     * Falls back to {@code redirectErrorUrl} (with {@code ?error=
     * totp_redirect_not_configured}) when the TOTP URL is missing.
     */
    public static String totp(String challengeToken, String redirectTotpUrl, String redirectErrorUrl) {
        if (redirectTotpUrl == null || redirectTotpUrl.isEmpty()) {
            return error("totp_redirect_not_configured", redirectErrorUrl);
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("totpRequired", true);
        payload.put("challengeToken", challengeToken);
        return render(200, payload, appendQuery(redirectTotpUrl, "challengeToken", challengeToken));
    }

    /**
     * Error outcome. {@code errorCode} is a short machine-readable code
     * (e.g. {@code "exchange_failed"}, {@code "missing_code"}); the
     * full-page branch sends the browser to
     * {@code redirectErrorUrl?error=<code>}.
     */
    public static String error(String errorCode, String redirectErrorUrl) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("error", errorCode);
        String redirect = redirectErrorUrl == null || redirectErrorUrl.isEmpty()
                ? null
                : appendQuery(redirectErrorUrl, "error", errorCode);
        return render(400, payload, redirect);
    }

    private static String render(int status, Map<String, Object> payload, String redirectUrl) {
        String payloadJson;
        try {
            payloadJson = MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            // Encoding a hand-built map of primitives + Strings can't fail
            // realistically; if it somehow does, fall through to a minimal
            // error payload rather than throwing into the customer's
            // response writer.
            payloadJson = "{\"error\":\"oauth_callback_payload_encode_failed\"}";
            status = 500;
        }
        // Defuse </script> injection: an error code or other field whose
        // value contains </script> would terminate our inline <script>
        // block. Replace </ with <\/ — valid JSON (the / can be escaped),
        // safe in HTML (no </script> sequence in the source).
        payloadJson = payloadJson.replace("</", "<\\/");

        String redirectJs = redirectUrl == null ? "" : jsString(redirectUrl);
        String fallbackText = htmlEscape(payloadJson);

        // Mirrors manyrows-go bff/popup.go writeOAuthCallbackResult.
        return "<!DOCTYPE html>\n"
                + "<html>\n"
                + "<head><title>Completing sign-in…</title></head>\n"
                + "<body>\n"
                + "<p>Completing sign-in…</p>\n"
                + "<script>\n"
                + "(function() {\n"
                + "  var status = " + status + ";\n"
                + "  var payload = " + payloadJson + ";\n"
                + "  var redirectURL = " + (redirectUrl == null ? "\"\"" : redirectJs) + ";\n"
                + "  if (window.opener) {\n"
                + "    try {\n"
                + "      window.opener.postMessage(\n"
                + "        { type: \"manyrows-oauth-callback\", status: status, payload: payload },\n"
                + "        window.location.origin\n"
                + "      );\n"
                + "    } catch (e) { /* opener may be closed */ }\n"
                + "    window.close();\n"
                + "    return;\n"
                + "  }\n"
                + "  if (redirectURL) {\n"
                + "    window.location.replace(redirectURL);\n"
                + "    return;\n"
                + "  }\n"
                + "  document.body.innerHTML = \"<pre>\" + " + jsString(fallbackText) + " + \"</pre>\";\n"
                + "})();\n"
                + "</script>\n"
                + "</body>\n"
                + "</html>";
    }

    /**
     * Discriminated outcome of {@link #dispatch}. Customer's handler writes
     * {@link #html()} to the response; on the {@code success} branch it also
     * issues a session cookie carrying {@link Success#session()}'s
     * {@code sessionId}. The {@code totp} and {@code error} branches are
     * cookie-less by design.
     */
    public sealed interface Outcome permits Success, Totp, Error {
        /** The popup-aware HTML page to write to the response body. */
        String html();
    }

    /** Successful login — write the session cookie before returning {@link #html()}. */
    public record Success(String html, BffSession session) implements Outcome {}

    /** TOTP step-up required — no cookie; AppKit's listener routes the user to the TOTP screen. */
    public record Totp(String html, String challengeToken) implements Outcome {}

    /** Error — surface {@link #error()} to telemetry; AppKit's listener echoes it. */
    public record Error(String html, String error) implements Outcome {}

    /**
     * Single entry point for {@code /auth/oauth/callback}. Mirrors the
     * manyrows-go {@code Handlers.OAuthCallback}: parses the query
     * (error / challengeRequired / code), exchanges the auth code via
     * {@link BffClient#exchangeAuthCode} when present, and returns an
     * {@link Outcome} carrying the popup-aware HTML the customer should
     * write — plus the parsed session on success so the customer's
     * framework can issue its own cookie.
     *
     * <p>Pulls each query param from {@code query} via {@link Map#get};
     * pass a map view of {@code request.getParameterMap()} (just call
     * {@link #firstValue} on it) or any equivalent.
     *
     * <p>Customer pattern (Spring shown — servlets identical):
     *
     * <pre>{@code
     * Map<String, String> q = OAuthCallbackHtml.firstValue(request.getParameterMap());
     * OAuthCallbackHtml.Outcome out = OAuthCallbackHtml.dispatch(
     *     q, bff, redirectUri, "/", "/login?failed=1", "/login/totp",
     *     request.getRemoteAddr(), request.getHeader("User-Agent"));
     *
     * if (out instanceof OAuthCallbackHtml.Success s) {
     *     Cookie c = new Cookie("session", s.session().sessionId());
     *     c.setHttpOnly(true); c.setSecure(true); c.setPath("/");
     *     response.addCookie(c);
     * }
     * response.setContentType("text/html; charset=utf-8");
     * response.getWriter().write(out.html());
     * }</pre>
     *
     * @param query parsed query-string params (use {@link #firstValue} to
     *              flatten servlet's {@code Map<String, String[]>}).
     * @param totpRedirectUrl pass {@code ""} if your app doesn't have a
     *                        dedicated TOTP screen — totp branch falls
     *                        back to the error redirect.
     */
    public static Outcome dispatch(
            Map<String, String> query,
            BffClient bff,
            String redirectUri,
            String successRedirectUrl,
            String errorRedirectUrl,
            String totpRedirectUrl,
            String clientIp,
            String clientUserAgent) {
        String errCode = trimOrEmpty(query.get("error"));
        if (!errCode.isEmpty()) {
            return new Error(error(errCode, errorRedirectUrl), errCode);
        }
        if ("1".equals(trimOrEmpty(query.get("challengeRequired")))) {
            String ct = trimOrEmpty(query.get("challengeToken"));
            return new Totp(totp(ct, totpRedirectUrl, errorRedirectUrl), ct);
        }
        String code = trimOrEmpty(query.get("code"));
        if (code.isEmpty()) {
            return new Error(error("missing_code", errorRedirectUrl), "missing_code");
        }
        BffSession session;
        try {
            session = bff.exchangeAuthCode(code, redirectUri, clientIp, clientUserAgent);
        } catch (ManyRowsException e) {
            String surfacedErr = exchangeErrorCode(e);
            return new Error(error(surfacedErr, errorRedirectUrl), surfacedErr);
        }
        if (session.isTotpRequired()) {
            String ct = session.challengeToken() == null ? "" : session.challengeToken();
            return new Totp(totp(ct, totpRedirectUrl, errorRedirectUrl), ct);
        }
        return new Success(
                success(session.userId(), session.isTotpSetupRequired(), successRedirectUrl),
                session);
    }

    /**
     * Flatten a servlet {@code Map<String, String[]>} into the first-value
     * map {@link #dispatch} expects. Empty arrays map to {@code ""}; null
     * values are skipped.
     */
    public static Map<String, String> firstValue(Map<String, String[]> params) {
        Map<String, String> out = new LinkedHashMap<>(params.size());
        for (Map.Entry<String, String[]> e : params.entrySet()) {
            String[] vs = e.getValue();
            if (vs != null && vs.length > 0 && vs[0] != null) {
                out.put(e.getKey(), vs[0]);
            }
        }
        return out;
    }

    private static String exchangeErrorCode(ManyRowsException e) {
        String body = e.getBody();
        if (body != null && !body.isEmpty()) {
            try {
                JsonNode parsed = MAPPER.readTree(body);
                JsonNode err = parsed.get("error");
                if (err != null && err.isTextual() && !err.asText().isEmpty()) {
                    return err.asText();
                }
            } catch (JsonProcessingException ignored) {
                // Body wasn't JSON — fall through to the generic code.
            }
        }
        return "exchange_failed";
    }

    private static String trimOrEmpty(String s) {
        return s == null ? "" : s.trim();
    }

    static String appendQuery(String base, String key, String value) {
        if (base == null || base.isEmpty()) return base;
        String sep = base.indexOf('?') >= 0 ? "&" : "?";
        return base + sep + urlEncode(key) + "=" + urlEncode(value == null ? "" : value);
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String jsString(String raw) {
        // Build a JS string literal. Escapes only what's actually dangerous
        // inside an inline <script> block: the standard JSON-string set
        // plus < (for </script> safety) and U+2028 / U+2029 (which are
        // line terminators in JS, unlike in JSON, and would break a
        // single-line string). & and > are safe inside <script> — the
        // HTML parser doesn'''t process entities there, and only < starts
        // a tag close.
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '<' -> out.append("\\u003c");
                                case ' ' -> out.append("\\u2028");
                case ' ' -> out.append("\\u2029");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
        return out.toString();
    }

    private static String htmlEscape(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
