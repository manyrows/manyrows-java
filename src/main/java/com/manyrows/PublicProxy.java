package com.manyrows;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Proxies the unauthenticated browser-facing surface that AppKit hits in
 * BFF mode. Two patterns the customer's backend has to forward to ManyRows
 * with no Basic auth and no session cookie:
 *
 * <ul>
 *   <li>{@code GET /apps/{appId}}: AppKit's bootstrap fetch — auth methods,
 *       branding, OAuth client IDs. Forwards to
 *       {@code /x/{workspaceSlug}/apps/{appId}} on ManyRows.</li>
 *   <li>{@code GET|POST /apps/{appId}/auth/*}: pre-login auth surface —
 *       OAuth provider authorize, OTP request, password reset, etc.
 *       Forwards to {@code /x/{workspaceSlug}/apps/{appId}/auth/*}.</li>
 * </ul>
 *
 * <p>Conceptually distinct from {@link BffClient}: that calls authenticated
 * server-to-server endpoints with HTTP Basic; this just relays browser
 * requests with no credentials of its own. The Go SDK does both inside
 * its {@code MountAppBoot} router-mount helper; Java land has no portable
 * router-mount equivalent, so the customer's framework wires
 * {@code /apps/{appId}} and {@code /apps/{appId}/auth/*} routes manually
 * and calls into this class.
 *
 * <pre>{@code
 * PublicProxy pp = new PublicProxy(
 *     "https://app.manyrows.com",
 *     "your-workspace");
 *
 * // Inside your /apps/{appId} GET handler:
 * PublicProxy.Response r = pp.appBootGet(appId);
 * resp.setStatus(r.status());
 * resp.setContentType(r.contentType());
 * resp.getWriter().write(r.body());
 *
 * // Inside your /apps/{appId}/auth/{rest...} catch-all:
 * String suffix = req.getRequestURI().substring(("/apps/" + appId).length());
 * String body = req.getMethod().equals("POST") ? readBody(req) : null;
 * PublicProxy.Response r = pp.authForward(
 *     appId, req.getMethod(), suffix, req.getQueryString(), body, req.getContentType());
 * resp.setStatus(r.status());
 * resp.setContentType(r.contentType());
 * resp.getWriter().write(r.body());
 * }</pre>
 */
public class PublicProxy {

    static final String USER_AGENT = "manyrows-java-public-proxy/1.0";

    private final String baseUrl;
    private final String workspaceSlug;
    private final HttpTransport transport;

    public PublicProxy(String baseUrl, String workspaceSlug) {
        this(baseUrl, workspaceSlug, Auth.defaultTransport());
    }

    public PublicProxy(String baseUrl, String workspaceSlug, HttpTransport transport) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("manyrows: baseUrl is required");
        }
        if (workspaceSlug == null || workspaceSlug.isEmpty()) {
            throw new IllegalArgumentException("manyrows: workspaceSlug is required");
        }
        if (transport == null) {
            throw new IllegalArgumentException("manyrows: transport is required");
        }
        this.baseUrl = Auth.stripTrailingSlashes(baseUrl);
        this.workspaceSlug = workspaceSlug;
        this.transport = transport;
    }

    /**
     * GET /x/{workspaceSlug}/apps/{appId}. The public boot endpoint for
     * AppKit's bffMode initialisation.
     */
    public Response appBootGet(String appId) {
        if (appId == null || appId.isEmpty()) {
            throw new IllegalArgumentException("manyrows: appId is required");
        }
        return forward("GET", baseUrl + "/x/" + workspaceSlug + "/apps/" + appId, null, null);
    }

    /**
     * Forward an /apps/{appId}/auth/* request to ManyRows.
     *
     * @param appId        target app
     * @param method       HTTP method (GET, POST, ...)
     * @param suffix       path segment after {@code /apps/{appId}/auth} — for
     *                     a bare {@code /apps/{appId}/auth} pass {@code ""}
     *                     or {@code "/"}; for {@code /apps/{appId}/auth/microsoft/authorize}
     *                     pass {@code "/microsoft/authorize"}
     * @param query        URL query string without leading {@code ?}, or
     *                     {@code null} for none
     * @param body         request body, or {@code null}
     * @param contentType  request body Content-Type, or {@code null}
     */
    public Response authForward(String appId, String method, String suffix,
                                String query, String body, String contentType) {
        if (appId == null || appId.isEmpty()) {
            throw new IllegalArgumentException("manyrows: appId is required");
        }
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("manyrows: method is required");
        }
        String s = suffix == null ? "" : suffix;
        if (!s.isEmpty() && !s.startsWith("/")) {
            s = "/" + s;
        }
        String url = baseUrl + "/x/" + workspaceSlug + "/apps/" + appId + "/auth" + s;
        if (query != null && !query.isEmpty()) {
            url = url + "?" + query;
        }
        return forward(method, url, body, contentType);
    }

    private Response forward(String method, String url, String body, String contentType) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("User-Agent", USER_AGENT);
        if (body != null) {
            if (contentType != null && !contentType.isEmpty()) {
                b.header("Content-Type", contentType);
            }
            b.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }

        HttpResponse<String> resp;
        try {
            resp = transport.send(b.build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ManyRowsException("manyrows: request interrupted", e);
        } catch (IOException e) {
            throw new ManyRowsException("manyrows: request failed: " + e.getMessage(), e);
        }

        String upstreamCT = resp.headers().firstValue("Content-Type").orElse("application/json");
        return new Response(resp.statusCode(), resp.body(), upstreamCT, resp.headers().map());
    }

    /**
     * Upstream response — the caller decides what to forward to the browser.
     * {@link #headers} gives the full upstream header map for callers that
     * need to relay specific headers (e.g. {@code Cache-Control}).
     */
    public record Response(
            int status,
            String body,
            String contentType,
            Map<String, java.util.List<String>> headers
    ) {}
}
