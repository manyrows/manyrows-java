# manyrows-java

Official Java SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go), [`@manyrows/manyrows-node`](https://www.npmjs.com/package/@manyrows/manyrows-node), and [`manyrows-python`](https://github.com/manyrows/manyrows-python).

Requires **Java 17+**. One runtime dependency: [Jackson](https://github.com/FasterXML/jackson-databind).

## Install

This SDK is **not yet on Maven Central**. Two options:

### Use the source directly (recommended)

Copy the files in `src/main/java/com/manyrows/` into your project. There are 8: `Client`, `BffClient`, `PublicProxy`, `OAuthCallbackHtml`, `Auth`, `HttpTransport`, `ManyRowsException`, `Types`. Already use Jackson? You're done. Otherwise add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.18.0</version>
</dependency>
```

### Build a JAR locally

```bash
git clone https://github.com/manyrows/manyrows-java.git
cd manyrows-java
mvn package
# target/manyrows-java-1.0.0.jar
```

## Client

The client wraps the ManyRows Server API. Requires an API key.

```java
import com.manyrows.Client;
import com.manyrows.Types.UserResult;

Client client = new Client(
    "https://app.manyrows.com",
    "your-workspace",
    "your-app-id",
    System.getenv("MANYROWS_API_KEY"));

UserResult user = client.getUser("u_123");
```

### Delivery (config + feature flags)

```java
Delivery delivery = client.getDelivery();
// delivery.config().publicItems(), .privateItems(), .secrets()
// delivery.flags().client(), .server()
```

(`public` and `private` are Java reserved words, so the JSON `public`/`private`
keys map to `publicItems()` / `privateItems()` accessors. The wire format is
unchanged.)

### Check permission

```java
boolean allowed = client.hasPermission(userId, "posts:edit");

// Or get the full result:
PermissionResult result = client.checkPermission(userId, "posts:edit");
// result.allowed(), result.permission(), result.accountId()
```

### User lookup

```java
UserResult user = client.getUser(userId);
// user.user().email(), user.roles(), user.permissions(), user.fields()

UserResult byEmail = client.getUserByEmail("user@example.com");
```

### Members

```java
MembersResult result = client.listMembers(0, 50);
// result.members(), result.total(), result.page(), result.pageSize()

// Filter by email substring:
MembersResult filtered = client.listMembers(0, 50, "alice");

// Or the convenience alias:
MembersResult byEmail = client.listMembersByEmail("alice");
```

### User fields

```java
List<UserField> fields = client.listUserFields();
// fields.get(0).key(), .valueType(), .label()
```

### Error handling

Non-2xx responses throw `ManyRowsException`:

```java
try {
    client.getUser("bogus");
} catch (ManyRowsException ex) {
    System.out.println(ex.getStatus() + " " + ex.getBody());
}
```

`ManyRowsException` extends `RuntimeException` (unchecked) so callers don't
need to declare `throws`. Network errors are wrapped into the same exception.

## BFF Client (full-BFF mode)

`BffClient` calls the ManyRows `/bff/*` server-to-server endpoints — the
"full-BFF" deployment posture where the browser never sees a token, only an
HttpOnly session cookie set by your backend that carries an opaque ManyRows
session ID. AppKit running in the browser hits relative paths on your
server (`/auth/login`, `/auth/google`, `/auth/verify`, `/auth/totp/verify`,
`/auth/passkey/login/{begin,finish}`, `/auth/oauth/callback`,
`/auth/logout`, `/auth/forgot-password`, `/auth/reset-password`,
`/apps/{appId}/a/*` for authed data calls), and your handlers forward each
to ManyRows via `BffClient`.

Authenticates with HTTP Basic. Always pass through the real browser IP and
User-Agent so per-IP rate limits and audit logs in ManyRows attribute to
the actual user instead of your egress IP.

```java
import com.manyrows.BffClient;
import com.manyrows.Types.BffSession;

BffClient bff = new BffClient(
    "https://app.manyrows.com",
    System.getenv("MANYROWS_BFF_CLIENT_ID"),
    System.getenv("MANYROWS_BFF_CLIENT_SECRET"));

// Inside your /auth/login handler:
BffSession s = bff.loginPassword(
    body.email, body.password, body.rememberMe,
    request.getRemoteAddr(),
    request.getHeader("User-Agent"));

if (s.isTotpRequired()) {
    // Reply with {totpRequired: true, challengeToken: s.challengeToken()}.
    // The browser shows the TOTP form, then your /auth/totp/verify handler
    // calls bff.verifyTotp(s.challengeToken(), code, ip, ua).
    return;
}

// Stash s.sessionId() in your own HttpOnly session cookie and respond 200.
sessionStore.put(httpSession, "manyrowsSessionId", s.sessionId());
```

### Forwarding authed AppKit data calls

```java
// Your /apps/{appId}/a/* handler:
String sessionId = sessionStore.get(httpSession, "manyrowsSessionId");
BffClient.ProxyResponse r = bff.proxyGet(
    sessionId,
    "/me",                                  // path within the proxy
    request.getRemoteAddr(),
    request.getHeader("User-Agent"));
response.setStatus(r.status());
response.getWriter().write(r.body());
```

POST/PUT/PATCH/DELETE: `bff.proxyPost(sessionId, path, body, ip, ua)` etc.

### Other login flows

```java
// Google ID token from GSI:
BffSession s = bff.loginGoogle(idToken, rememberMe, ip, ua);

// Email-OTP verify (registration when appId is non-null):
BffSession s = bff.verifyOtp(email, code, appId, rememberMe, ip, ua);
if (s.isPasswordAlreadySet()) {
    // Existing user re-verifying — skip the "set your password" screen.
}

// Passkey:
JsonNode begin = bff.passkeyLoginBegin(ip, ua);   // pass straight to the browser
BffSession s = bff.passkeyLoginFinish(challengeId, response, rememberMe, ip, ua);

// Apple/Microsoft/GitHub OAuth callback (after ManyRows redirects to your
// /auth/oauth/callback?code=...). See `OAuthCallbackHtml` below for the
// popup-aware response page AppKit expects.
BffSession s = bff.exchangeAuthCode(code, redirectUri, ip, ua);

// Logout:
bff.logout(sessionId, ip, ua);
sessionStore.remove(httpSession, "manyrowsSessionId");
```

### Popup-aware OAuth callback HTML

AppKit (in BFF mode) opens Apple/Microsoft/GitHub sign-in in a popup.
After ManyRows redirects the popup to your `/auth/oauth/callback?code=...`,
your handler must serve a specific HTML page that postMessages the
opener (or, when there's no opener, redirects the current tab). Use
`OAuthCallbackHtml` for that:

```java
import com.manyrows.OAuthCallbackHtml;

// Inside /auth/oauth/callback handler:
String code = req.getParameter("code");
String error = req.getParameter("error");
String html;

if (error != null) {
    html = OAuthCallbackHtml.error(error, "/login?failed=1");
} else {
    try {
        BffSession s = bff.exchangeAuthCode(code, redirectUri, ip, ua);
        if (s.isTotpRequired()) {
            html = OAuthCallbackHtml.totp(s.challengeToken(), "/login/totp", "/login?failed=1");
        } else {
            sessionStore.put(httpSession, "manyrowsSessionId", s.sessionId());
            html = OAuthCallbackHtml.success(s.userId(), s.isTotpSetupRequired(), "/");
        }
    } catch (ManyRowsException ex) {
        html = OAuthCallbackHtml.error("exchange_failed", "/login?failed=1");
    }
}
res.setContentType("text/html; charset=utf-8");
res.setHeader("Cache-Control", "no-store");
res.getWriter().write(html);
```

### Public proxies for AppKit boot + pre-login auth

AppKit also hits two unauthenticated endpoints on your backend that
forward to ManyRows: `/apps/{appId}` (public app config) and
`/apps/{appId}/auth/*` (OAuth authorize, OTP request, password reset
discovery, etc.). Use `PublicProxy`:

```java
import com.manyrows.PublicProxy;

PublicProxy pp = new PublicProxy("https://app.manyrows.com", "your-workspace");

// Inside /apps/{appId} GET handler:
PublicProxy.Response r = pp.appBootGet(appId);
res.setStatus(r.status());
res.setContentType(r.contentType());
res.getWriter().write(r.body());

// Inside /apps/{appId}/auth/{rest...} catch-all:
String suffix = req.getRequestURI().substring(("/apps/" + appId + "/auth").length());
String body = "POST".equals(req.getMethod()) ? readBody(req) : null;
PublicProxy.Response r = pp.authForward(
    appId, req.getMethod(), suffix, req.getQueryString(), body, req.getContentType());
res.setStatus(r.status());
res.setContentType(r.contentType());
res.getWriter().write(r.body());
```

### Session cookie security

`BffClient` returns the session ID; you store it in a browser-facing
cookie. Mark that cookie **HttpOnly + Secure + SameSite=Strict** —
servlet `HttpSession` (Spring, Jetty, Tomcat) defaults to HttpOnly and
SameSite=Lax; flip to Strict for `/auth/*` paths. If you set the cookie
manually, set all three flags explicitly. Without them an XSS or
CSRF on the customer's domain hands the attacker a usable session ID.

## Auth helpers

Validate bearer tokens from your end users by calling the ManyRows
`/a/me` endpoint, then read the user ID.

```java
import com.manyrows.Auth;
import java.util.Optional;

Optional<String> token = Auth.bearerToken(request.getHeader("Authorization"));
if (token.isEmpty()) {
    response.setStatus(401);
    return;
}

Optional<String> userId;
try {
    userId = Auth.verifyToken(
            token.get(),
            "https://app.manyrows.com",
            "your-workspace",
            "your-app-id");
} catch (ManyRowsException ex) {
    response.setStatus(401); // fail closed on network errors
    return;
}

if (userId.isEmpty()) {
    response.setStatus(401);
    return;
}

// userId.get() is the authenticated user ID.
```

`verifyToken` returns:
- `Optional.of(userId)` on success
- `Optional.empty()` on rejection (401/403) or empty token
- throws `ManyRowsException` on network errors or unexpected responses (5xx, malformed)

### Spring (filter)

```java
@Component
public class ManyRowsAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        Optional<String> token = Auth.bearerToken(req.getHeader("Authorization"));
        if (token.isEmpty()) {
            res.sendError(401);
            return;
        }
        Optional<String> userId;
        try {
            userId = Auth.verifyToken(token.get(), baseUrl, workspaceSlug, appId);
        } catch (ManyRowsException ex) {
            res.sendError(401);
            return;
        }
        if (userId.isEmpty()) {
            res.sendError(401);
            return;
        }
        req.setAttribute("manyrowsUserId", userId.get());
        chain.doFilter(req, res);
    }
}
```

## Custom HTTP transport

`Client` and `Auth.verifyToken` both accept an optional `HttpTransport` for
testing, request tracing, or custom timeout / proxy / SSL configuration:

```java
HttpClient http = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(30))
    .proxy(ProxySelector.of(new InetSocketAddress("proxy.example.com", 8080)))
    .build();

HttpTransport transport = req -> http.send(req, HttpResponse.BodyHandlers.ofString());

Client client = new Client(baseUrl, workspaceSlug, appId, apiKey, transport);
```

## Webhook verification

ManyRows signs every outbound webhook delivery. Use `Webhook.verify`
on your receiver:

```java
import com.manyrows.Webhook;

@PostMapping(value = "/webhooks/manyrows", consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> webhook(
        @RequestBody byte[] body,                    // raw bytes — not a DTO
        @RequestHeader Map<String, String> headers) {
    try {
        Webhook.verify(secret, headers, body);
    } catch (Webhook.InvalidException e) {
        return ResponseEntity.status(401).body(Map.of("error", e.code()));
    }
    // body is verified — parse + process
    return ResponseEntity.ok().build();
}
```

`Webhook.verify` checks both the HMAC-SHA256 signature (over
`<timestamp>.<body>`) and that `X-Webhook-Timestamp` is within
±5 minutes of now. Pass `Webhook.Options.builder().tolerance(...).build()`
to widen or tighten.

Read the body as **raw bytes** before verifying — re-serializing
parsed JSON changes whitespace and breaks the check.

## License

[MIT](./LICENSE)
