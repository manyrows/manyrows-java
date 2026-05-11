# manyrows-java

Official Java SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go), [`@manyrows/manyrows-node`](https://www.npmjs.com/package/@manyrows/manyrows-node), and [`manyrows-python`](https://github.com/manyrows/manyrows-python).

Requires **Java 17+**. One runtime dependency: [Jackson](https://github.com/FasterXML/jackson-databind).

The examples below assume a self-hosted deployment at
`https://manyrows.example.com`. Swap in whatever host your install
runs on (`http://localhost:3000` for local development, your own
domain in production).

## Install

This SDK is **not yet on Maven Central**. Two options:

### Use the source directly (recommended)

Copy the files in `src/main/java/com/manyrows/` into your project. There are 5: `Client`, `Auth`, `HttpTransport`, `ManyRowsException`, `Types`. Two runtime deps — Jackson for JSON, Nimbus for JWT/JWKS:

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.18.0</version>
</dependency>
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.40</version>
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
    "https://manyrows.example.com",
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

### Decrypt secrets

Secret values are returned as encrypted envelopes. Decrypt them with
your workspace private key (downloaded once when you generated the
workspace key in your install's admin UI):

```java
import com.manyrows.Secrets;
import com.manyrows.Types.*;
import com.fasterxml.jackson.databind.ObjectMapper;

String privateKeyJwkJson = System.getenv("MANYROWS_WORKSPACE_PRIVATE_KEY");
Delivery delivery = client.getDelivery();
ObjectMapper mapper = new ObjectMapper();

for (ConfigItem sec : delivery.config().secrets()) {
    if (!Boolean.TRUE.equals(sec.isSet()) || sec.envelope() == null) continue;
    byte[] plaintext = Secrets.decryptSecret(sec.envelope(), privateKeyJwkJson);
    // plaintext is JSON-encoded. For a string secret you'll get
    // `"hello"` (with quotes) — parse with Jackson to recover.
    String value = mapper.readValue(plaintext, String.class);
}
```

The private key never leaves your server — secrets are decrypted in
process. See `src/main/java/com/manyrows/Secrets.java` for the full
algorithm (ECDH P-256 + HKDF-SHA256 + AES-256-GCM). On JDK 17 we
implement HKDF directly on top of `Mac` since stdlib HKDF only
arrived in 21+.

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

## Auth helpers

Verify the user's JWT **locally** against your install's JWKS. Fetches `${baseUrl}/.well-known/jwks.json` once on first verify, caches the keys in-process, refetches on a kid mismatch. No per-request round trip to ManyRows. Built on [`nimbus-jose-jwt`](https://connect2id.com/products/nimbus-jose-jwt) — the de-facto Java JOSE/JWT library.

Two helpers extract the JWT from a request: `Auth.bearerToken(authorizationHeader)` reads the `Authorization` header and `Auth.mrAtCookie(cookieHeader)` reads the `mr_at` cookie that AppKit sets in cookie mode.

```java
import com.manyrows.Auth;
import java.util.Optional;

// Try Authorization header first, then mr_at cookie (cookie-mode AppKit).
Optional<String> token = Auth.bearerToken(request.getHeader("Authorization"));
if (token.isEmpty()) {
    token = Auth.mrAtCookie(request.getHeader("Cookie"));
}
if (token.isEmpty()) {
    response.setStatus(401);
    return;
}

Optional<String> userId = Auth.verifyToken(
        token.get(),
        "https://manyrows.example.com",
        "your-workspace",
        "your-app-id");
if (userId.isEmpty()) {
    response.setStatus(401);
    return;
}

// userId.get() is the authenticated user ID (the JWT's sub claim).
```

`verifyToken` returns:
- `Optional.of(userId)` on success — the JWT signature verified, exp/nbf are in range, and `sub` is non-empty
- `Optional.empty()` for any verification failure (expired, malformed, wrong signature, missing `sub`, JWKS unreachable)

It does NOT throw on auth-decision-equivalent conditions — fail-closed is the caller's job; `Optional.empty()` is the "not authenticated" signal.

### Spring (filter)

```java
@Component
public class ManyRowsAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        Optional<String> token = Auth.bearerToken(req.getHeader("Authorization"));
        if (token.isEmpty()) {
            token = Auth.mrAtCookie(req.getHeader("Cookie"));
        }
        if (token.isEmpty()) {
            res.sendError(401);
            return;
        }
        Optional<String> userId = Auth.verifyToken(token.get(), baseUrl, workspaceSlug, appId);
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

`Client` accepts an optional `HttpTransport` for testing, request tracing, or custom timeout / proxy / SSL configuration on its non-JWKS API calls:

```java
HttpClient http = HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(30))
    .proxy(ProxySelector.of(new InetSocketAddress("proxy.example.com", 8080)))
    .build();

HttpTransport transport = req -> http.send(req, HttpResponse.BodyHandlers.ofString());

Client client = new Client(baseUrl, workspaceSlug, appId, apiKey, transport);
```

`Auth.verifyToken` doesn't take an `HttpTransport` — its JWKS fetch goes through Nimbus's internal HTTP client. For tests, use the package-private `Auth.verifyToken(token, JWKSource)` overload with an in-memory `ImmutableJWKSet` (see `AuthTest` for examples).

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
