# manyrows-java

Official Java SDK for [ManyRows](https://manyrows.com). Mirrors the surface of [`manyrows-go`](https://github.com/manyrows/manyrows-go), [`@manyrows/manyrows-node`](https://www.npmjs.com/package/@manyrows/manyrows-node), and [`manyrows-python`](https://github.com/manyrows/manyrows-python).

Requires **Java 17+**. One runtime dependency: [Jackson](https://github.com/FasterXML/jackson-databind).

## Install

This SDK is **not yet on Maven Central**. Two options:

### Use the source directly (recommended)

Copy the files in `src/main/java/com/manyrows/` into your project. There are only 5: `Client`, `Auth`, `HttpTransport`, `ManyRowsException`, `Types`. Already use Jackson? You're done. Otherwise add to your `pom.xml`:

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

## Auth helpers

Validate bearer tokens from your end users by calling the ManyRows
`/a/app/me` endpoint, then read the user ID.

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

## License

[MIT](./LICENSE)
