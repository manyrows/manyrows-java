package com.manyrows;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal HttpTransport for tests. Returns canned replies in order; reuses
 * the last reply for any further requests. Captures every request so tests
 * can assert URL / headers.
 */
final class MockTransport implements HttpTransport {

    static final class Reply {
        final int status;
        final String body;
        final IOException error;

        private Reply(int status, String body, IOException error) {
            this.status = status;
            this.body = body;
            this.error = error;
        }

        static Reply ok(String body) {
            return new Reply(200, body, null);
        }

        static Reply status(int status, String body) {
            return new Reply(status, body, null);
        }

        static Reply error(IOException error) {
            return new Reply(0, null, error);
        }
    }

    private final List<Reply> replies;
    private final List<HttpRequest> captured = new ArrayList<>();
    private int idx = 0;

    MockTransport(List<Reply> replies) {
        this.replies = replies;
    }

    List<HttpRequest> captured() {
        return captured;
    }

    @Override
    public HttpResponse<String> send(HttpRequest request) throws IOException {
        captured.add(request);
        Reply r = replies.get(Math.min(idx++, replies.size() - 1));
        if (r.error != null) {
            throw r.error;
        }
        return new HttpResponse<>() {
            @Override public int statusCode() { return r.status; }
            @Override public HttpRequest request() { return request; }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a, b) -> true); }
            @Override public String body() { return r.body; }
            @Override public Optional<SSLSession> sslSession() { return Optional.empty(); }
            @Override public URI uri() { return request.uri(); }
            @Override public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }
}
