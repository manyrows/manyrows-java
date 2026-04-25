package com.manyrows;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Single-method HTTP transport, kept narrow so tests can mock it without a
 * library. The default implementation in {@link Client} wraps Java's built-in
 * {@link java.net.http.HttpClient}.
 */
@FunctionalInterface
public interface HttpTransport {
    HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException;
}
