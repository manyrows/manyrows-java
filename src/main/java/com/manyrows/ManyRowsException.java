package com.manyrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Thrown for any non-2xx response from the ManyRows API, or for network /
 * decoding failures while talking to it. Inspect {@link #getStatus()} and
 * {@link #getBody()} to distinguish auth failures (401), rate limits (429),
 * server errors (5xx), etc. For endpoints with stable error codes (the
 * {@code "error"} field of the JSON body), {@link #getCode()} /
 * {@link #hasCode(String)} / {@link #isCode(Throwable, String)} let callers
 * branch without parsing the body themselves.
 */
public class ManyRowsException extends RuntimeException {

    // Stable API error codes (the "error" field of a JSON error body) for the
    // organization endpoints.
    public static final String CODE_USER_NOT_SIGNED_IN = "error.userNotSignedIn";
    public static final String CODE_INVITE_PENDING = "error.invitePending";
    public static final String CODE_CONFLICT = "error.conflict";
    public static final String CODE_NOT_FOUND = "error.notFound";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Integer status;
    private final String body;
    private final String code;

    public ManyRowsException(String message) {
        super(message);
        this.status = null;
        this.body = null;
        this.code = null;
    }

    public ManyRowsException(String message, Throwable cause) {
        super(message, cause);
        this.status = null;
        this.body = null;
        this.code = null;
    }

    public ManyRowsException(String message, int status, String body) {
        super(message);
        this.status = status;
        this.body = body;
        this.code = parseCode(body);
    }

    /** HTTP status code, or {@code null} if the failure was not HTTP-related. */
    public Integer getStatus() {
        return status;
    }

    /** Raw response body, or {@code null} if unavailable. */
    public String getBody() {
        return body;
    }

    /**
     * Stable API error code (the {@code "error"} field of the JSON error body),
     * e.g. {@link #CODE_NOT_FOUND}, or {@code null} if the body carried none.
     */
    public String getCode() {
        return code;
    }

    /** Whether this exception carries the given API error code. */
    public boolean hasCode(String code) {
        return code != null && code.equals(this.code);
    }

    /**
     * Reports whether {@code t} is a {@link ManyRowsException} carrying the
     * given API code. Mirrors the Go SDK's {@code IsCode(err, code)}.
     */
    public static boolean isCode(Throwable t, String code) {
        return t instanceof ManyRowsException e && e.hasCode(code);
    }

    /** Best-effort extraction of the {@code "error"} field from a JSON error body. */
    private static String parseCode(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(body);
            JsonNode error = node.path("error");
            return error.isTextual() ? error.asText() : null;
        } catch (java.io.IOException e) {
            return null; // not JSON — no stable code
        }
    }
}