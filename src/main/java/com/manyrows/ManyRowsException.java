package com.manyrows;

/**
 * Thrown for any non-2xx response from the ManyRows API, or for network /
 * decoding failures while talking to it. Inspect {@link #getStatus()} and
 * {@link #getBody()} to distinguish auth failures (401), rate limits (429),
 * server errors (5xx), etc.
 */
public class ManyRowsException extends RuntimeException {

    private final Integer status;
    private final String body;

    public ManyRowsException(String message) {
        super(message);
        this.status = null;
        this.body = null;
    }

    public ManyRowsException(String message, Throwable cause) {
        super(message, cause);
        this.status = null;
        this.body = null;
    }

    public ManyRowsException(String message, int status, String body) {
        super(message);
        this.status = status;
        this.body = body;
    }

    /** HTTP status code, or {@code null} if the failure was not HTTP-related. */
    public Integer getStatus() {
        return status;
    }

    /** Raw response body, or {@code null} if unavailable. */
    public String getBody() {
        return body;
    }
}
