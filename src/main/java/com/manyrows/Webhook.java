package com.manyrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verifies HMAC-SHA256 signatures on inbound webhook deliveries from
 * ManyRows.
 *
 * <p>Usage in a customer's webhook receiver (Spring shown — servlets
 * identical):
 *
 * <pre>{@code
 * @PostMapping(value = "/webhooks/manyrows", consumes = MediaType.APPLICATION_JSON_VALUE)
 * public ResponseEntity<?> webhook(@RequestBody byte[] body, @RequestHeader Map<String, String> headers) {
 *     try {
 *         Webhook.verify(secret, headers, body);
 *     } catch (Webhook.InvalidException e) {
 *         return ResponseEntity.status(401).body(Map.of("error", e.code()));
 *     }
 *     // body is verified — parse + process
 *     return ResponseEntity.ok().build();
 * }
 * }</pre>
 *
 * <p>IMPORTANT: read the body as RAW BYTES before verifying. The HMAC
 * covers the exact transmitted bytes; re-serialising parsed JSON
 * changes whitespace and breaks the check. In Spring use
 * {@code @RequestBody byte[]}, NOT a deserialised DTO.
 */
public final class Webhook {

    private static final String HEADER_TIMESTAMP = "x-webhook-timestamp";
    private static final String HEADER_SIGNATURE = "x-webhook-signature";
    private static final String SIGNATURE_PREFIX = "sha256=";
    private static final Duration DEFAULT_TOLERANCE = Duration.ofMinutes(5);

    private Webhook() {}

    /**
     * Reasons {@link InvalidException} can be thrown. Stable string
     * values suitable for logging / metric tags.
     */
    public enum Reason {
        MISSING_TIMESTAMP("missing_timestamp"),
        MISSING_SIGNATURE("missing_signature"),
        INVALID_TIMESTAMP("invalid_timestamp"),
        TIMESTAMP_OUT_OF_WINDOW("timestamp_out_of_window"),
        INVALID_SIGNATURE("invalid_signature");

        private final String code;
        Reason(String code) { this.code = code; }
        public String code() { return code; }
    }

    /**
     * Thrown by {@link #verify} when the delivery is malformed,
     * tampered, or stale. Inspect {@link #reason()} to distinguish
     * causes — all of them mean "reject the delivery".
     */
    public static final class InvalidException extends RuntimeException {
        private final Reason reason;

        public InvalidException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public Reason reason() { return reason; }

        /** Stable lowercase string; convenience for logging. */
        public String code() { return reason.code(); }
    }

    /** Tunes {@link #verify}. Use {@link Builder} or pass {@code null} for defaults. */
    public static final class Options {
        private final Duration tolerance;
        private final Supplier<Instant> now;

        private Options(Duration tolerance, Supplier<Instant> now) {
            this.tolerance = tolerance;
            this.now = now;
        }

        public static Builder builder() { return new Builder(); }

        public static final class Builder {
            private Duration tolerance = DEFAULT_TOLERANCE;
            private Supplier<Instant> now = Instant::now;

            /** Accept timestamps within ±tolerance of {@code now()}. Default 5 minutes. */
            public Builder tolerance(Duration v) { this.tolerance = v; return this; }
            /** Override {@code Instant.now()} (test hook). */
            public Builder now(Supplier<Instant> v) { this.now = v; return this; }
            public Options build() { return new Options(tolerance, now); }
        }
    }

    /**
     * Verifies the HMAC-SHA256 signature and timestamp on an inbound
     * webhook delivery from ManyRows. Throws {@link InvalidException}
     * on any failure; returns normally on success.
     *
     * <p>The signature covers the canonical string
     * {@code "<timestamp>.<body>"} so a replay of an old delivery is
     * detectable by the timestamp check even if the body itself is
     * unchanged.
     *
     * @param secret per-webhook secret from the ManyRows admin UI
     * @param headers inbound headers (case-insensitive lookup)
     * @param body raw request body bytes
     */
    public static void verify(String secret, Map<String, String> headers, byte[] body) {
        verify(secret, headers, body, null);
    }

    /** {@link #verify(String, Map, byte[])} with options. {@code opts == null} uses defaults. */
    public static void verify(String secret, Map<String, String> headers, byte[] body, Options opts) {
        if (opts == null) opts = Options.builder().build();

        String tsRaw = header(headers, HEADER_TIMESTAMP);
        if (tsRaw.isEmpty()) {
            throw new InvalidException(Reason.MISSING_TIMESTAMP, "missing X-Webhook-Timestamp header");
        }
        String sigRaw = header(headers, HEADER_SIGNATURE);
        if (sigRaw.isEmpty()) {
            throw new InvalidException(Reason.MISSING_SIGNATURE, "missing X-Webhook-Signature header");
        }

        long tsUnix;
        try {
            tsUnix = Long.parseLong(tsRaw);
        } catch (NumberFormatException e) {
            throw new InvalidException(Reason.INVALID_TIMESTAMP, "X-Webhook-Timestamp is not an integer");
        }
        Duration delta = Duration.between(Instant.ofEpochSecond(tsUnix), opts.now.get());
        Duration tolerance = opts.tolerance != null ? opts.tolerance : DEFAULT_TOLERANCE;
        if (delta.compareTo(tolerance.negated()) < 0 || delta.compareTo(tolerance) > 0) {
            throw new InvalidException(
                    Reason.TIMESTAMP_OUT_OF_WINDOW,
                    "X-Webhook-Timestamp is outside the accepted window");
        }

        if (!sigRaw.startsWith(SIGNATURE_PREFIX)) {
            throw new InvalidException(
                    Reason.INVALID_SIGNATURE,
                    "X-Webhook-Signature missing 'sha256=' prefix");
        }
        String sigHex = sigRaw.substring(SIGNATURE_PREFIX.length());

        byte[] provided;
        try {
            provided = HexFormat.of().parseHex(sigHex);
        } catch (IllegalArgumentException e) {
            throw new InvalidException(Reason.INVALID_SIGNATURE, "X-Webhook-Signature is not valid hex");
        }

        byte[] expected;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(tsRaw.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) '.');
            mac.update(body);
            expected = mac.doFinal();
        } catch (Exception e) {
            // HmacSHA256 is mandatory in every JRE; this should never happen.
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }

        // MessageDigest.isEqual is constant-time per its Javadoc since Java 7.
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new InvalidException(Reason.INVALID_SIGNATURE, "signature mismatch");
        }
    }

    private static String header(Map<String, String> headers, String name) {
        // Case-insensitive lookup — Spring's request.getHeaders() returns
        // mixed case; raw servlets are also mixed; use a target lowercase
        // match.
        String target = name.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() == null) continue;
            if (e.getKey().toLowerCase(Locale.ROOT).equals(target)) {
                String v = e.getValue();
                return v == null ? "" : v.trim();
            }
        }
        return "";
    }
}
