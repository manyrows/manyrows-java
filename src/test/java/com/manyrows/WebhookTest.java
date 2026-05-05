package com.manyrows;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WebhookTest {

    private static final String SECRET = "whsec_test_supersecret_please_rotate";
    private static final byte[] BODY = "{\"event\":\"user.created\",\"userId\":\"u_1\"}"
            .getBytes(StandardCharsets.UTF_8);

    private static String sign(String secret, String ts, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update(ts.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) '.');
            mac.update(body);
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, String> headers(String ts, String sig) {
        Map<String, String> h = new HashMap<>();
        if (ts != null) h.put("X-Webhook-Timestamp", ts);
        if (sig != null) h.put("X-Webhook-Signature", sig);
        return h;
    }

    private static Webhook.Options atUnix(long sec) {
        return Webhook.Options.builder().now(() -> Instant.ofEpochSecond(sec)).build();
    }

    @Test
    void okOnFreshSignedDelivery() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        String sig = sign(SECRET, ts, BODY);
        Webhook.verify(SECRET, headers(ts, sig), BODY);
    }

    @Test
    void rejectsMissingTimestamp() {
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(null, "sha256=abc"), BODY));
        assertEquals(Webhook.Reason.MISSING_TIMESTAMP, e.reason());
    }

    @Test
    void rejectsMissingSignature() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, null), BODY));
        assertEquals(Webhook.Reason.MISSING_SIGNATURE, e.reason());
    }

    @Test
    void rejectsMalformedTimestamp() {
        String sig = sign(SECRET, "not-a-number", BODY);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers("not-a-number", sig), BODY));
        assertEquals(Webhook.Reason.INVALID_TIMESTAMP, e.reason());
    }

    @Test
    void rejectsStaleTimestamp() {
        String ts = "1700000000";
        String sig = sign(SECRET, ts, BODY);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, sig), BODY, atUnix(1700000000L + 3600)));
        assertEquals(Webhook.Reason.TIMESTAMP_OUT_OF_WINDOW, e.reason());
    }

    @Test
    void rejectsFutureTimestamp() {
        String ts = Long.toString(1700000000L + 3600);
        String sig = sign(SECRET, ts, BODY);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, sig), BODY, atUnix(1700000000L)));
        assertEquals(Webhook.Reason.TIMESTAMP_OUT_OF_WINDOW, e.reason());
    }

    @Test
    void rejectsTamperedBody() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        String sig = sign(SECRET, ts, BODY);
        byte[] tampered = "{\"event\":\"user.created\",\"userId\":\"u_999\"}"
                .getBytes(StandardCharsets.UTF_8);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, sig), tampered));
        assertEquals(Webhook.Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsTamperedTimestamp() {
        long now = Instant.now().getEpochSecond();
        String tsSigned = Long.toString(now);
        String sig = sign(SECRET, tsSigned, BODY);
        String tsHeader = Long.toString(now + 1);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(tsHeader, sig), BODY));
        assertEquals(Webhook.Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsWrongSecret() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        String sig = sign("different-secret", ts, BODY);
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, sig), BODY));
        assertEquals(Webhook.Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void rejectsSignatureWithoutPrefix() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        String full = sign(SECRET, ts, BODY);
        String rawHex = full.substring("sha256=".length());
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, rawHex), BODY));
        assertEquals(Webhook.Reason.INVALID_SIGNATURE, e.reason());
    }

    @Test
    void customTolerance() {
        String ts = "1700000000";
        String sig = sign(SECRET, ts, BODY);
        Webhook.Options opts = Webhook.Options.builder()
                .tolerance(Duration.ofSeconds(10))
                .now(() -> Instant.ofEpochSecond(1700000000L + 30))
                .build();
        Webhook.InvalidException e = assertThrows(Webhook.InvalidException.class,
                () -> Webhook.verify(SECRET, headers(ts, sig), BODY, opts));
        assertEquals(Webhook.Reason.TIMESTAMP_OUT_OF_WINDOW, e.reason());
    }

    @Test
    void caseInsensitiveHeaders() {
        String ts = Long.toString(Instant.now().getEpochSecond());
        String sig = sign(SECRET, ts, BODY);
        Map<String, String> h = new HashMap<>();
        h.put("x-webhook-timestamp", ts);
        h.put("x-webhook-signature", sig);
        Webhook.verify(SECRET, h, BODY);
    }
}
