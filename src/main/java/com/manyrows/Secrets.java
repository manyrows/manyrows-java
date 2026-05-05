package com.manyrows;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Decrypts ManyRows config-secret envelopes server-side.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * import com.manyrows.Secrets;
 * import com.manyrows.Types.*;
 *
 * String privateKeyJwkJson = System.getenv("MANYROWS_WORKSPACE_PRIVATE_KEY");
 * Delivery delivery = client.getDelivery();
 *
 * for (ConfigItem sec : delivery.config().secrets()) {
 *     if (!Boolean.TRUE.equals(sec.isSet()) || sec.envelope() == null) continue;
 *     byte[] plaintext = Secrets.decryptSecret(sec.envelope(), privateKeyJwkJson);
 *     // plaintext is JSON-encoded. For a string secret you'll get
 *     // `"hello"` (with quotes) — parse with Jackson to recover.
 *     String value = new ObjectMapper().readValue(plaintext, String.class);
 * }
 * }</pre>
 *
 * <p>Algorithm: ECDH P-256 → HKDF-SHA256 (salt {@code "manyrows:secrets:v1"},
 * info {@code "workspace-fingerprint:<hex>"}) → AES-256-GCM. Mirrors
 * the browser-side encrypt path in the ManyRows admin UI; if those
 * constants change, update them here too.
 */
public final class Secrets {

    private static final byte[] HKDF_SALT = "manyrows:secrets:v1".getBytes(StandardCharsets.UTF_8);
    private static final String HKDF_INFO_PREFIX = "workspace-fingerprint:";
    private static final String EXPECTED_ALGORITHM = "ECDH-P256+HKDF-SHA256+AES-256-GCM";
    private static final int EXPECTED_VERSION = 1;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final int IV_BYTES = 12;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Secrets() {}

    /**
     * Raised on any decryption failure or malformed envelope. Wraps
     * any underlying cause without exposing whether it was a key
     * mismatch, tampered ciphertext, or fingerprint divergence —
     * all three look identical to a caller.
     */
    public static class SecretsException extends RuntimeException {
        public SecretsException(String message) { super(message); }
        public SecretsException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * Decrypt a secret envelope using the workspace private JWK.
     *
     * @param envelope         the {@code envelope} field from a {@link Types.ConfigItem}
     *                         under {@link Types.DeliveryConfig#secrets} — accepts
     *                         the raw {@link Object} Jackson handed back, a
     *                         {@link Map}, or a JSON {@link String}.
     * @param privateKeyJwkJson the workspace private JWK as a JSON string
     *                          (downloaded once from the admin UI).
     * @return the JSON-encoded plaintext exactly as the browser stored
     *         it (i.e. for a string-typed secret you get {@code "hello"}
     *         with the quotes — parse with Jackson to recover the typed
     *         value).
     * @throws SecretsException on any mismatch: malformed envelope,
     *         wrong algorithm version, base64 decode failures, missing
     *         key fields, GCM authentication failure (wrong key,
     *         tampered ciphertext, or fingerprint mismatch).
     */
    public static byte[] decryptSecret(Object envelope, String privateKeyJwkJson) {
        Map<String, Object> env = parseEnvelope(envelope);

        Number version = (Number) env.get("v");
        if (version == null || version.intValue() != EXPECTED_VERSION) {
            throw new SecretsException("manyrows secrets: unsupported envelope version " + version);
        }
        String alg = (String) env.get("alg");
        if (!EXPECTED_ALGORITHM.equals(alg)) {
            throw new SecretsException("manyrows secrets: unsupported algorithm \"" + alg + "\"");
        }
        String fingerprint = (String) env.get("fingerprintSha256");
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw new SecretsException("manyrows secrets: missing fingerprintSha256");
        }
        @SuppressWarnings("unchecked")
        Map<String, String> ephJwk = (Map<String, String>) env.get("ephemeralPublicKeyJwk");
        if (ephJwk == null) {
            throw new SecretsException("manyrows secrets: missing ephemeralPublicKeyJwk");
        }
        String ivB64 = (String) env.get("ivB64");
        if (ivB64 == null) throw new SecretsException("manyrows secrets: missing ivB64");
        String ciphertextB64 = (String) env.get("ciphertextB64");
        if (ciphertextB64 == null) throw new SecretsException("manyrows secrets: missing ciphertextB64");

        ECParameterSpec p256Params = p256Params();
        PrivateKey privateKey = loadPrivateKey(privateKeyJwkJson, p256Params);
        PublicKey ephemeralPublic = loadEphemeralPublicKey(ephJwk, p256Params);

        byte[] shared;
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(ephemeralPublic, true);
            shared = ka.generateSecret();
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: ECDH failed", e);
        }

        byte[] info = (HKDF_INFO_PREFIX + fingerprint).getBytes(StandardCharsets.UTF_8);
        byte[] aesKey = hkdfSha256(shared, HKDF_SALT, info, 32);

        byte[] iv;
        byte[] ct;
        try {
            iv = Base64.getDecoder().decode(ivB64);
            ct = Base64.getDecoder().decode(ciphertextB64);
        } catch (IllegalArgumentException e) {
            throw new SecretsException("manyrows secrets: base64 decode failed", e);
        }
        if (iv.length < IV_BYTES) {
            throw new SecretsException("manyrows secrets: ivB64 too short");
        }
        // GCM tag is 16 bytes; anything shorter can't possibly contain ciphertext + tag.
        if (ct.length < GCM_TAG_BYTES) {
            throw new SecretsException("manyrows secrets: ciphertextB64 too short");
        }

        // WebCrypto AES-GCM appends the 16-byte tag at the end of the
        // ciphertext, which is the same layout javax.crypto expects.
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ct);
        } catch (Exception e) {
            // Wrong key, tampered ciphertext, fingerprint mismatch all land here.
            // Don't leak which.
            throw new SecretsException(
                    "manyrows secrets: decrypt failed (signature mismatch or wrong key)", e);
        }
    }

    /**
     * Compute the canonical SHA-256 fingerprint of a public JWK.
     * Sorted keys: {@code crv, kty, x, y} → SHA-256 hex. Useful for
     * verifying the fingerprint shown in the admin UI matches the JWK
     * you have on disk. Not required for normal decryption.
     */
    public static String computePublicJwkFingerprint(Map<String, String> publicJwk) {
        try {
            String canonical = "{\"crv\":\"" + publicJwk.get("crv") + "\","
                    + "\"kty\":\"" + publicJwk.get("kty") + "\","
                    + "\"x\":\"" + publicJwk.get("x") + "\","
                    + "\"y\":\"" + publicJwk.get("y") + "\"}";
            byte[] sum = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(sum.length * 2);
            for (byte b : sum) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: SHA-256 unavailable", e);
        }
    }

    private static Map<String, Object> parseEnvelope(Object raw) {
        try {
            if (raw instanceof String s) {
                return MAPPER.readValue(s, new TypeReference<>() {});
            }
            if (raw instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) raw;
                return m;
            }
            // Anything else: round-trip through Jackson to coerce into a Map.
            return MAPPER.convertValue(raw, new TypeReference<>() {});
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: malformed envelope JSON", e);
        }
    }

    private static ECParameterSpec p256Params() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: P-256 params unavailable", e);
        }
    }

    private static PrivateKey loadPrivateKey(String jwkJson, ECParameterSpec params) {
        Map<String, String> jwk;
        try {
            jwk = MAPPER.readValue(jwkJson, new TypeReference<>() {});
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: private JWK JSON parse failed", e);
        }
        if (!"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv"))) {
            throw new SecretsException("manyrows secrets: private key must be EC P-256 JWK");
        }
        String d = jwk.get("d");
        if (d == null) throw new SecretsException("manyrows secrets: private JWK missing 'd'");
        BigInteger s = new BigInteger(1, b64UrlDecode(d, "private 'd'"));
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(s, params));
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: private key construction failed", e);
        }
    }

    private static PublicKey loadEphemeralPublicKey(Map<String, String> jwk, ECParameterSpec params) {
        if (!"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv"))) {
            throw new SecretsException("manyrows secrets: ephemeral public key must be EC P-256 JWK");
        }
        byte[] x = b64UrlDecode(jwk.get("x"), "ephemeral 'x'");
        byte[] y = b64UrlDecode(jwk.get("y"), "ephemeral 'y'");
        if (x.length != 32 || y.length != 32) {
            throw new SecretsException("manyrows secrets: ephemeral public key coords must be 32 bytes each");
        }
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        try {
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, params));
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: ephemeral public key construction failed", e);
        }
    }

    private static byte[] b64UrlDecode(String s, String label) {
        if (s == null) {
            throw new SecretsException("manyrows secrets: missing " + label);
        }
        try {
            return Base64.getUrlDecoder().decode(padBase64(s));
        } catch (IllegalArgumentException e) {
            throw new SecretsException("manyrows secrets: " + label + " base64url decode failed", e);
        }
    }

    private static String padBase64(String s) {
        int rem = s.length() % 4;
        if (rem == 0) return s;
        return s + "====".substring(0, 4 - rem);
    }

    /**
     * RFC 5869 HKDF-Extract+Expand with HMAC-SHA256. Java 17 doesn't
     * have HKDF in stdlib (added in 21+), so we implement it directly
     * on top of Mac. For length ≤ 32 bytes only one expand block is
     * needed, but we handle the general case.
     */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");

            byte[] saltKey = (salt == null || salt.length == 0) ? new byte[hmac.getMacLength()] : salt;
            hmac.init(new SecretKeySpec(saltKey, "HmacSHA256"));
            byte[] prk = hmac.doFinal(ikm);

            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] okm = new byte[length];
            byte[] prev = new byte[0];
            int generated = 0;
            for (int i = 1; generated < length; i++) {
                hmac.update(prev);
                if (info != null) hmac.update(info);
                hmac.update((byte) i);
                prev = hmac.doFinal();
                int copy = Math.min(prev.length, length - generated);
                System.arraycopy(prev, 0, okm, generated, copy);
                generated += copy;
            }
            return okm;
        } catch (Exception e) {
            throw new SecretsException("manyrows secrets: HKDF failed", e);
        }
    }
}
