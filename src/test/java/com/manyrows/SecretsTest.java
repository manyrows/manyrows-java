package com.manyrows;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for {@link Secrets#decryptSecret}. Mirrors the
 * browser-side encrypt path in
 * manyrows-ui/src/project/ConfigKeys.tsx::encryptSecretValueToEnvelope.
 * If algorithm constants change, update them in three places: the
 * browser, Secrets.java, and this test helper.
 */
class SecretsTest {

    private static final byte[] HKDF_SALT = "manyrows:secrets:v1".getBytes(StandardCharsets.UTF_8);
    private static final String HKDF_INFO_PREFIX = "workspace-fingerprint:";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private record Keypair(String privateJwkJson, Map<String, String> publicJwk, String fingerprint) {}

    private static Keypair generateKeypair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();

        byte[] x = bigIntTo32(pub.getW().getAffineX());
        byte[] y = bigIntTo32(pub.getW().getAffineY());
        byte[] d = bigIntTo32(priv.getS());

        Map<String, String> publicJwk = new LinkedHashMap<>();
        publicJwk.put("kty", "EC");
        publicJwk.put("crv", "P-256");
        publicJwk.put("x", b64Url(x));
        publicJwk.put("y", b64Url(y));

        Map<String, String> privateJwk = new LinkedHashMap<>(publicJwk);
        privateJwk.put("d", b64Url(d));

        String fingerprint = Secrets.computePublicJwkFingerprint(publicJwk);
        return new Keypair(MAPPER.writeValueAsString(privateJwk), publicJwk, fingerprint);
    }

    /** Browser-side encrypt: ECDH(P256) + HKDF-SHA256 + AES-256-GCM. */
    private static Map<String, Object> encryptForTest(byte[] plaintext, Keypair kp) throws Exception {
        // Reconstruct workspace public key from JWK.
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec p256 = ap.getParameterSpec(ECParameterSpec.class);

        BigInteger pubX = new BigInteger(1, b64UrlDecode(kp.publicJwk().get("x")));
        BigInteger pubY = new BigInteger(1, b64UrlDecode(kp.publicJwk().get("y")));
        var wsPub = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new java.security.spec.ECPublicKeySpec(
                        new java.security.spec.ECPoint(pubX, pubY), p256));

        // Generate ephemeral keypair.
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair eph = g.generateKeyPair();
        ECPublicKey ephPub = (ECPublicKey) eph.getPublic();

        // ECDH.
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(wsPub, true);
        byte[] shared = ka.generateSecret();

        // HKDF-SHA256 → 32-byte AES key.
        byte[] info = (HKDF_INFO_PREFIX + kp.fingerprint()).getBytes(StandardCharsets.UTF_8);
        byte[] aesKey = hkdfSha256(shared, HKDF_SALT, info, 32);

        // AES-256-GCM with random 12-byte IV; tag appended to ciphertext.
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ctWithTag = cipher.doFinal(plaintext);

        // Build envelope.
        Map<String, String> ephJwk = new LinkedHashMap<>();
        ephJwk.put("kty", "EC");
        ephJwk.put("crv", "P-256");
        ephJwk.put("x", b64Url(bigIntTo32(ephPub.getW().getAffineX())));
        ephJwk.put("y", b64Url(bigIntTo32(ephPub.getW().getAffineY())));

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("v", 1);
        envelope.put("alg", "ECDH-P256+HKDF-SHA256+AES-256-GCM");
        envelope.put("fingerprintSha256", kp.fingerprint());
        envelope.put("ephemeralPublicKeyJwk", ephJwk);
        envelope.put("ivB64", Base64.getEncoder().encodeToString(iv));
        envelope.put("ciphertextB64", Base64.getEncoder().encodeToString(ctWithTag));
        return envelope;
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
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
    }

    private static byte[] bigIntTo32(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        if (b.length == 33 && b[0] == 0) {
            byte[] r = new byte[32];
            System.arraycopy(b, 1, r, 0, 32);
            return r;
        }
        byte[] r = new byte[32];
        System.arraycopy(b, 0, r, 32 - b.length, b.length);
        return r;
    }

    private static String b64Url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] b64UrlDecode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    @Test
    void roundTripString() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        byte[] plaintext = Secrets.decryptSecret(env, kp.privateJwkJson());
        assertEquals("\"hello\"", new String(plaintext, StandardCharsets.UTF_8));
        assertEquals("hello", MAPPER.readValue(plaintext, String.class));
    }

    @Test
    void roundTripObject() throws Exception {
        Keypair kp = generateKeypair();
        String json = "{\"db_url\":\"postgres://localhost\",\"port\":5432}";
        Map<String, Object> env = encryptForTest(json.getBytes(StandardCharsets.UTF_8), kp);
        byte[] plaintext = Secrets.decryptSecret(env, kp.privateJwkJson());
        assertEquals(json, new String(plaintext, StandardCharsets.UTF_8));
    }

    @Test
    void acceptsEnvelopeAsJsonString() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        String envJson = MAPPER.writeValueAsString(env);
        byte[] plaintext = Secrets.decryptSecret(envJson, kp.privateJwkJson());
        assertEquals("\"hello\"", new String(plaintext, StandardCharsets.UTF_8));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        byte[] ct = Base64.getDecoder().decode((String) env.get("ciphertextB64"));
        ct[0] ^= 0xFF;
        env.put("ciphertextB64", Base64.getEncoder().encodeToString(ct));
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(env, kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("decrypt failed"));
    }

    @Test
    void rejectsWrongPrivateKey() throws Exception {
        Keypair kp = generateKeypair();
        Keypair other = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(env, other.privateJwkJson()));
        assertTrue(e.getMessage().contains("decrypt failed"));
    }

    @Test
    void rejectsFingerprintMismatch() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        env.put("fingerprintSha256", "a".repeat(64));
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(env, kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("decrypt failed"));
    }

    @Test
    void rejectsUnsupportedAlgorithm() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        env.put("alg", "AES-128-CBC");
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(env, kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("unsupported algorithm"));
    }

    @Test
    void rejectsUnsupportedVersion() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> env = encryptForTest("\"hello\"".getBytes(StandardCharsets.UTF_8), kp);
        env.put("v", 2);
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(env, kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("unsupported envelope version"));
    }

    @Test
    void rejectsMalformedEnvelopeJson() throws Exception {
        Keypair kp = generateKeypair();
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret("not json", kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("malformed envelope"));
    }

    @Test
    void rejectsEnvelopeMissingFields() throws Exception {
        Keypair kp = generateKeypair();
        Map<String, Object> partial = new HashMap<>();
        partial.put("v", 1);
        partial.put("alg", "x");
        Secrets.SecretsException e = assertThrows(Secrets.SecretsException.class,
                () -> Secrets.decryptSecret(partial, kp.privateJwkJson()));
        assertTrue(e.getMessage().contains("unsupported algorithm")
                || e.getMessage().contains("missing"));
    }

    @Test
    void computePublicJwkFingerprintIsStableHex() {
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", "WxXEJP0w8e3FKpNi3qwJtBkb1H1bYU2pwLRm6q3a3Ww");
        jwk.put("y", "5y4FJW3LZ1MIK6CuM_kyLQH8UkN7q3KbbpXaWPOkY1Y");
        String fp1 = Secrets.computePublicJwkFingerprint(jwk);
        assertEquals(64, fp1.length());
        assertTrue(fp1.matches("[0-9a-f]{64}"));
        String fp2 = Secrets.computePublicJwkFingerprint(jwk);
        assertEquals(fp1, fp2);
    }
}
