package io.floci.aws.services.eks;

import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Signs the access entry a token webhook identity was mapped to, so the authorization webhook only applies
 * the access policies of an entry the token webhook itself chose. A user's {@code extra} attributes are set
 * by the authenticator, but a caller allowed to impersonate can set them too; without the signature an
 * impersonated request could claim another principal's access policies. EKS likewise applies no access
 * policies to an impersonated request.
 *
 * <p>The key lives only in memory. After a restart the API server's cached identities carry signatures
 * the new key rejects until they are reauthenticated, at most the token webhook's cache TTL later.
 */
@ApplicationScoped
public class EksAccessIdentitySigner {

    private final byte[] key;

    public EksAccessIdentitySigner() {
        this(newKey());
    }

    EksAccessIdentitySigner(byte[] key) {
        this.key = key.clone();
    }

    private static byte[] newKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /** The signature of {@code principalArn} and {@code principalId} for the cluster {@code clusterArn}. */
    String sign(String clusterArn, String createdAt, String principalArn, String principalId) {
        String message = String.join("\n", clusterArn, createdAt, principalArn, principalId);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    boolean verify(String signature, String clusterArn, String createdAt, String principalArn, String principalId) {
        if (signature == null || clusterArn == null || createdAt == null || principalArn == null
                || principalId == null) {
            return false;
        }
        return MessageDigest.isEqual(signature.getBytes(StandardCharsets.UTF_8),
                sign(clusterArn, createdAt, principalArn, principalId).getBytes(StandardCharsets.UTF_8));
    }
}
