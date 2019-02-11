package uk.co.akm.imprintdemo.utils;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by thanosmavroidis on 02/11/2019.
 */
public final class KeyPairFunctions extends KeyStoreProvider {
    private static final String KEY_PAIR_NAME_PREFIX = "local_fingerprint_verification_key_pair.asymmetric.";

    private final String keyPairName;

    public KeyPairFunctions(String appKeyName) {
        this.keyPairName = (KEY_PAIR_NAME_PREFIX + appKeyName);
    }

    // Generates a key pair for asymmetric encryption, if not already generated.
    private void generateKeyPairIfNoneExists(KeyStore keyStore) {
        if (keyNotGenerated(keyStore, keyPairName)) {
            generateKeyPair(keyPairName);
        }
    }

    // Generates a key pair for asymmetric encryption.
    private void generateKeyPair(String keyPairName) {
        try {
            final KeyPairGenerator keyPairGenerator = getKeyPairGenerator(KeyProperties.KEY_ALGORITHM_EC);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(keyPairName,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setUserAuthenticationRequired(true)
                            .build());

            keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair.", e);
        }
    }
}
