package uk.co.akm.imprintdemo.utils;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import uk.co.akm.imprintdemo.error.UselessKeyException;

/**
 * https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html
 * 
 * Created by Thanos Mavroidis on 02/11/2019.
 */
final class KeyPairFunctions extends KeyStoreProvider {
    private static final String TAG = "KeyPairFunctions";

    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String KEY_PAIR_NAME_PREFIX = "local_fingerprint_verification_key_pair.asymmetric.";

    private final String keyPairName;

    KeyPairFunctions(String appKeyName) {
        this.keyPairName = (KEY_PAIR_NAME_PREFIX + appKeyName);
    }

    PublicKey getOrGeneratePublicKey() {
        final KeyStore keyStore = getKeyStore();
        generateKeyPairIfNoneExists(keyStore);

        return readGeneratedPublicKey(keyStore);
    }

    private void generateKeyPairIfNoneExists(KeyStore keyStore) {
        if (keyNotGenerated(keyStore, keyPairName)) {
            Log.d(TAG, "No existing key-pair found. Will generate a new one.");
            generateKeyPair(keyPairName);
        }
    }

    private PublicKey readGeneratedPublicKey(KeyStore keyStore) {
        try {
            return keyStore.getCertificate(keyPairName).getPublicKey();
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get the public key from the generated key-pair: " + keyPairName, e);
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
                            .setUserAuthenticationRequired(true) // Require hardware (e.g. fingerprint) authentication to generate the key-pair.
                            .build());

            keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair.", e);
        }
    }

    Signature getSignatureInstance() {
        final PrivateKey key = getPrivateKey();

        try {
            final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(key);

            return signature;
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException("Failed to obtain a signature instance for algorithm: " + SIGNATURE_ALGORITHM, nsae);
        } catch (KeyPermanentlyInvalidatedException kpie) {
            Log.d(TAG, "Failed to obtain a signature instance and initialize it with the private key from the key-pair: " + keyPairName + " because the key pair has been permanently invalidated.");
            throw new UselessKeyException(kpie);
        } catch (InvalidKeyException ike) {
            throw new RuntimeException("Failed to obtain a signature instance and initialize it with the private key from the key-pair: " + keyPairName, ike);
        }
    }

    private PrivateKey getPrivateKey() {
        final KeyStore keyStore = loadKeyStore();

        try {
            return (PrivateKey) keyStore.getKey(keyPairName, null);
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain the private key from key-pair: " + keyPairName, e);
        }
    }

    void deleteKeyPair() {
        final KeyStore keyStore = loadKeyStore();

        try {
            keyStore.deleteEntry(keyPairName);
        } catch (KeyStoreException kse) {
            throw new RuntimeException("Failed to delete key-pair: " + keyPairName, kse);
        }
    }
}
