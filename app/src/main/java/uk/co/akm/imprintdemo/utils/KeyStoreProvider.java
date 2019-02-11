package uk.co.akm.imprintdemo.utils;


import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;

/**
 * Created by thanosmavroidis on 02/11/2019.
 */
class KeyStoreProvider {
    private static final String KEY_STORE_PROVIDER = "AndroidKeyStore";

    KeyStoreProvider() {}

    // Returns a key store instance.
    final KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance(KEY_STORE_PROVIDER);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get a KeyStore instance of type: " + KEY_STORE_PROVIDER, e);
        }
    }

    // Returns a key generator instance to generate keys used for encryption and decryption.
    final KeyGenerator getKeyGenerator(String algorithm) {
        try {
            return KeyGenerator.getInstance(algorithm, KEY_STORE_PROVIDER);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }
    }

    // Returns a key pair generator instance to generate key pairs used for asymmetric encryption.
    final KeyPairGenerator getKeyPairGenerator(String algorithm) {
        try {
            return KeyPairGenerator.getInstance(algorithm, KEY_STORE_PROVIDER);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get KeyPairGenerator instance for the '" + algorithm + "' algorithm from provider '" + KEY_STORE_PROVIDER +  "'.", e);
        }
    }

    /**
     * Returns true if the encryption key exists in the key store (i.e. it has already been
     * generated) or false otherwise.
     *
     * @param keyStore the key store to check for the encryption key
     * @return true if the encryption key exists in the key store (i.e. it has already been
     * generated) or false otherwise
     */
    final boolean keyNotGenerated(KeyStore keyStore, String keyName) {
        try {
            keyStore.load(null);
            return !(keyStore.containsAlias(keyName));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException("Failed to check the KeyStore for key: " + keyName, e);
        }
    }
}
