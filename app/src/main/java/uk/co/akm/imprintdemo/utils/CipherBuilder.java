package uk.co.akm.imprintdemo.utils;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Builds a cipher, initialised with an encryption key, that can be used for fingerprint
 * authentication purposes.
 *
 * Created by thanosmavroidis on 18/09/2016.
 */
public final class CipherBuilder extends KeyStoreProvider {
    private static final String KEY_NAME_PREFIX = "local_fingerprint_data_encryption_key.";

    private final String keyName;

    CipherBuilder(String appKeyName) {
        this.keyName = (KEY_NAME_PREFIX + appKeyName);
    }

    /**
     * Returns a cipher that can be used to encrypt data.
     *
     * @return a cipher that can be used to encrypt data
     */
    Cipher buildEncryptionCipher() {
        return buildCipher(null);
    }

    /**
     * Returns a cipher that can be used to decrypt data.
     *
     * @param iv the initialization vector used when encrypting the data that we wish to decrypt
     * @return a cipher that can be used to decrypt data
     */
    Cipher buildDecryptionCipher(byte[] iv) {
        return buildCipher(iv);
    }

    private Cipher buildCipher(byte[] iv) {
        final KeyStore keyStore = getKeyStore();
        final SecretKey key = getOrGenerateEncryptionKey(keyStore);

        return buildCipher(key, iv);
    }

    // Returns an encryption key to be used for our fingerprint authentication
    private SecretKey getOrGenerateEncryptionKey(KeyStore keyStore) {
        if (keyNotGenerated(keyStore, keyName)) {
            generateEncryptionKey(keyStore);
        }

        return getEncryptionKey(keyStore);
    }

    // Generates an encryption key for our fingerprint authentication.
    private void generateEncryptionKey(KeyStore keyStore) {
        final KeyGenerator keyGenerator = getKeyGenerator(KeyProperties.KEY_ALGORITHM_AES);

        try {
            final int keyPurposes = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
            final KeyGenParameterSpec.Builder keyGenSpecBuilder = new KeyGenParameterSpec.Builder(keyName, keyPurposes);
            keyGenSpecBuilder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true) // This means that the resulting cipher cannot be used before some kind of user authentication takes place.
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            keyStore.load(null);
            keyGenerator.init(keyGenSpecBuilder.build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertificateException | IOException e) {
            throw new RuntimeException("Failed to generate the encryption key", e);
        }
    }

    // Gets the encryption key which is already generated.
    private SecretKey getEncryptionKey(KeyStore keyStore) {
        try {
            keyStore.load(null);
            return (SecretKey) keyStore.getKey(keyName, null);
        } catch (UnrecoverableKeyException uke) {
            return null;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize Cipher", e);
        }
    }

    // Builds and initializes cipher with the input secret key.
    private Cipher buildCipher(SecretKey key, byte[] iv) {
        Cipher cipher;

        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher instance", e);
        }

        try {
            if (iv == null) {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            } else {
                final IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            }

            return cipher;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Cipher", e);
        }
    }
}
