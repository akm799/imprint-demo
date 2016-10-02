package uk.co.akm.imprintdemo;

import android.content.SharedPreferences;
import android.util.Base64;

import javax.crypto.Cipher;

/**
 * Helper class to encrypt and persist a string as well as read
 * the encrypted values from persistent storage and, then, decrypt it.
 * Please note, that in addition to the encrypted data, the initial vector
 * bytes used in the encryption operation are also stored in persistent
 * store. This is because without this initial vector it is not possible
 * to decrypt the encrypted data and recover the original plain-text.
 *
 * Created by thanosmavroidis on 02/10/2016.
 */
public final class CryptoString {
    private static final String IV_STRING_KEY_POST_FIX = "_iv_string_key";

    private String storageKey;

    private String plainText;
    private String cipherText;
    private String ivAsString;

    /**
     * Creates an instance ready for encryption and subsequent storage.
     *
     * @param plainText the plain-text value to be encrypted
     */
    public CryptoString(String plainText) {
        if (plainText != null) {
            this.plainText = plainText.trim();
        }
    }

    /**
     * Creates a value with the encrypted value read from persistent storage.
     *
     * @param prefs the shared preferences from where the encrypted data are read
     * @param storageKey the storage key holding the encrypted data
     */
    public CryptoString(SharedPreferences prefs, String storageKey) {
        this.storageKey = storageKey;
        this.cipherText = prefs.getString(storageKey, null);
        this.ivAsString = prefs.getString(buildIvKey(), null);
    }

    /**
     * Returns true if this instance is ready for encryption or false otherwise.
     *
     * @return true if this instance is ready for encryption or false otherwise
     */
    public boolean readyToEncrypt() {
        return (plainText != null && cipherText == null);
    }

    /**
     * Encrypt the plain-text held in this instance.
     *
     * @param cipher the cipher that will be used for encryption
     */
    public void encrypt(Cipher cipher) {
        if (plainText != null) {
            try {
                final byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
                cipherText = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);

                final byte[] iv = cipher.getIV();
                ivAsString = Base64.encodeToString(iv, Base64.DEFAULT);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Stores the encrypted data in persistent storage. Please note that in the addition to the
     * encrypted bytes, the initial vector bytes used in the encryption process are also stored
     * in this method call. This is because, without this initial vector, it is not possible to
     * decrypt the encrypted bytes to the original plain-text.
     *
     * @param prefs the shared preferences used to store the encrypted data
     * @param storageKey the key under which the encrypted data will be stored in the shared preferences
     */
    public void store(SharedPreferences prefs, String storageKey) {
        this.storageKey = storageKey;
        prefs.edit().putString(storageKey, cipherText).putString(buildIvKey(), ivAsString).commit();
    }

    /**
     * Decrypts the encrypted data held in this instance and recovers the original plain-text.
     *
     * @param cipher the cipher used for the decryption operation.
     */
    public void decrypt(Cipher cipher) {
        if (cipherText != null) {
            final byte[] encryptedBytes = Base64.decode(cipherText, Base64.DEFAULT);
            try {
                final byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                plainText = new String(decryptedBytes, "UTF-8");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private String buildIvKey() {
        return (storageKey + IV_STRING_KEY_POST_FIX);
    }

    /**
     * The encrypted data held in this instance in the form of an encoded string or null if no encryption
     * operation has been performed.
     *
     * @return encrypted data held in this instance in the form of an encoded string or null if no encryption
     * operation has been performed
     */
    public String getCipherText() {
        return cipherText;
    }

    /**
     * The initial vector used in the encryption operation or null if no such operation has taken place.
     *
     * @return the initial vector used in the encryption operation or null if no such operation has taken place
     */
    public byte[] getIv() {
        return (ivAsString == null ? null : Base64.decode(ivAsString, Base64.DEFAULT));
    }

    /**
     * The plain-text that is to be encrypted or that has just been decrypted or null if no such
     * plain-text has been set or decrypted.
     *
     * @return the plain-text that is to be encrypted or that has just been decrypted or null if no
     * such plain-text has been set or decrypted
     */
    @Override
    public String toString() {
        return plainText;
    }
}
