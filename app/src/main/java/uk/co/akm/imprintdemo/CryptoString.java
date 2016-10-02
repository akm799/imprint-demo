package uk.co.akm.imprintdemo;

import android.content.SharedPreferences;
import android.util.Base64;

import javax.crypto.Cipher;

/**
 * Created by thanosmavroidis on 02/10/2016.
 */
public final class CryptoString {
    private static final String IV_STRING_KEY_POST_FIX = "_iv_string_key";

    private String storageKey;

    private String plainText;
    private String cipherText;
    private String ivAsString;

    public CryptoString(String plainText) {
        if (plainText != null) {
            this.plainText = plainText.trim();
        }
    }

    public CryptoString(SharedPreferences prefs, String storageKey) {
        this.storageKey = storageKey;
        this.cipherText = prefs.getString(storageKey, null);
        this.ivAsString = prefs.getString(buildIvKey(), null);
    }

    public boolean readyToEncrypt() {
        return (plainText != null && cipherText == null);
    }

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

    public void store(SharedPreferences prefs, String storageKey) {
        this.storageKey = storageKey;
        prefs.edit().putString(storageKey, cipherText).putString(buildIvKey(), ivAsString).commit();
    }

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

    public String getCipherText() {
        return cipherText;
    }

    public byte[] getIv() {
        return (ivAsString == null ? null : Base64.decode(ivAsString, Base64.DEFAULT));
    }

    @Override
    public String toString() {
        return plainText;
    }
}
