package uk.co.akm.imprintdemo;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import javax.crypto.Cipher;

import uk.co.akm.imprintdemo.utils.AuthenticationListener;
import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

public class AuthCryptoActivity extends AppCompatActivity implements AuthenticationListener {
    private static final String PREFS_NAME = "uk.co.akm.imprintdemo.prefs";
    private static final String CIPHER_TEXT_KEY = "cipher.text.store.key";

    private TextView state;
    private TextView cipherTextView;
    private EditText plainTextView;

    private String plainText;
    private byte[] cipherText;

    private FingerprintLocalAuthenticator authenticator;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_crypto);

        state = (TextView)findViewById(R.id.auth_state);
        cipherTextView = (TextView)findViewById(R.id.cipher_text);
        plainTextView = (EditText) findViewById(R.id.plain_text);

        final String cipherTextStr = readCipherText();
        if (cipherTextStr != null) {
            allowDecryptOption(cipherTextStr);
        }
    }

    private String readCipherText() {
        final SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        final String cypherTextStr = prefs.getString(CIPHER_TEXT_KEY, null);
        if (cypherTextStr != null) {
            cipherText = Base64.decode(cypherTextStr, Base64.DEFAULT);
        }

        return cypherTextStr;
    }

    private void allowDecryptOption(String cipherTextStr) {
        cipherTextView.setText(cipherTextStr);
        cipherTextView.setVisibility(View.VISIBLE);
        findViewById(R.id.decrypt_btn).setVisibility(View.VISIBLE);
    }

    @Override
    protected void onPause() {
        super.onPause();

        if (authenticator != null) {
            authenticator.stopAuthentication();
        }
    }

    // Authentication process cancelled manually by the user.
    public void onCancel(View view) {
        if (authenticator != null) {
            authenticator.stopAuthentication();
            authenticator = null;
        }

        finish();
    }

    public void onEncrypt(View view) {
        plainText = plainTextView.getText().toString().trim();
        if (plainText.isEmpty()) {
            plainText = null;
            Toast.makeText(this, "Nothing to encrypt", Toast.LENGTH_SHORT).show();
        } else {
            plainTextView.setEnabled(false);
            state.setText("Touch fingerptint sensor to encrypt");

            authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();
            authenticator.startAuthenticationForEncryption(this, this);
        }
    }

    public void onDecrypt(View view) {
        plainText = null;
        plainTextView.setText("");
        plainTextView.setEnabled(false);
        state.setText("Touch fingerptint sensor to decrypt");

        authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();
        authenticator.startAuthenticationForDecryption(this, this);
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        Toast.makeText(this, "Authentication Error\n" + errString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        Toast.makeText(this, "Authentication Help\n" + helpString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        authenticator = null;
        if (plainText == null) {
            decrypt(result);
        } else {
            encrypt(result);
        }
    }

    private void encrypt(FingerprintManager.AuthenticationResult result) {
        plainTextView.setEnabled(true);
        encrypt(plainText, result.getCryptoObject().getCipher());
    }

    private void encrypt(String plainText, Cipher cipher) {
        try {
            cipherText = cipher.doFinal(plainText.getBytes());
            final String cypherTextStr = storeCipherText(cipherText);
            if (cypherTextStr != null) {
                allowDecryptOption(cypherTextStr);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Failed to encrypt plaintext", Toast.LENGTH_SHORT).show();
        }
    }

    private String storeCipherText(byte[] cipherText) {
        final String cypherTextStr = Base64.encodeToString(cipherText, Base64.DEFAULT);
        final SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(CIPHER_TEXT_KEY, cypherTextStr).commit();

        return cypherTextStr;
    }

    private void decrypt(FingerprintManager.AuthenticationResult result) {
        if (result != null) {
            Toast.makeText(this, "Under construction", Toast.LENGTH_SHORT).show();
            return;
        }

        final String plainText = decrypt(cipherText, result.getCryptoObject().getCipher());
        plainTextView.setText(plainText);
        plainTextView.setEnabled(true);
    }

    private String decrypt(byte[] cipherText, Cipher cipher) {
        try {
            final byte[] plainText = cipher.doFinal(cipherText);

            return Base64.encodeToString(plainText, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Failed to encrypt plaintext", Toast.LENGTH_SHORT).show();
            return null;
        }
    }

    @Override
    public void onAuthenticationFailed() {
        Toast.makeText(this, "Authentication Failed", Toast.LENGTH_SHORT).show();
    }
}
