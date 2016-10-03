package uk.co.akm.imprintdemo;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import javax.crypto.Cipher;

import uk.co.akm.imprintdemo.utils.AuthenticationListener;
import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

/**
 * Demo activity of fingerptint authentication with a subsequent cryptographic operation.
 *
 * If the user enters some plain-text in the edit text and chooses the 'encrypt' option, then,
 * after successful fingerprint authorisation, the entered plain-text will be encrypted and
 * stored in the shared preferences.
 *
 * If an encrypted plain-text has already been stored and the user chooses the decrypt option,
 * then, after successful fingerprint authorisation, the stored cipher-text will be decrypted
 * and displayed.
 */
public class AuthCryptoActivity extends AppCompatActivity implements AuthenticationListener {
    private static final String PREFS_NAME = "uk.co.akm.imprintdemo.prefs";
    private static final String CIPHER_TEXT_KEY = "cipher.text.store.key";

    private TextView state;
    private TextView cipherTextView;
    private EditText plainTextView;

    private CryptoString cryptoString;

    private FingerprintLocalAuthenticator authenticator;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_crypto);

        state = (TextView)findViewById(R.id.auth_state);
        cipherTextView = (TextView)findViewById(R.id.cipher_text);
        plainTextView = (EditText) findViewById(R.id.plain_text);
    }

    @Override
    protected void onResume() {
        super.onResume();

        cryptoString = readCipherText();
        if (cryptoString != null) {
            allowDecryptOption(cryptoString.getCipherText());
        }
    }

    private CryptoString readCipherText() {
        final SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        if (prefs.contains(CIPHER_TEXT_KEY)) {
            return new CryptoString(prefs, CIPHER_TEXT_KEY);
        } else {
            return null;
        }
    }

    private void allowDecryptOption(String cipherTextStr) {
        cipherTextView.setText(cipherTextStr);
        cipherTextView.setVisibility(View.VISIBLE);
        findViewById(R.id.decrypt_btn).setVisibility(View.VISIBLE);
    }

    @Override
    protected void onPause() {
        super.onPause();

        stopAuthentication();
        cryptoString = null;
    }

    // Authentication process cancelled manually by the user.
    public void onCancel(View view) {
        stopAuthentication();
        finish();
    }

    private void stopAuthentication() {
        if (authenticator != null) {
            authenticator.stopAuthentication();
            authenticator = null;
        }
    }

    // The user pressed the encrypt button (after hopefully, entering something to be encrypted).
    public void onEncrypt(View view) {
        final String plainText = plainTextView.getText().toString().trim();
        if (plainText.isEmpty()) {
            Toast.makeText(this, "Nothing to encrypt", Toast.LENGTH_SHORT).show();
        } else {
            cryptoString = new CryptoString(plainText);

            plainTextView.setEnabled(false);
            state.setText("Touch fingerprint sensor to encrypt");

            // Start listening for fingerprint authentication so then we can encrypt.
            authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();
            authenticator.startAuthenticationForEncryption(this, this);
        }
    }

    // The user pressed the decrypt button.
    public void onDecrypt(View view) {
        plainTextView.setText("");
        plainTextView.setEnabled(false);
        state.setText("Touch fingerprint sensor to decrypt");

        // Start listening for fingerprint authentication so then we can decrypt.
        authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();
        authenticator.startAuthenticationForDecryption(this, cryptoString.getIv(), this);
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
        if (cryptoString == null) {
            return;
        }

        final Cipher cipher = result.getCryptoObject().getCipher();
        if (cryptoString.readyToEncrypt()) { // fingerprint authenticated after ENCRYPT button was pressed.
            encrypt(cipher);
        } else { // fingerprint authenticated after DECRYPT button was pressed.
            decrypt(cipher);
        }
    }

    private void encrypt(Cipher cipher) {
        final SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        cryptoString.encrypt(cipher);
        cryptoString.store(prefs, CIPHER_TEXT_KEY);

        AfterAuthActivity.startAfterAuthActivity(this, true, cryptoString.getCipherText());
        finish();
    }

    private void decrypt(Cipher cipher) {
        cryptoString.decrypt(cipher);

        AfterAuthActivity.startAfterAuthActivity(this, false, cryptoString.toString());
        finish();
    }

    @Override
    public void onAuthenticationFailed() {
        Toast.makeText(this, "Authentication Failed", Toast.LENGTH_SHORT).show();
    }
}
