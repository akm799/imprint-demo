package uk.co.akm.imprintdemo;

import android.content.Context;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

/**
 * This activity simulates the app content after successful authentication. This content is only
 * available to authenticated users. If the fingerprint authentication involved cryptographic
 * operations, then the result of such an operation is displayed.
 */
public class AfterAuthActivity extends AppCompatActivity {
    private static final String CRYPTO_TEXT_KEY = "crypto.result.text.key";
    private static final String CRYPTO_ENCRYPT_FUNCTION_KEY = "crypto.result.function.key";

    private static final String AUTHORISED_USERNAME_KEY = "authorised.username.key";

    static void startAfterAuthActivity(Context context, String username) {
        final Intent intent = new Intent(context, AfterAuthActivity.class);
        intent.putExtra(AUTHORISED_USERNAME_KEY, username);

        context.startActivity(intent);
    }

    static void startAfterAuthActivity(Context context, boolean encrypted, String cryptoText) {
        final Intent intent = new Intent(context, AfterAuthActivity.class);
        intent.putExtra(CRYPTO_ENCRYPT_FUNCTION_KEY, encrypted);
        intent.putExtra(CRYPTO_TEXT_KEY, cryptoText);

        context.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_after_auth);

        final Intent intent = getIntent();
        if (hasMessage(intent)) {
            showMessage(intent);
        } else if (hasUsername(intent)) {
            showWelcomeMessage(intent);
        }
    }

    private boolean hasMessage(Intent intent) {
        return (intent.hasExtra(CRYPTO_ENCRYPT_FUNCTION_KEY) && intent.hasExtra(CRYPTO_TEXT_KEY));
    }

    private void showMessage(Intent intent) {
        final boolean encrypted = intent.getBooleanExtra(CRYPTO_ENCRYPT_FUNCTION_KEY, false);
        final String cryptoText = intent.getStringExtra(CRYPTO_TEXT_KEY);
        if (cryptoText != null) {
            showMessage(encrypted, cryptoText);
        }
    }

    private void showMessage(boolean encrypted, String cryptoText) {
        final TextView authResult = (TextView)findViewById(R.id.auth_result);
        if (encrypted) {
            authResult.setText("Authentication successful.\n\nYour text was encrypted and stored as:\n\n" + cryptoText);
        } else {
            authResult.setText("Authentication successful.\n\nYour stored, encrypted text was decrypted as:\n\n" + cryptoText);
        }
    }

    private boolean hasUsername(Intent intent) {
        return intent.hasExtra(AUTHORISED_USERNAME_KEY);
    }

    private void showWelcomeMessage(Intent intent) {
        final String username = intent.getStringExtra(AUTHORISED_USERNAME_KEY);
        final TextView authResult = (TextView)findViewById(R.id.auth_result);
        authResult.setText("Authentication successful.\n\nWelcome " + username + "!");
    }
}
