package uk.co.akm.imprintdemo;

import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import uk.co.akm.imprintdemo.utils.AuthenticationListener;
import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

/**
 * Fingerprint authentication activity. This activity performs fingerprint authentication
 * in order to grant (or not) the user access to the secure content.
 */
public class LocalAuthActivity extends AppCompatActivity implements AuthenticationListener {
    private TextView state;

    private final FingerprintLocalAuthenticator authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_local_auth);

        state = (TextView)findViewById(R.id.auth_state);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (!authenticator.startAuthentication(this, this)) {
            state.setText("Error: Cannot authenticate.");
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

        authenticator.stopAuthentication();
    }

    // Authentication process cancelled manually by the user.
    public void onCancel(View view) {
        authenticator.stopAuthentication();
        finish();
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        Toast.makeText(this, "Authentication Error\n" + errString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        Toast.makeText(this, "Authentication Help\n" + helpString, Toast.LENGTH_LONG).show();
    }

    // Authentication successful: Stop the authentication process and show the user the secure content.
    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        authenticator.stopAuthentication();
        startActivity(new Intent(this, AfterAuthActivity.class)); // Go to the secure content.
        finish();
    }

    @Override
    public void onAuthenticationFailed() {
        Toast.makeText(this, "Authentication Failed", Toast.LENGTH_SHORT).show();
    }
}
