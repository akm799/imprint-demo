package uk.co.akm.imprintdemo;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.PublicKey;

import uk.co.akm.imprintdemo.server.InMemoryRemoteServer;
import uk.co.akm.imprintdemo.server.RemoteServer;
import uk.co.akm.imprintdemo.server.ServerException;
import uk.co.akm.imprintdemo.utils.AuthenticationListener;
import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

public class AuthAsymmetricActivity extends AppCompatActivity implements AuthenticationListener {
    private final RemoteServer server = new InMemoryRemoteServer();
    private final FingerprintLocalAuthenticator authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();

    private TextView authState;
    private EditText usernameText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_asymmetric);

        authState = (TextView) findViewById(R.id.auth_state);
        usernameText = (EditText) findViewById(R.id.username_text);
    }

    public void onRegister(View view) {
        final String username = usernameText.getText().toString().trim();
        if (username.isEmpty()) {
            Toast.makeText(this, "Please provide a username.", Toast.LENGTH_SHORT).show();
        } else {
            register(username);
        }
    }

    private void register(String username) {
        final PublicKey key = authenticator.generateKeyPairForRemoteAuthentication();

        try {
            server.registerPublicKey(username, key);
            Toast.makeText(this, "User '" + username + "' registered.", Toast.LENGTH_SHORT).show();
        } catch (ServerException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    public void onAuthenticate(View view) {
        final String username = usernameText.getText().toString().trim();
        if (username.isEmpty()) {
            Toast.makeText(this, "Please provide a username.", Toast.LENGTH_SHORT).show();
        } else {
            authState.setVisibility(View.VISIBLE);
            authenticate(username);
        }
    }

    private void authenticate(String username) {
        //TODO
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {

    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {

    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {

    }

    @Override
    public void onAuthenticationFailed() {

    }
}
