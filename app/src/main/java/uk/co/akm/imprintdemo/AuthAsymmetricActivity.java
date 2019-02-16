package uk.co.akm.imprintdemo;

import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

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

    private String username;

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
        this.username = username;
        authenticator.startAuthenticationForRemoteAuthentication(this, this);
    }

    // Authentication process cancelled manually by the user.
    public void onCancel(View view) {
        stopAuthentication();
        finish();
    }

    private void stopAuthentication() {
        authenticator.stopAuthentication();
        authState.setVisibility(View.INVISIBLE);
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        this.username = null;
        Toast.makeText(this, "Authentication Error\n" + errString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        this.username = null;
        Toast.makeText(this, "Authentication Help\n" + helpString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        stopAuthentication();

        final byte[] message = server.getAuthenticationMessageToSign();
        final byte[] signature = signMessage(result.getCryptoObject().getSignature(), message);

        if (signature == null) {
            Toast.makeText(this, "Could not sign server message.", Toast.LENGTH_LONG).show();
        } else {
            if (authenticatedWithServer(username, message, signature)) {
                Log.d(getClass().getSimpleName(), "User authenticated with remote server.");
                startActivity(new Intent(this, AfterAuthActivity.class)); // Go to the secure content.
                finish();
            } else {
                Toast.makeText(this, "Access Denied.", Toast.LENGTH_SHORT).show();
            }
        }

        this.username = null;
    }

    private boolean authenticatedWithServer(String username, byte[] message, byte[] signature) {
        try {
            return server.authenticate(username, message, signature);
        } catch (ServerException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    private byte[] signMessage(Signature signature, byte[] message) {
        try {
            signature.update(message);
            return signature.sign();
        } catch (SignatureException e) {
            return null;
        }
    }

    @Override
    public void onAuthenticationFailed() {
        this.username = null;
        Toast.makeText(this, "Authentication Failed", Toast.LENGTH_SHORT).show();
    }
}
