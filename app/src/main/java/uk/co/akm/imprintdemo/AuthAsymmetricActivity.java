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

import uk.co.akm.imprintdemo.error.UselessKeyException;
import uk.co.akm.imprintdemo.key.KeySerializationException;
import uk.co.akm.imprintdemo.key.KeySerializer;
import uk.co.akm.imprintdemo.key.KeySerializerFactory;
import uk.co.akm.imprintdemo.server.InMemoryRemoteServer;
import uk.co.akm.imprintdemo.server.RemoteServer;
import uk.co.akm.imprintdemo.server.ServerException;
import uk.co.akm.imprintdemo.utils.AuthenticationListener;
import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

/**
 * Activity for registering users that will use asymmetric encryption to log in as well as for logging
 * in registered users (using the aforementioned asymmetric encryption).
 *
 * Created by Thanos Mavroidis.
 */
public class AuthAsymmetricActivity extends AppCompatActivity implements AuthenticationListener {
    private final RemoteServer server = new InMemoryRemoteServer();
    private final KeySerializer keySerializer = KeySerializerFactory.instance();
    private final FingerprintLocalAuthenticator authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();

    private EditText usernameRegistrationText;
    private EditText usernameAuthenticationText;

    private TextView authState;
    private View authAction;
    private View authCancelAction;
    private View fingerprintImageView;

    private String username;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_asymmetric);

        usernameRegistrationText = (EditText) findViewById(R.id.auth_asymmetric_registration_username);
        usernameAuthenticationText = (EditText) findViewById(R.id.auth_asymmetric_authentication_username);

        authState = (TextView) findViewById(R.id.auth_asymmetric_auth_prompt);
        authAction = findViewById(R.id.auth_asymmetric_authentication_btn);
        authCancelAction = findViewById(R.id.auth_asymmetric_authentication_cancel_btn);
        fingerprintImageView = findViewById(R.id.auth_asymmetric_fingerprint_image);
    }

    public void onReset(View view) {
        authenticator.reset();
        Toast.makeText(this, "Reset complete.", Toast.LENGTH_SHORT).show();
    }

    public void onRegister(View view) {
        final String username = usernameRegistrationText.getText().toString().trim();
        if (username.isEmpty()) {
            Toast.makeText(this, "Please provide a username.", Toast.LENGTH_SHORT).show();
        } else {
            register(username);
        }
    }

    private void register(String username) {
        final String serializedKey = generateKeyPairAndSerializePublicKey();

        if (serializedKey == null) {
            Toast.makeText(this, "Key generation or serialization error.", Toast.LENGTH_SHORT).show();
        } else {
            try {
                server.registerPublicKey(username, serializedKey);
                Toast.makeText(this, "User '" + username + "' registered successfully.", Toast.LENGTH_SHORT).show();
            } catch (ServerException e) {
                Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    private String generateKeyPairAndSerializePublicKey() {
        try {
            final PublicKey key = authenticator.generateKeyPairForRemoteAuthentication();

            return keySerializer.serialize(key);
        } catch (KeySerializationException kse) {
            Log.e(getClass().getSimpleName(), "Key serialization error.", kse);
            return null;
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Key generation error.", e);
            return null;
        }
    }

    public void onAuthenticate(View view) {
        final String username = usernameAuthenticationText.getText().toString().trim();
        if (username.isEmpty()) {
            Toast.makeText(this, "Please provide a username.", Toast.LENGTH_SHORT).show();
        } else {
            setScreenToAuthenticationMode();
            authenticate(username);
        }
    }

    private void setScreenToAuthenticationMode() {
        authAction.setVisibility(View.INVISIBLE);

        authState.setVisibility(View.VISIBLE);
        fingerprintImageView.setVisibility(View.VISIBLE);
        authCancelAction.setVisibility(View.VISIBLE);
    }

    private void authenticate(String username) {
        this.username = username;

        try {
            authenticator.startAuthenticationForRemoteAuthentication(this, this);
        } catch (UselessKeyException uke) {
            Toast.makeText(this, "Please reset and start again.", Toast.LENGTH_SHORT).show();
        }
    }

    // Authentication process cancelled manually by the user.
    public void onCancel(View view) {
        stopAuthentication();
    }

    @Override
    public void onBackPressed() {
        try {
            authenticator.stopAuthentication();
        } finally {
            super.onBackPressed();
        }
    }

    private void stopAuthentication() {
        authenticator.stopAuthentication();
        onAuthenticationStopped();
    }

    private void onAuthenticationStopped() {
        username = null;
        setScreenOffAuthenticationMode();
    }

    private void setScreenOffAuthenticationMode() {
        authAction.setVisibility(View.VISIBLE);

        authState.setVisibility(View.INVISIBLE);
        fingerprintImageView.setVisibility(View.INVISIBLE);
        authCancelAction.setVisibility(View.INVISIBLE);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        authState.setVisibility(View.INVISIBLE);
        authenticatedWithServer(result.getCryptoObject().getSignature());
    }

    private void authenticatedWithServer(Signature signatureFunction) {
        final byte[] message = getAuthenticationMessageFromServer(username);
        if (message != null) {
            authenticatedWithServer(username, message, signatureFunction);
        } else {
            stopAuthentication();
        }
    }

    private byte[] getAuthenticationMessageFromServer(String username) {
        try {
            return server.getAuthenticationMessageToSign(username);
        } catch (ServerException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
            return null;
        }
    }

    private void authenticatedWithServer(String username, byte[] message, Signature signatureFunction) {
        final byte[] signature = signMessage(signatureFunction, message);

        if (signature == null) {
            Toast.makeText(this, "Could not sign server message.", Toast.LENGTH_LONG).show();
            stopAuthentication();
        } else {
            authenticatedWithServer(username, message, signature);
        }
    }

    private byte[] signMessage(Signature signatureFunction, byte[] message) {
        try {
            signatureFunction.update(message);
            return signatureFunction.sign();
        } catch (SignatureException e) {
            Log.e(getClass().getSimpleName(), "Signature Error", e);
            return null;
        }
    }

    private void authenticatedWithServer(String username, byte[] message, byte[] signature) {
        try {
            if (server.authenticate(username, message, signature)) {
                onRemoteAuthenticationComplete();
            } else {
                this.username = null;
                Toast.makeText(this, "Access Denied.", Toast.LENGTH_SHORT).show();
            }
        } catch (ServerException e) {
            this.username = null;
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    private void onRemoteAuthenticationComplete() {
        Log.d(getClass().getSimpleName(), "User authenticated with remote server.");
        AfterAuthActivity.startAfterAuthActivity(this, username); // Go to the secure content.
        username = null;
        finish();
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        onAuthenticationStopped();
        Toast.makeText(this, "Authentication Error\n" + errString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        onAuthenticationStopped();
        Toast.makeText(this, "Authentication Help\n" + helpString, Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationFailed() {
        stopAuthentication(); // After failure we need to cancel the authentication process completely, because our (private) key operation authorisation was only for this failed effort. For the next try we need a new authorisation.
        Toast.makeText(this, "Authentication Failed", Toast.LENGTH_SHORT).show();
    }
}
