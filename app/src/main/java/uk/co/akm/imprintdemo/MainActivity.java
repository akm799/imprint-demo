package uk.co.akm.imprintdemo;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;
import uk.co.akm.imprintdemo.utils.FingerprintLocalAuthenticator;

/**
 * Initial activity that checks for fingerprint authentication ability and allows the user to go to
 * the fingerprint authentication screen if it is possible to do so. If not, then an error message
 * explaining the exact reason is displayed.
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final View authBtn = findViewById(R.id.auth_btn);
        final View authCryptoBtn = findViewById(R.id.auth_crypto_btn);
        final View authAsymmetricBtn = findViewById(R.id.auth_asymmetric_btn);
        final TextView state = (TextView)findViewById(R.id.compatibility_state);

        setInitialState(state, authBtn, authCryptoBtn, authAsymmetricBtn);
    }

    private void setInitialState(TextView state, View... authButtons) {
        final FingerprintLocalAuthenticator authenticator = FingerprintAuthenticatorFactory.localAuthenticatorInstance();
        switch (authenticator.canAuthenticate(this)) {
            case ERR_SDK_TOO_OLD:
                state.setText("Your software version does not support fingerprint authentication.");
                break;

            case ERR_NO_LOCK_SCREEN:
                state.setText("Lock screen security is not enabled.");
                break;

            case ERR_NO_PERMISSION:
                state.setText("Fingerprint authentication permission is not granted.");
                break;

            case ERR_NO_HARDWARE:
                state.setText("Your device does not support fingerprint authentication.");
                break;

            case ERR_NO_FINGERPRINTS:
                state.setText("The current user has not registered any fingerprints.");
                break;

            case OK:
                state.setText("Fingerprint authentication can proceed.");
                for (View btn : authButtons) {
                    btn.setEnabled(true);
                }
                break;

            default:
        }
    }

    public void onAuth(View view) {
        startActivity(new Intent(this, AuthActivity.class));
    }

    public void onAuthForCrypto(View view) {
        startActivity(new Intent(this, AuthCryptoActivity.class));
    }

    public void onAuthForAsymmetric(View view) {
        startActivity(new Intent(this, AuthAsymmetricActivity.class));
    }
}
