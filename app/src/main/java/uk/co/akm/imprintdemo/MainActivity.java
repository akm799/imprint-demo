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

        final View localAuthBtn = findViewById(R.id.local_auth_btn);
        final TextView state = (TextView)findViewById(R.id.compatibility_state);

        setInitialState(state, localAuthBtn);
    }

    private void setInitialState(TextView state, View localAuthButton) {
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
                localAuthButton.setEnabled(true);
                break;

            default:
        }
    }

    public void onLocalAuth(View view) {
        startActivity(new Intent(this, LocalAuthActivity.class));
    }
}
