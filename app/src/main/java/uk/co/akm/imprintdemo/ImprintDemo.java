package uk.co.akm.imprintdemo;

import android.app.Application;
import android.util.Log;

import uk.co.akm.imprintdemo.utils.FingerprintAuthenticatorFactory;

/**
 * Application initialization where the fingerprint authentication API (actually just its factory
 * class) is initialized.
 *
 * Created by thanosmavroidis on 19/09/2016.
 */
public class ImprintDemo extends Application {
    private static final String FINGERPRINT_AUTH_KEY_NAME = "imprint.demo.secret.key";

    @Override
    public void onCreate() {
        super.onCreate();

        FingerprintAuthenticatorFactory.init(FINGERPRINT_AUTH_KEY_NAME);
        Log.d(getClass().getSimpleName(), "FingerprintAuthenticatorFactory initialized.");
    }
}
