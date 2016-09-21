package uk.co.akm.imprintdemo.utils;

import android.util.Log;

/**
 * This factory provides the only way to get #FingerprintLocalAuthenticator instances.
 * Before invoking the #localAuthenticatorInstance() method, that will provide such instances, the
 * #init(String) method must be invoked with a non-null, non-empty and non-blank string argument.
 */
public final class FingerprintAuthenticatorFactory {
    private static final String TAG = FingerprintAuthenticatorFactory.class.getSimpleName();

    private static String APP_KEY_NAME;

    /**
     * Initializes this factory with the key name that will be used to store the secret key serving
     * to handle the encryption of the fingerprint data. This key name must be unique per application.
     * This method can be called when your application initializes (e.g. in the onCreate() method of
     * your Application class).
     *
     * @param appKeyName he key name that will be used to store the secret key serving to handle the
     * encryption of the fingerprint data
     */
    public static void init(String appKeyName) {
        if (appKeyName != null && appKeyName.trim().length() > 0) {
            APP_KEY_NAME = appKeyName;
        } else {
            Log.e(TAG, "Trying to call the FingerprintAuthenticatorFactory.init(String) method with a null or empty/blank string argument.");
        }
    }

    /**
     * Returns a #FingerprintLocalAuthenticator instance or null if the #init(String) method has not
     * been previously invoked.
     *
     * @return a #FingerprintLocalAuthenticator instance or null if the #init(String) method has not
     * been previously invoked
     */
    public static FingerprintLocalAuthenticator localAuthenticatorInstance() {
        if (APP_KEY_NAME == null) {
            Log.e(TAG, "Trying to get a " + FingerprintLocalAuthenticator.class.getName() + " instance before calling the FingerprintAuthenticatorFactory.init(String) method.");
            return null;
        }

        return new BasicFingerprintLocalAuthenticator(APP_KEY_NAME);
    }

    private FingerprintAuthenticatorFactory() {}
}
