package uk.co.akm.imprintdemo.utils;

import android.hardware.fingerprint.FingerprintManager;

/**
 * android.hardware.fingerprint.FingerprintManager.AuthenticationCallback methods as an interface.
 * This interface must be implemented by the application components that will receive the result of
 * the fingerprint authentication process.
 *
 * Created by thanosmavroidis on 18/09/2016.
 */
public interface AuthenticationListener {
    /**
     * Called when an unrecoverable error has been encountered and the operation is complete.
     * No further callbacks will be made on this object.
     * @param errorCode An integer identifying the error message
     * @param errString A human-readable error string that can be shown in UI
     */
    void onAuthenticationError(int errorCode, CharSequence errString);

    /**
     * Called when a recoverable error has been encountered during authentication. The help
     * string is provided to give the user guidance for what went wrong, such as
     * "Sensor dirty, please clean it."
     * @param helpCode An integer identifying the error message
     * @param helpString A human-readable string that can be shown in UI
     */
    void onAuthenticationHelp(int helpCode, CharSequence helpString);

    /**
     * Called when a fingerprint is recognized.
     * @param result An object containing authentication-related data
     */
    void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result);

    /**
     * Called when a fingerprint is valid but not recognized.
     */
    void onAuthenticationFailed();
}
