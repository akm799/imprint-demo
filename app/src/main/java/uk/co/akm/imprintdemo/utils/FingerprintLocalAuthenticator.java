package uk.co.akm.imprintdemo.utils;

import android.content.Context;

/**
 * This interface contains all methods required by the application to use local fingerprint
 * authentication.
 *
 * Created by thanosmavroidis on 18/09/2016.
 */
public interface FingerprintLocalAuthenticator {
    /**
     * Result returned by the method that checks if fingerprint authentication is possible (#canAuthenticate(Context)).
     */
    enum Compatibility {
        ERR_SDK_TOO_OLD,
        ERR_NO_LOCK_SCREEN,
        ERR_NO_PERMISSION,
        ERR_NO_HARDWARE,
        ERR_NO_FINGERPRINTS,
        OK
    }

    /**
     * Returns #Compatibility.OK if fingerprint authentication is possible or another value which
     * points to the exact reason why it is not possible.
     *
     * @param context the context used to obtain the necessary services
     * @return #Compatibility.OK if fingerprint authentication is possible or another value which
     * points to the exact reason why it is not possible
     */
    Compatibility canAuthenticate(Context context);

    /**
     * Starts the fingerprint authentication process and returns true or just returns false otherwise.
     * This method will just authenticate without providing any subsequent cryptography options.
     *
     * @param context the context required to obtain and use the necessary services
     * @param listener the listener that will be informed of the authentication process result
     * @return true if the authentication process was started or false otherwise
     */
    boolean startAuthentication(Context context, AuthenticationListener listener);

    /**
     * Starts the fingerprint authentication process, with a subsequent encryption option, and
     * returns true or just returns false otherwise. If the fingerprint authentication succeeds
     * then calling the #FingerprintManager.AuthenticationResult.getCryptoObject().getCipher()
     * on the returned result (from the callback) will return a #Cipher instance that is set for
     * encryption.
     *
     * @param context the context required to obtain and use the necessary services
     * @param listener the listener that will be informed of the authentication process result
     * @return true if the authentication process was started or false otherwise
     */
    boolean startAuthenticationForEncryption(Context context, AuthenticationListener listener);

    /**
     * Starts the fingerprint authentication process, with a subsequent decryption option, and
     * returns true or just returns false otherwise. If the fingerprint authentication succeeds
     * then calling the #FingerprintManager.AuthenticationResult.getCryptoObject().getCipher()
     * on the returned result (from the callback) will return a #Cipher instance that is set for
     * decryption.
     *
     * @param context the context required to obtain and use the necessary services
     * @param iv the initialization vector used when encrypting the data that we wish to decrypt
     * @param listener the listener that will be informed of the authentication process result
     * @return true if the authentication process was started or false otherwise
     */
    boolean startAuthenticationForDecryption(Context context, byte[] iv, AuthenticationListener listener);

    /**
     * Starts the fingerprint authentication process, with a subsequent option of signing a message
     * for the purpose of authenticating with a remote server. If the fingerprint authentication succeeds
     * then calling the #FingerprintManager.AuthenticationResult.getCryptoObject().getSignature() on
     * the returned result (from the callback) will return a #Signature instance that is can be used
     * to sign a message for the purpose of authenticating with a remote server.
     *
     * @param context the context required to obtain and use the necessary services
     * @param listener the listener that will be informed of the authentication process result
     * @return true if the authentication process was started or false otherwise
     */
    boolean startAuthenticationForRemoteAuthentication(Context context, AuthenticationListener listener);

    /**
     * Stops the (already running) fingerprint authetication process. Usually called, from the
     * onPause() method of the caller activity or fragment or when the process is cancelled by
     * the user.
     */
    void stopAuthentication();
}
