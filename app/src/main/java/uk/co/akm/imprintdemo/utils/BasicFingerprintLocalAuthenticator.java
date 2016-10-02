package uk.co.akm.imprintdemo.utils;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.util.Log;

import javax.crypto.Cipher;

/**
 * Created by thanosmavroidis on 18/09/2016.
 */
public final class BasicFingerprintLocalAuthenticator extends FingerprintManager.AuthenticationCallback implements FingerprintLocalAuthenticator {
    private static final String TAG = BasicFingerprintLocalAuthenticator.class.getSimpleName();

    private AuthenticationListener listener;
    private CancellationSignal cancellationSignal;

    private final CipherBuilder cipherBuilder;

    BasicFingerprintLocalAuthenticator(String userKeyName) {
        cipherBuilder = new CipherBuilder(userKeyName);
    }

    public Compatibility canAuthenticate(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return Compatibility.ERR_SDK_TOO_OLD;
        }

        final KeyguardManager keyguardManager = (KeyguardManager)context.getSystemService(Context.KEYGUARD_SERVICE);
        if (!keyguardManager.isKeyguardSecure()) {
            return Compatibility.ERR_NO_LOCK_SCREEN;
        }

        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return Compatibility.ERR_NO_PERMISSION;
        }

        final FingerprintManager fingerprintManager = (FingerprintManager)context.getSystemService(Context.FINGERPRINT_SERVICE);
        if (!fingerprintManager.isHardwareDetected()) {
            return Compatibility.ERR_NO_HARDWARE;
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
            return Compatibility.ERR_NO_FINGERPRINTS;
        } else {
            return Compatibility.OK;
        }
    }

    @Override
    public boolean startAuthentication(Context context, AuthenticationListener listener) {
        return startAuthentication(context, null, listener);
    }

    @Override
    public boolean startAuthenticationForEncryption(Context context, AuthenticationListener listener) {
        return startAuthentication(context, new byte[0], listener);
    }

    @Override
    public boolean startAuthenticationForDecryption(Context context, byte[] iv, AuthenticationListener listener) {
        return startAuthentication(context, iv, listener);
    }

    // Initialization vector byte array is used to identify 3 cases:
    // null     : no encryption or decryption required.
    // empty    : encryption operation after authentication.
    // non-empty: decryption operation after authentication.
    private boolean startAuthentication(Context context, byte[] iv, AuthenticationListener listener) {
        // Checking permission again here because it might have changed since we last checked and to avoid Lint errors.
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }

        final FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
        final FingerprintManager.CryptoObject cryptoObject = (iv == null ? null : buildCryptoObject(iv));

        this.listener = listener;
        cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);

        Log.d(TAG, "Fingerprint authentication started ...");
        return true;
    }

    private FingerprintManager.CryptoObject buildCryptoObject(byte[] iv) {
        try {
            final Cipher cipher = (iv.length == 0 ? cipherBuilder.buildEncryptionCipher() : cipherBuilder.buildDecryptionCipher(iv));

            return new FingerprintManager.CryptoObject(cipher);
        } catch (Exception e) {
            Log.e(TAG, "Error while trying to build the crypto-object.", e);
            return null;
        }
    }

    @Override
    public void stopAuthentication() {
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
            cancellationSignal = null;

            listener = null;
            Log.d(TAG, "Fingerprint authentication stopped.");
        }
    }

    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        if (listener != null) {
            listener.onAuthenticationError(errorCode, errString);
        }
    }

    @Override
    public void onAuthenticationFailed() {
        if (listener != null) {
            listener.onAuthenticationFailed();
        }
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        if (listener != null) {
            listener.onAuthenticationHelp(helpCode, helpString);
        }
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        if (listener != null) {
            listener.onAuthenticationSucceeded(result);
        }
    }
}
