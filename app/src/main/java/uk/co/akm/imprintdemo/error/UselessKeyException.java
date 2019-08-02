package uk.co.akm.imprintdemo.error;

import android.security.keystore.KeyPermanentlyInvalidatedException;

/**
 *  * Created by Thanos Mavroidis on 02/08/2019.
 */
public final class UselessKeyException extends RuntimeException {

    public UselessKeyException(KeyPermanentlyInvalidatedException cause) {
        super(cause);
    }
}
