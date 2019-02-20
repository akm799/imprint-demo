package uk.co.akm.imprintdemo.key;

import android.util.Base64;
import android.util.Log;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * https://stackoverflow.com/questions/45968285/reconstructing-private-and-public-keys-with-bouncy-castle
 */
final class X509KeySerializer implements KeySerializer {
    static final String X_509 = "X.509";

    private final String algorithm;

    X509KeySerializer(String algorithm) {
        this.algorithm = algorithm;
    }

    public String serialize(PublicKey key) throws KeySerializationException {
        if (!algorithm.equals(key.getAlgorithm())) {
            throw new KeySerializationException("Incompatible public key algorithms. The input key algorithm is " + key.getAlgorithm() + " but this key serializer supports only the " + algorithm + "algorithm.");
        }

        if (!X_509.equals(key.getFormat())) {
            throw new KeySerializationException("Unsupported " + algorithm + " public key encoding format: " + key.getFormat() + ". Only the " + X_509 + " encoding format is supported.");
        }

        return Base64.encodeToString(key.getEncoded(), Base64.DEFAULT);
    }

    public PublicKey deserialize(String encoded) throws KeySerializationException {
        try {
            final byte[] keyBytes = Base64.decode(encoded, Base64.DEFAULT);
            final KeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Key deserialization error.", e);
            throw new KeySerializationException("Key deserialization error.", e);
        }
    }
}
