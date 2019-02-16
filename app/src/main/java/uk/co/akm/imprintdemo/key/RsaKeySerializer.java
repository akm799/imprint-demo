package uk.co.akm.imprintdemo.key;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * https://stackoverflow.com/questions/21606428/serialize-and-deserialize-an-rsa-public-key
 */
final class RsaKeySerializer implements KeySerializer, KeySerializerConstants {

    RsaKeySerializer() {}

    @Override
    public String serialize(PublicKey key) throws KeySerializationException {
        if (key instanceof RSAPublicKey) {
            final RSAPublicKey rsaKey = (RSAPublicKey) key;
            return (rsaKey.getModulus().toString() + SEPARATOR + rsaKey.getPublicExponent().toString());
        } else {
            throw new KeySerializationException("Can only serialize instances of " +  RSAPublicKey.class.getName() +".");
        }
    }

    @Override
    public PublicKey deserialize(String serializedKey) throws KeySerializationException {
        final KeyComponents rsaKeyParts = new KeyComponents(serializedKey);
        final RSAPublicKeySpec rsaKeySpec = new RSAPublicKeySpec(rsaKeyParts.first, rsaKeyParts.second);

        try {
            return KeyFactory.getInstance(KEY_ALGORITHM_RSA).generatePublic(rsaKeySpec);
        } catch (NoSuchAlgorithmException nsae) {
            throw new KeySerializationException("Unsupported " + KEY_ALGORITHM_RSA + " algorithm.");
        } catch (InvalidKeySpecException ikse) {
            throw new KeySerializationException("Unable to generate publis RSA key from input modulus and public exponent numbers.");
        }
    }
}
