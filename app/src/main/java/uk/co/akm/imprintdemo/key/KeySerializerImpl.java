package uk.co.akm.imprintdemo.key;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;


final class KeySerializerImpl implements KeySerializer, KeySerializerConstants {
    private final Map<String, KeySerializer> keySerializers = new HashMap(2);

    KeySerializerImpl() {
        keySerializers.put(KEY_ALGORITHM_EC, new X509KeySerializer(KEY_ALGORITHM_EC));
        keySerializers.put(KEY_ALGORITHM_RSA, new X509KeySerializer(KEY_ALGORITHM_RSA));
    }

    @Override
    public String serialize(PublicKey key) throws KeySerializationException {
        final String algorithm = key.getAlgorithm();
        final String format = key.getFormat();
        checkAlgorithmAndFormat(algorithm, format);

        final String data = keySerializers.get(algorithm).serialize(key);

        return (algorithm + SEPARATOR + format + SEPARATOR + data);
    }

    @Override
    public PublicKey deserialize(String serializedKey) throws KeySerializationException {
        final KeyComponents keyComponents = new KeyComponents(serializedKey);
        checkAlgorithmAndFormat(keyComponents.algorithm, keyComponents.format);

        return keySerializers.get(keyComponents.algorithm).deserialize(keyComponents.data);
    }

    private void checkAlgorithmAndFormat(String algorithm, String format) {
        if (!keySerializers.containsKey(algorithm)) {
            throw new KeySerializationException("Unsupported public key algorithm " + algorithm + ".");
        }

        if (!X509KeySerializer.X_509.equals(format)) {
            throw new KeySerializationException("Unsupported public key encoding format " + format + ". Only the " + X509KeySerializer.X_509 + " format is supported.");
        }
    }
}
