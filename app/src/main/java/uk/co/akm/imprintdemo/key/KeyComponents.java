package uk.co.akm.imprintdemo.key;


final class KeyComponents implements KeySerializerConstants {
    final String algorithm;
    final String format;
    final String data;

    KeyComponents(String serializedKey) {
        try {
            final int sep1 = serializedKey.indexOf(SEPARATOR, 0);
            final int sep2 = serializedKey.indexOf(SEPARATOR, sep1 + 1);

            algorithm = serializedKey.substring(0, sep1);
            format = serializedKey.substring(sep1 + 1, sep2);
            data = serializedKey.substring(sep2 + 1);

            if (!KEY_ALGORITHMS.contains(algorithm)) {
                throw new KeySerializationException("Unsupported public key algorithm: '" + algorithm + "'.");
            }
        } catch (Exception e) {
            throw new KeySerializationException("Invalid serialized public key format.", e);
        }
    }
}
