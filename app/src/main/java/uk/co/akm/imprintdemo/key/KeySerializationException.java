package uk.co.akm.imprintdemo.key;


import java.util.Iterator;

final class KeySerializationException extends RuntimeException {

    static KeySerializationException unsupportedAlgorithmInstance(String algorithm) {
        final String message = "Unsupported public key algorithm '" + algorithm + "'. The only algorithms supported are: " + supportedAlgorithms() + ".";

        return new KeySerializationException(message);
    }

    private static String supportedAlgorithms() {
        final StringBuilder sb = new StringBuilder();
        final Iterator<String> algorithms = KeySerializerConstants.KEY_ALGORITHMS.iterator();
        while (algorithms.hasNext()) {
            sb.append(algorithms.next());
            if (algorithms.hasNext()) {
                sb.append(", ");
            }
        }

        return sb.toString();
    }

    KeySerializationException(String message) {
        super(message);
    }

    KeySerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
