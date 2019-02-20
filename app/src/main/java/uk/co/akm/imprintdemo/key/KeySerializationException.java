package uk.co.akm.imprintdemo.key;


final class KeySerializationException extends RuntimeException {

    KeySerializationException(String message) {
        super(message);
    }

    KeySerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
