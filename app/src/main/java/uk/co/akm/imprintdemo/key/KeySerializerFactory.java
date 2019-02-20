package uk.co.akm.imprintdemo.key;


public class KeySerializerFactory {

    public static final KeySerializer instance() {
        return new KeySerializerImpl();
    }

    private KeySerializerFactory() {}
}
