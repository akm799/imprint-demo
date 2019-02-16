package uk.co.akm.imprintdemo.key;

import java.security.PublicKey;

public interface KeySerializer {

    String serialize(PublicKey key) throws KeySerializationException;

    PublicKey deserialize(String serializedKey) throws KeySerializationException;
}
