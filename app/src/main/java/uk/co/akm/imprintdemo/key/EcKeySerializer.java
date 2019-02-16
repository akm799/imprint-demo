package uk.co.akm.imprintdemo.key;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

final class EcKeySerializer implements KeySerializer, KeySerializerConstants {

    EcKeySerializer() {}

    @Override
    public String serialize(PublicKey key) throws KeySerializationException {
        if (key instanceof ECPublicKey) {
            final ECPublicKey ecKey = (ECPublicKey) key;
            return (ecKey.getW().getAffineX().toString() + SEPARATOR + ecKey.getW().getAffineY().toString());
        } else {
            throw new KeySerializationException("Can only serialize instances of " +  ECPublicKey.class.getName() +".");
        }
    }

    @Override
    public PublicKey deserialize(final String serializedKey) throws KeySerializationException {
        final KeyComponents ecKeyParts = new KeyComponents(serializedKey);
        final ECPoint ecPoint = new ECPoint(ecKeyParts.first, ecKeyParts.second);

        return new ECPublicKey() {

            @Override
            public ECPoint getW() {
                return ecPoint;
            }

            @Override
            public String getAlgorithm() {
                return KEY_ALGORITHM_EC;
            }

            @Override
            public String getFormat() {
                return "CUSTOM"; //TODO
            }

            @Override
            public byte[] getEncoded() {
                return serializedKey.getBytes(); //TODO
            }

            @Override
            public ECParameterSpec getParams() {
                return null; //TODO
            }
        };
    }
}
