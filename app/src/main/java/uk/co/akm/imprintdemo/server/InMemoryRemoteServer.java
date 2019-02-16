package uk.co.akm.imprintdemo.server;


import android.util.Log;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import uk.co.akm.imprintdemo.key.KeySerializer;
import uk.co.akm.imprintdemo.key.KeySerializerFactory;

public final class InMemoryRemoteServer implements RemoteServer {
    private static final int MESSAGE_LENGTH = 512;
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    private final KeySerializer keySerializer = KeySerializerFactory.instance();

    private final Random random = new SecureRandom();
    private final Map<String, PublicKey> users = new HashMap<>();
    private final Map<String, byte[]> messages = new HashMap<>();

    @Override
    public void registerPublicKey(String username, String publicKeyData) throws ServerException {
        final PublicKey publicKey = keySerializer.deserialize(publicKeyData);
        registerPublicKey(username, publicKey);
    }

    @Override
    public void registerPublicKey(String username, PublicKey publicKey) throws ServerException {
        if (username == null || username.trim().isEmpty()) {
            throw new ServerException("Missing username.");
        }

        if (users.containsKey(username)) {
            throw new ServerException("User '" + username + "' is already registered.");
        }

        users.put(username, publicKey);
    }

    @Override
    public byte[] getAuthenticationMessageToSign(String username) {
        if (!users.containsKey(username)) {
            throw new ServerException("User '" + username + "' has not registered.");
        }

        final byte[] message = new byte[MESSAGE_LENGTH];
        random.nextBytes(message);

        messages.put(username, message);

        return message;
    }

    @Override
    public boolean authenticate(String username, byte[] message, byte[] signature) throws ServerException {
        checkArguments(username, message, signature);

        final byte[] expectedMessage = messages.get(username);
        if (notExpectedMessage(expectedMessage, message)) {
            return false;
        }

        final PublicKey key = users.get(username);
        if (key == null) {
            throw new ServerException("User '" + username + "' has not registered.");
        }

        return verifySignature(message, key, signature);
    }

    private void checkArguments(String username, byte[] message, byte[] signature) throws ServerException {
        if (username == null || username.trim().isEmpty()) {
            throw new ServerException("Missing username.");
        }

        if (message == null || message.length == 0) {
            throw new ServerException("Missing authentication message.");
        }

        if (signature == null || signature.length == 0) {
            throw new ServerException("Missing authentication signature.");
        }
    }

    private boolean notExpectedMessage(byte[] expectedMessage, byte[] message) {
        if (expectedMessage == null) {
            return true;
        }

        if (expectedMessage.length != message.length) {
            return true;
        }

        for (int i=0 ; i<message.length ; i++) {
            if (expectedMessage[i] != message[i]) {
                return true;
            }
        }

        return false;
    }

    private boolean verifySignature(byte[] message, PublicKey key, byte[] signature) throws ServerException {
        try {
            final Signature verificationFunction = Signature.getInstance(SIGNATURE_ALGORITHM);

            verificationFunction.initVerify(key);
            verificationFunction.update(message);

            return verificationFunction.verify(signature);
        } catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Signature versification error.", e);
            throw new ServerException("Signature versification error.");
        }
    }
}
