package uk.co.akm.imprintdemo.server;


import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public final class InMemoryRemoteServer implements RemoteServer {
    private static final int MESSAGE_LENGTH = 256;

    private final Random random = new SecureRandom();
    private final Map<String, PublicKey> users = new HashMap<>();

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
    public byte[] getAuthenticationMessageToSign() {
        final byte[] message = new byte[MESSAGE_LENGTH];
        random.nextBytes(message);

        return message;
    }

    @Override
    public boolean authenticate(byte[] message, byte[] signature) throws ServerException {
        return false;
    }
}
