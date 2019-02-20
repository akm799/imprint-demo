package uk.co.akm.imprintdemo.server;


public interface RemoteServer {

    void registerPublicKey(String username, String publicKeyData) throws ServerException;

    byte[] getAuthenticationMessageToSign(String username);

    boolean authenticate(String username, byte[] message, byte[] signature) throws ServerException;
}
