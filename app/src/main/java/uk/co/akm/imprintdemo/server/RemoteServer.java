package uk.co.akm.imprintdemo.server;

import java.security.PublicKey;

public interface RemoteServer {

    void registerPublicKey(String username, PublicKey publicKey) throws ServerException;

    byte[] getAuthenticationMessageToSign();

    boolean authenticate(byte[] message, byte[] signature) throws ServerException;
}