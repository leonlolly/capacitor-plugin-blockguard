package com.farsight.plugin;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

public class CustomKeyManager implements X509KeyManager {

    private final X509Certificate clientCert;
    private final PrivateKey clientPrivateKey;

    private final String clientAliases;

    public CustomKeyManager(X509Certificate clientCert, PrivateKey clientPrivateKey, String clientAliases) {
        this.clientCert = clientCert;
        this.clientPrivateKey = clientPrivateKey;
        this.clientAliases = clientAliases;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers){
        return new String[] {this.clientAliases};
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return this.clientAliases;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (alias.equals("client")) {
            return new X509Certificate[] {clientCert};
        } else {
            throw new IllegalStateException("Invalid alias: " + alias);
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (alias.equals("client")) {
            return clientPrivateKey;
        } else {
            throw new IllegalStateException("Invalid alias: " + alias);
        }
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        // Not applicable for client-side mTLS (can be empty)
        return new String[0];
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        // Not applicable for client-side mTLS (can be empty)
        return null;
    }
}