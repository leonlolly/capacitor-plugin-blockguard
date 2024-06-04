package com.farsight.plugin;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class CustomSSLSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory delegate;

    public CustomSSLSocketFactory(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(s, host, port, autoClose);
        enableAllProtocolsAndCiphers(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        enableAllProtocolsAndCiphers(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port, localHost, localPort);
        enableAllProtocolsAndCiphers(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(host, port);
        enableAllProtocolsAndCiphers(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        SSLSocket socket = (SSLSocket) delegate.createSocket(address, port, localAddress, localPort);
        enableAllProtocolsAndCiphers(socket);
        return socket;
    }

    private void enableAllProtocolsAndCiphers(SSLSocket socket) {
        socket.setEnabledProtocols(socket.getSupportedProtocols());
        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
    }
}