package com.github.tvbox.osc.util;

import android.os.Build;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class TLSSocketFactory extends SSLSocketFactory {
    private final SSLSocketFactory delegate;
    private String TLS_VERSIONS[] = { "TLSv1.1", "TLSv1.2", "TLSv1.3" };
    private String TLS_CIPHER_SUITES[] = null;

    public TLSSocketFactory(SSLSocketFactory base) {
        this.delegate = base;

        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1) {
            // Disable ECDSA cipher suites on Android 4.0.x, which do not support them.
            // No way to set siguature schemes, so we have to disable TLS v1.3.

            List<String> cipherSuites = new ArrayList<>();
            for (String suite : delegate.getDefaultCipherSuites()) {
                if (suite.toUpperCase().contains("RSA")) {
                    cipherSuites.add(suite);
                }
            }
            this.TLS_VERSIONS = new String[] { "TLSv1.1", "TLSv1.2" };
            this.TLS_CIPHER_SUITES = cipherSuites.toArray(new String[cipherSuites.size()]);
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        if (TLS_CIPHER_SUITES != null) {
            return TLS_CIPHER_SUITES;
        }
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return patch(delegate.createSocket(s, host, port, autoClose));
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return patch(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return patch(delegate.createSocket(host, port, localHost, localPort));
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return patch(delegate.createSocket(host, port));
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return patch(delegate.createSocket(address, port, localAddress, localPort));
    }

    private Socket patch(Socket s) {
        if (s instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) s;
            sslSocket.setEnabledProtocols(TLS_VERSIONS);
            sslSocket.setEnabledCipherSuites(getDefaultCipherSuites());
        }
        return s;
    }
}