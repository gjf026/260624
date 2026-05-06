package com.github.tvbox.osc.util.SSL;

import android.os.Build;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class SSLSocketFactoryCompat extends SSLSocketFactory {
    private final SSLSocketFactory defaultFactory;
    private String TLS_VERSIONS[] = { "TLSv1.1", "TLSv1.2", "TLSv1.3" };
    private String TLS_CIPHER_SUITES[] = null;

    public SSLSocketFactoryCompat(X509TrustManager tm) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, (tm != null) ? new X509TrustManager[] { tm } : null, null);
            defaultFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException e) {
            throw new AssertionError();
        }

        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.ICE_CREAM_SANDWICH_MR1) {
            // Disable ECDSA cipher suites on Android 4.0.x, which do not support them.
            // No way to set siguature schemes, so we have to disable TLS v1.3.

            List<String> cipherSuites = new ArrayList<>();
            for (String suite : defaultFactory.getDefaultCipherSuites()) {
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
        return defaultFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return defaultFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        Socket ssl = patch(defaultFactory.createSocket(s, host, port, autoClose));
        return ssl;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        Socket ssl = patch(defaultFactory.createSocket(host, port));
        return ssl;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        Socket ssl = patch(defaultFactory.createSocket(host, port, localHost, localPort));
        return ssl;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket ssl = patch(defaultFactory.createSocket(host, port));
        return ssl;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        Socket ssl = patch(defaultFactory.createSocket(address, port, localAddress, localPort));
        return ssl;
    }

    private Socket patch(Socket s) {
        if (s instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) s;
            sslSocket.setEnabledCipherSuites(getDefaultCipherSuites());
            sslSocket.setEnabledProtocols(TLS_VERSIONS);
        }
        return s;
    }
}