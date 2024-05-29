package com.farsight.plugin;

import android.annotation.SuppressLint;
import android.util.Log;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManagerFactory;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

@SuppressLint("CustomX509TrustManager")
class X509TrustManager implements javax.net.ssl.X509TrustManager
{

    private X509Certificate trustedCert;

    public X509TrustManager(X509Certificate x509Certificate) throws Exception {
        trustedCert = x509Certificate;
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
    {
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // Check if the server certificate matches our trusted self-signed certificate
        if (chain[0].equals(trustedCert)) {
            return; // Trusted certificate
        } else {
            throw new CertificateException("Untrusted server certificate!");
        }
    }

    @SuppressLint("TrustAllX509TrustManager")
    @SuppressWarnings("unused")
    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException
    {
        if (chain[0].equals(trustedCert)) {
            return;
        } else {
            throw new CertificateException("Untrusted server certificate!");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[] { trustedCert };
    }

}
