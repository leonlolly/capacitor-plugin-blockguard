package com.farsight.plugin;

import android.annotation.SuppressLint;

import java.security.cert.CertificateException;

import java.security.cert.X509Certificate;

@SuppressLint("CustomX509TrustManager")
class CustomX509TrustManager implements javax.net.ssl.X509TrustManager
{

    private X509Certificate trustedCert;

    public CustomX509TrustManager(X509Certificate x509Certificate) throws Exception {
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

    }

    @SuppressLint("TrustAllX509TrustManager")
    @SuppressWarnings("unused")
    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException
    {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[] { trustedCert };
    }

}
