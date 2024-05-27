package com.farsight.plugin;

import android.annotation.SuppressLint;

import java.security.KeyStore;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManagerFactory;

import java.security.cert.X509Certificate;

@SuppressLint("CustomX509TrustManager")
class X509TrustManager implements javax.net.ssl.X509TrustManager
{

    private final javax.net.ssl.X509TrustManager trustManager;

    public X509TrustManager(KeyStore keyStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        trustManager = (javax.net.ssl.X509TrustManager) tmf.getTrustManagers()[0];
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
    {
        trustManager.checkClientTrusted(chain, authType);
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
    {
    }

    @SuppressLint("TrustAllX509TrustManager")
    @SuppressWarnings("unused")
    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException
    {
    }

    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        X509Certificate[] certificates = trustManager.getAcceptedIssuers();
        return certificates;
    }

}
