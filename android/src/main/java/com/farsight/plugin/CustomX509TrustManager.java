package com.farsight.plugin;

import android.annotation.SuppressLint;
import android.util.Log;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@SuppressLint("CustomX509TrustManager")
class CustomX509TrustManager implements javax.net.ssl.X509TrustManager
{

    private X509Certificate trustedCert;

    public CustomX509TrustManager(X509Certificate x509Certificate) throws Exception {
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
    {
        Log.i("checkClientTrusted", Arrays.toString(chain));
        Log.i("checkClientTrusted", authType);
    }

    @SuppressLint("TrustAllX509TrustManager")
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        Log.i("checkServerTrusted", Arrays.toString(chain));
        Log.i("checkServerTrusted", authType);

    }

    @SuppressLint("TrustAllX509TrustManager")
    @SuppressWarnings("unused")
    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException
    {
        trustedCert = chain[0];
        Log.i("checkServerTrusted", Arrays.toString(chain));
        Log.i("checkServerTrusted", authType);
        Log.i("checkServerTrusted", host);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[] { trustedCert };
    }

}
