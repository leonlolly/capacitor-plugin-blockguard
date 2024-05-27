package com.farsight.plugin;

import android.annotation.SuppressLint;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class NativeAPI {

    public MTLSFetchResponse mtlsFetch(String method,String url, String body,String clientCertificate ,String privateKey) {
        try {
            System.setProperty("javax.net.debug", "all");

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            String privateKeyContent = privateKey
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);


            byte[] clientCertificateBytes = clientCertificate.getBytes(StandardCharsets.UTF_8); // Specify encoding for clarity
            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
            Certificate certificateChain = certificateFactory.generateCertificate(certificateChainAsInputStream);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("clientCertificate", certificateChain);
            keyStore.setKeyEntry("client", keyFactory.generatePrivate(keySpec), null, new Certificate[]{certificateChain});

            certificateChainAsInputStream.close();

            X509TrustManager trustManager = new MyTrustManager(keyStore);


            TrustManager[] trustManagers = {trustManager};

            HostnameVerifier hostnameVerifier = new HostnameVerifier() {
                @SuppressLint("BadHostnameVerifier")
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }};

            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null,trustManagers, null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            HttpsURLConnection ctx = null;
            InputStream o = null;

            try  {
                URL url2 = new URL(url);
                ctx = (HttpsURLConnection) url2.openConnection();
                ctx.setRequestMethod(method);
                ctx.setHostnameVerifier(hostnameVerifier);
                ctx.setAllowUserInteraction(true);
                ctx.setSSLSocketFactory(sslSocketFactory);
                ctx.connect();

                int responseCode = ctx.getResponseCode();



                if (responseCode < 200 || responseCode > 299) {
                    Log.w("Blockguard", "mtlsFetch: Response code: " + ctx.getResponseCode());
                    return new MTLSFetchResponse(false, ctx.getResponseCode(), "");
                }

                o = ctx.getInputStream();
                byte[] bytes = new byte[o.available()];
                String responseString = new String(bytes);


                    Log.d("Blockguard", "mtlsFetch: Response code: " + ctx.getResponseCode() + ", Body: " + responseString);
                    return new MTLSFetchResponse(true, ctx.getResponseCode() , responseString);

            } catch (IOException e) {
                Log.e("Blockguard", "mtlsFetch: IOException", e);
                return new MTLSFetchResponse(false, -1, e.getMessage());
            }
        } catch (
                KeyManagementException
                | InvalidKeySpecException
                | NoSuchAlgorithmException
                | KeyStoreException
                | IOException
                | CertificateException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());} catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}