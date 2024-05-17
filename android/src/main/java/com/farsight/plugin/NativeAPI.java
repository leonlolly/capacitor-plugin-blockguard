package com.farsight.plugin;

import android.util.Log;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class NativeAPI {

    public MTLSFetchResponse mtlsFetch(String method,String url, String body,String clientCertificate ,String privateKey) {
        try {
            String cleanPrivateKey = privateKey.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .trim();

            byte[] encoded = Base64.getDecoder().decode(cleanPrivateKey);

            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(new ByteArrayInputStream(clientCertificate.getBytes()));

            PrivateKey generatePrivate = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));

            KeyStore clientKeyStore = KeyStore.getInstance("AndroidKeyStore");
            clientKeyStore.load(null, null);
            clientKeyStore.setKeyEntry("test", generatePrivate, null, chain.toArray(new Certificate[0]));

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
            keyManagerFactory.init(clientKeyStore, null);


            // Create Trust Manager that will accept self signed certificates.

            X509TrustManager[] acceptAllTrustManager = {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(
                                X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(
                                X509Certificate[] certs, String authType) {
                        }
                    }
            };

            // Initialize ssl context.

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), acceptAllTrustManager, new SecureRandom());

            X509TrustManager trustManager = acceptAllTrustManager[0];

            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                    .build();

            Request exactRequest;
            if (body.isEmpty()){
                exactRequest = new Request.Builder()
                        .url(url)
                        .method(method, null) // Remove RequestBody argument for GET
                        .build();
            }
            else {
                exactRequest = new Request.Builder()
                        .url(url)
                        .method(method, RequestBody.create(body, MediaType.parse("text/plain")))
                        .build();
            }
            try (Response exactResponse = client.newCall(exactRequest).execute()) {
                if (exactResponse.code() < 200 || exactResponse.code() > 299) {
                    Log.w("Blockguard", "mtlsFetch: Response code: " + exactResponse.code());
                    return new MTLSFetchResponse(false, exactResponse.code(), "");
                }
                ResponseBody responseBody = exactResponse.body();
                if (responseBody == null) {
                    Log.d("Blockguard", "mtlsFetch: Response code: " + exactResponse.code() + ", Body: responseBody is empty");
                    return new MTLSFetchResponse(true, exactResponse.code(), "responseBody is empty");
                } else {
                    String responseBodystring = responseBody.string();
                    Log.d("Blockguard", "mtlsFetch: Response code: " + exactResponse.code() + ", Body: " + responseBodystring);
                    return new MTLSFetchResponse(true, exactResponse.code(), responseBodystring);
                }
            } catch (IOException e) {
                Log.e("Blockguard", "mtlsFetch: IOException", e);
                return new MTLSFetchResponse(false, -1, e.getMessage());
            }
        } catch (
                UnrecoverableKeyException
                | KeyManagementException
                | InvalidKeySpecException
                | NoSuchAlgorithmException
                | KeyStoreException
                | IOException
                | CertificateException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());}
    }
}