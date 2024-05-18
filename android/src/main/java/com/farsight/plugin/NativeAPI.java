package com.farsight.plugin;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import org.conscrypt.Conscrypt.ProviderBuilder;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.cert.X509Certificate;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class NativeAPI {

    public MTLSFetchResponse mtlsFetch(String method,String url, String body,String clientCertificate ,String privateKey) {
        try {

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");


            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

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


            try {
                String a = KeyStore.getDefaultType();
                System.out.print(a);
                // Load the client key and certificate from a key store
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null,null);
                keyStore.setKeyEntry("client", keyFactory.generatePrivate(keySpec), null, new Certificate[]{certificateChain});

                KeyStore.Entry b = keyStore.getEntry("client",null);
                System.out.print(b);

// Create a KeyManagerFactory and initialize it with the client key and certificate
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(keyStore, "password".toCharArray());

// Load the server certificate from a trust store


                keyStore.setCertificateEntry("cert",certificateChain);

// Create a TrustManagerFactory and initialize it with the server certificate
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);

// Create an SSLContext and initialize it with the client key and certificate, and the server certificate
                SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
                sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());


// Create a ConscryptEngineSocket and configure it with the SSLContext
                URL url2 = new URL(url);
                HttpsURLConnection ctx = (HttpsURLConnection) url2.openConnection();
                ctx.setSSLSocketFactory(sslContext.getSocketFactory());
                InputStream o = (InputStream) ctx.getContent();
                byte[] bytes = new byte[o.available()];
                o.read(bytes);
            }
            catch (Exception e){
                Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
                throw e;
            }


            KeyStore identityStore = KeyStore.getInstance(KeyStore.getDefaultType());
            identityStore.load(null, null);
            identityStore.setKeyEntry("client", keyFactory.generatePrivate(keySpec), null, new Certificate[]{certificateChain});

            certificateChainAsInputStream.close();

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(identityStore, null);
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0])
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
//            try (Response exactResponse = client.newCall(exactRequest).execute()) {
//                if (exactResponse.code() < 200 || exactResponse.code() > 299) {
//                    Log.w("Blockguard", "mtlsFetch: Response code: " + exactResponse.code());
//                    return new MTLSFetchResponse(false, exactResponse.code(), "");
//                }
//                ResponseBody responseBody = exactResponse.body();
//                if (responseBody == null) {
//                    Log.d("Blockguard", "mtlsFetch: Response code: " + exactResponse.code() + ", Body: responseBody is empty");
//                    return new MTLSFetchResponse(true, exactResponse.code(), "responseBody is empty");
//                } else {
//                    String responseBodystring = responseBody.string();
//                    Log.d("Blockguard", "mtlsFetch: Response code: " + exactResponse.code() + ", Body: " + responseBodystring);
//                    return new MTLSFetchResponse(true, exactResponse.code(), responseBodystring);
//                }
//            } catch (IOException e) {
//                Log.e("Blockguard", "mtlsFetch: IOException", e);
//                return new MTLSFetchResponse(false, -1, e.getMessage());
//            }
        } catch (
                KeyManagementException | InvalidKeySpecException | NoSuchAlgorithmException |
                KeyStoreException | IOException |
                CertificateException |
                UnrecoverableEntryException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());}
        return null;
    }
}