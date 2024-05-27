package com.farsight.plugin;

import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.internal.tls.OkHostnameVerifier;

public class NativeAPI {

    public MTLSFetchResponse mtlsFetch(String method,String url, String body,String clientCertificate ,String privateKey) {
        try {

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);


            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);

            String privateKeyContent = privateKey
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);


            byte[] clientCertificateBytes = clientCertificate.getBytes(StandardCharsets.UTF_8); // Specify encoding for clarity
            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
            Certificate certificateChain = certificateFactory.generateCertificate(certificateChainAsInputStream);

            KeyStore identityStore = KeyStore.getInstance(KeyStore.getDefaultType());
            identityStore.load(null, null);
            identityStore.setKeyEntry("client", keyFactory.generatePrivate(keySpec), null, new Certificate[]{certificateChain});

            certificateChainAsInputStream.close();

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            trustManagerFactory.init(trustStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            keyManagerFactory.init(identityStore, null);
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(keyManagers, null, null);

            SSLSocketFactory sslSocketFactory =(SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket)sslSocketFactory.createSocket();




            HttpsURLConnection ctx = null;
            InputStream o = null;

            try  {
                URL url2 = new URL(url);
                ctx = (HttpsURLConnection) url2.openConnection();
                ctx.setRequestMethod(method);
                ctx.setAllowUserInteraction(true);
                ctx.setSSLSocketFactory(sslContext.getSocketFactory());
                ctx.connect();



                if (ctx.getResponseCode() < 200 || ctx.getResponseCode() > 299) {
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
                UnrecoverableKeyException
                | KeyManagementException
                | InvalidKeySpecException
                | NoSuchAlgorithmException
                | KeyStoreException
                | IOException
                | CertificateException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());} catch (
                NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}