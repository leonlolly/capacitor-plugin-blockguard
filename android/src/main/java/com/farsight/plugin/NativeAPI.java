package com.farsight.plugin;

import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


public class NativeAPI {


    public String alias = "alias";
    public KeyStore keyStore;

    public NativeAPI(){
        try {
            this.keyStore = KeyStore.getInstance("AndroidKeyStore" ); //PKCS12-DEF //PKCS12  //BKS  -- no diff in KEY_USAGE_BIT_INCORRECT
            this.keyStore.load(null, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
            }
    }

    public void storePrivateKeyWithCertificate(String privateKeyString, String certificateString) {
        try {
            //PK
            String privateKeyContent = privateKeyString
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
            KeyFactory keyFactory = KeyFactory.getInstance("EC" );
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            //CERT
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509" );
            byte[] clientCertificateBytes = certificateString.getBytes(StandardCharsets.UTF_8);
            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
            Certificate originalCert = certificateFactory.generateCertificate(certificateChainAsInputStream);

            this.keyStore.setKeyEntry(this.alias, privateKey, null, new Certificate[]{originalCert});
        }
        catch (Exception e){
            Log.e("Blockguard", "storePrivateKey: ", e);
            Log.e("Blockguard", "storePrivateKey: ", e.getCause());
        }
    }

        public boolean validatePrivateKey(PublicKey publicKey) {
        try {
            ECPrivateKey privateKey = (ECPrivateKey) this.keyStore.getKey(this.alias, null);

            byte[] data = "Test Data".getBytes();
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signedData = signature.sign();

            signature.initVerify(publicKey);
            signature.update(data);

            return signature.verify(signedData);
        } catch (Exception e) {
            Log.e("KeyValidationUtil", "validatePrivateKey: ", e);
            return false;
        }
    }


    public boolean validateCertificate(PublicKey publicKey) {
        try {
            Certificate[] certificates = this.keyStore.getCertificateChain(alias);
            X509Certificate certificate = (X509Certificate) certificates[0];
            PublicKey extractedPublicKey = certificate.getPublicKey();



            if (!certificate.getPublicKey().getAlgorithm().equals(publicKey.getAlgorithm())) {
                Log.w("CertificateValidation", "Public key algorithm mismatch in certificate");
                return false;
            }

            if (!extractedPublicKey.equals(publicKey)) {
                return false;
            }

            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            Log.e("Blockguard", "validateCertificate: ", e);
            return false;
        }
    }


    public boolean validatePublicKey() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) this.keyStore.getEntry(alias,null);
            Certificate certificate = privateKeyEntry.getCertificate();
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            PublicKey publicKeyFromCertificate = certificate.getPublicKey();
            PublicKey publicKeyFromPrivateKey = KeyFactory.getInstance("EC")
                    .generatePublic(new PKCS8EncodedKeySpec(privateKey.getEncoded()));

            return publicKeyFromPrivateKey.equals(publicKeyFromCertificate);
        } catch (Exception e) {
            Log.e("Blockguard", "validatePublicKey: ", e);
            return false;
        }
    }

    private X509Certificate getCertificate(){
        try {
            return (X509Certificate) this.keyStore.getCertificate("client");
        } catch (ClassCastException | KeyStoreException e) {
            Log.e("CertificateError", "Invalid certificate type retrieved from keystore", e);
        }
        throw new RuntimeException("Failed to retrieve certificate from keystore");
    }


    public MTLSFetchResponse mtlsFetch(String method, String url, String body) {
        try {

            CustomX509TrustManager trustManager = new CustomX509TrustManager(getCertificate());


            TrustManager[] trustManagers = {trustManager};


            SSLContext sslContext = SSLContext.getInstance("TLS");

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(this.keyStore, null);

            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            HttpsURLConnection ctx;
            InputStream o;

            try {
                URL url2 = new URL(url);
                ctx = (HttpsURLConnection) url2.openConnection();
                ctx.setSSLSocketFactory(sslSocketFactory);
                ctx.setHostnameVerifier((hostname, session) -> true);
                ctx.setRequestMethod(method);

                ctx.connect();

                int responseCode = ctx.getResponseCode();


                if (responseCode < 200 || responseCode > 299) {
                    Log.w("Blockguard", "mtlsFetch: Response code: " + ctx.getResponseCode());
                    return new MTLSFetchResponse(false, ctx.getResponseCode(), "");
                }

                StringBuilder response = new StringBuilder();
                try (BufferedReader in = new BufferedReader(new InputStreamReader(ctx.getInputStream()))) {
                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        response.append(inputLine);
                    }
                } catch (Exception e) {
                    Log.e("Blockguard", "Error reading response", e);
                    return new MTLSFetchResponse(false, responseCode, "");
                }
                String res = response.toString();


                Log.d("Blockguard", "mtlsFetch: Response code: " + ctx.getResponseCode() + ", Body: " + res);
                return new MTLSFetchResponse(true, ctx.getResponseCode(), res);

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
            return new MTLSFetchResponse(false, -1, e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    }