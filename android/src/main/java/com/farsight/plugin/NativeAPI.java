package com.farsight.plugin;

import android.annotation.SuppressLint;
import android.util.Log;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tls.TlsClientContext;
import org.bouncycastle.tls.TlsClientProtocol;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;


public class NativeAPI {


    public String privateKeyAlias = "PrivateKeyClient";
    public String certificateAlias = "CertificateAlias";
    public KeyStore keyStore;

    public NativeAPI(){
        try {
            final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            if (provider == null) {
                // Web3j will set up the provider lazily when it's first used.
                return;
            }
            if (provider.getClass().equals(BouncyCastleProvider.class)) {
                // BC with same package name, shouldn't happen in real life.
                return;
            }
            // Android registers its own BC provider. As it might be outdated and might not include
            // all needed ciphers, we substitute it with a known BC bundled in the app.
            // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
            // of that it's possible to have another BC implementation loaded in VM.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            Security.insertProviderAt(new BouncyCastleProvider(), 1);


            this.keyStore = KeyStore.getInstance("PKCS12-DEF", BouncyCastleProvider.PROVIDER_NAME); //PKCS12-DEF //PKCS12  //BKS  -- no diff in KEY_USAGE_BIT_INCORRECT
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
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA",BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            if (!(privateKey instanceof BCECPrivateKey )) {
                throw new RuntimeException("privateKey is not BCECPrivateKey");
            }

            //CERT
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",BouncyCastleProvider.PROVIDER_NAME);
            byte[] clientCertificateBytes = certificateString.getBytes(StandardCharsets.UTF_8);
            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
            X509Certificate originalCert = (X509Certificate) certificateFactory.generateCertificate(certificateChainAsInputStream);

            if (!(originalCert.getPublicKey() instanceof BCECPublicKey)) {
                throw new RuntimeException("originalCert public key is not BCECPublicKey");
            }

            this.keyStore.setKeyEntry(this.privateKeyAlias, privateKey, null, new X509Certificate[]{originalCert});
        }
        catch (Exception e){
            Log.e("Blockguard", "storePrivateKey: ", e);
            Log.e("Blockguard", "storePrivateKey: ", e.getCause());
        }
    }

        public boolean validatePrivateKey(PublicKey publicKey) {
        try {
            ECPrivateKey privateKey = (ECPrivateKey) this.keyStore.getKey(this.privateKeyAlias, null);

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
            Certificate[] certificates = this.keyStore.getCertificateChain(privateKeyAlias);
            X509Certificate certificate = (X509Certificate) certificates[0];
            PublicKey extractedPublicKey = certificate.getPublicKey();

            String a = certificate.getPublicKey().getAlgorithm();
            String b = publicKey.getAlgorithm();

            PublicKey publicKeyFromCert = certificate.getPublicKey();
            if (!(publicKeyFromCert instanceof ECDSAPublicKey)) {
                Log.e("CertificateValidation", "Public key in certificate is not ECDSAPublicKey");
                return false;
            }

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getEncoded());
            ECPublicKey ecPublicKeyFromCert = (ECPublicKey) subjectPublicKeyInfo.parsePublicKey();

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
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) this.keyStore.getEntry(privateKeyAlias,null);
            Certificate certificate = privateKeyEntry.getCertificate();
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            if (!(privateKey instanceof ECDSAPublicKey)) {
                Log.e("CertificateValidation", "PrivateKey in certificate is not ECDSAPublicKey");
                return false;
            }

            PublicKey publicKeyFromCertificate = certificate.getPublicKey();
            PublicKey publicKeyFromPrivateKey = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME)
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

            X509TrustManager trustManager = new X509TrustManager(getCertificate());


            TrustManager[] trustManagers = {trustManager};

            HostnameVerifier hostnameVerifier = new HostnameVerifier() {
                @SuppressLint("BadHostnameVerifier")
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };


            SSLContext sslContext = SSLContext.getInstance("TLS");

            sslContext.init(null, trustManagers, null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            HttpsURLConnection ctx = null;
            InputStream o = null;

            try {
                URL url2 = new URL(url);
                ctx = (HttpsURLConnection) url2.openConnection();
                ctx.setSSLSocketFactory(sslSocketFactory);
                ctx.setReadTimeout(10000);
                ctx.setConnectTimeout(15000);
                ctx.setRequestMethod(method);
                ctx.setDoInput(true);
                ctx.setDoOutput(true);
                ctx.setRequestProperty("Content-Type", "text/plain; charset=utf-8");

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
                return new MTLSFetchResponse(true, ctx.getResponseCode(), responseString);

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