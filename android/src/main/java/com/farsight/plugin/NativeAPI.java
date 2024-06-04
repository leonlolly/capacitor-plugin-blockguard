package com.farsight.plugin;

import android.util.Log;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Handshake;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class NativeAPI {


    public String alias = "PrivateKeyClient";


//    public void storePrivateKeyWithCertificate(String privateKeyString, String certificateString) {
//        try {
//            //PK
//            String privateKeyContent = privateKeyString
//                    .replace("-----BEGIN PRIVATE KEY-----", "")
//                    .replaceAll(System.lineSeparator(), "")
//                    .replace("-----END PRIVATE KEY-----", "");
//
//            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
//            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
//
////            if (!(privateKey instanceof BCECPrivateKey )) {
////                throw new RuntimeException("privateKey is not BCECPrivateKey");
////            }
//
//            //CERT
//            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509" );
//            byte[] clientCertificateBytes = certificateString.getBytes(StandardCharsets.UTF_8);
//            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
//            X509Certificate originalCert = (X509Certificate) certificateFactory.generateCertificate(certificateChainAsInputStream);
//            originalCert.checkValidity();
//            byte[] a = originalCert.getEncoded();
//
//
//
////            if (!(originalCert.getPublicKey() instanceof BCECPublicKey)) {
////                throw new RuntimeException("originalCert public key is not BCECPublicKey");
////            }
//
//           // this.keyStore.setKeyEntry(this.alias, privateKey, null, new X509Certificate[]{originalCert});
//        }
//        catch (Exception e){
//            Log.e("Blockguard", "storePrivateKey: ", e);
//            Log.e("Blockguard", "storePrivateKey: ", e.getCause());
//        }
//    }

//        public boolean validatePrivateKey(PublicKey publicKey) {
//        try {
//            ECPrivateKey privateKey = (ECPrivateKey) this.keyStore.getKey(this.alias, null);
//
//            byte[] data = "Test Data".getBytes();
//            Signature signature = Signature.getInstance("SHA256withECDSA" );
//            signature.initSign(privateKey);
//            signature.update(data);
//            byte[] signedData = signature.sign();
//
//            signature.initVerify(publicKey);
//            signature.update(data);
//
//            return signature.verify(signedData);
//        } catch (Exception e) {
//            Log.e("KeyValidationUtil", "validatePrivateKey: ", e);
//            return false;
//        }
//    }


//    public boolean validateCertificate(PublicKey publicKey) {
//        try {
//            Certificate[] certificates = this.keyStore.getCertificateChain(alias);
//            X509Certificate certificate = (X509Certificate) certificates[0];
//            PublicKey extractedPublicKey = certificate.getPublicKey();
//
//            String a = certificate.getPublicKey().getAlgorithm();
//            String b = publicKey.getAlgorithm();
//
//            PublicKey publicKeyFromCert = certificate.getPublicKey();
////            if (!(publicKeyFromCert instanceof ECDSAPublicKey)) {
////                Log.e("CertificateValidation", "Public key in certificate is not ECDSAPublicKey");
////                return false;
////            }
//
//
//            if (!certificate.getPublicKey().getAlgorithm().equals(publicKey.getAlgorithm())) {
//                Log.w("CertificateValidation", "Public key algorithm mismatch in certificate");
//                return false;
//            }
//
//            if (!extractedPublicKey.equals(publicKey)) {
//                return false;
//            }
//
//            certificate.verify(publicKey);
//            return true;
//        } catch (Exception e) {
//            Log.e("Blockguard", "validateCertificate: ", e);
//            return false;
//        }
//    }


//    public boolean validatePublicKey() {
//        try {
//            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) this.keyStore.getEntry(alias,null);
//            Certificate certificate = privateKeyEntry.getCertificate();
//            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
//
////            if (!(privateKey instanceof ECDSAPublicKey)) {
////                Log.e("CertificateValidation", "PrivateKey in certificate is not ECDSAPublicKey");
////                return false;
////            }
//
//            PublicKey publicKeyFromCertificate = certificate.getPublicKey();
//            PublicKey publicKeyFromPrivateKey = KeyFactory.getInstance("EC" )
//                    .generatePublic(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
//
//            return publicKeyFromPrivateKey.equals(publicKeyFromCertificate);
//        } catch (Exception e) {
//            Log.e("Blockguard", "validatePublicKey: ", e);
//            return false;
//        }
//    }

//    private X509Certificate getCertificate(){
//        try {
//            return (X509Certificate) this.keyStore.getCertificate(this.alias);
//        } catch (ClassCastException | KeyStoreException e) {
//            Log.e("CertificateError", "Invalid certificate type retrieved from keystore", e);
//        }
//        throw new RuntimeException("Failed to retrieve certificate from keystore");
//    }
//
//    private PrivateKey getPrivateKey(){
//        try {
//            return (PrivateKey) this.keyStore.getKey(this.alias,null);
//        } catch (Exception e) {
//            Log.e("PrivateKeyError", "Invalid PrivateKey type retrieved from keystore", e);
//        }
//        throw new RuntimeException("Failed to retrieve PrivateKey from keystore");
//    }


    public MTLSFetchResponse mtlsFetch(String method, String url, String body,String privateKeyString,String certificateString,int keyUsageInt) throws IOException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, InvalidKeySpecException {
//PK
            String privateKeyContent = privateKeyString
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);


        String certificateContent = certificateString
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END CERTIFICATE-----", "");

        byte[] clientCertificateBytes = Base64.getDecoder().decode(certificateContent);


            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(clientCertificateBytes);
            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(x509CertificateHolder);

//            certificateBuilder.addExtension(ex);

//            if(!certificateBuilder.hasExtension(Extension.keyUsage)){
//                throw new RuntimeException();
//            };
            //certificateBuilder.removeExtension(Extension.keyUsage);


//        KeyUsage keyUsage = new KeyUsage(keyUsageInt);
//        certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);


        certificateBuilder.removeExtension(Extension.extendedKeyUsage);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
        certificateBuilder.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);

        if(!certificateBuilder.hasExtension(Extension.extendedKeyUsage)){
            throw new RuntimeException();
        };
        if(!certificateBuilder.hasExtension(Extension.basicConstraints)){
            throw new RuntimeException();
        };

            if(!certificateBuilder.hasExtension(Extension.extendedKeyUsage)){
                throw new RuntimeException();
            };
            if(!certificateBuilder.hasExtension(Extension.basicConstraints)){
                throw new RuntimeException();
            };


            ContentSigner certSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .build(privateKey);

            X509CertificateHolder certificateHolder = certificateBuilder.build(certSigner);


            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);


            byte[] policyBytes = cert.getExtensionValue(Extension.certificatePolicies.toString());

            ASN1Primitive asn1Primitive = JcaX509ExtensionUtils.parseExtensionValue(policyBytes);

            CertificatePolicies policies = CertificatePolicies.getInstance(asn1Primitive);


            KeyStore keyStore2 = KeyStore.getInstance("AndroidKeyStore");
            keyStore2.load(null, null);
            keyStore2.setKeyEntry(this.alias, privateKey, null, new X509Certificate[]{cert});


            String s = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX" );
            trustManagerFactory.init(keyStore2);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
//            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
//                throw new IllegalStateException("Unexpected default trust managers:"
//                        + Arrays.toString(trustManagers));
//            }
            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            SSLContext sslContext = SSLContext.getInstance("TLS" );
            sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();



            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslSocketFactory, trustManager)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();

            Call call = client.newCall(new Request.Builder().url(url).build());

            Log.i("Blockguard", String.valueOf(keyUsageInt));
            try (Response response = call.execute()){
                return new MTLSFetchResponse(true, 5, "<");



            }
            catch (SSLHandshakeException e){
                if (Objects.requireNonNull(e.getMessage()).contains("KEY_USAGE_BIT_INCORRECT")){
                return new MTLSFetchResponse(false, -1, e.getMessage());
            }
                else {
                    throw e;
                }


            }
}}