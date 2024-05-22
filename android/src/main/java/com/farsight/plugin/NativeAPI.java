package com.farsight.plugin;

import static org.bouncycastle.jce.ECKeyUtil.privateToExplicitParameters;
import static org.bouncycastle.jce.ECKeyUtil.publicToExplicitParameters;

import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;


import org.bouncycastle.jce.ECKeyUtil;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import java.security.cert.X509Certificate;
import java.util.Locale;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class NativeAPI {

    public MTLSFetchResponse mtlsFetch(String method,String url, String body,String clientCertificate ,String privateKeyString) {
        try {
//            Security.removeProvider("BC");
//            BouncyCastleProvider bc = new BouncyCastleProvider();
//            Security.insertProviderAt(bc, 1);

            String privateKeyContent = privateKeyString
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyAsBytes = Base64.getDecoder().decode(privateKeyContent);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            String certContent = clientCertificate
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END CERTIFICATE-----", "");



            ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2");
            Extension clientAuthExtention = Extension.create(asn1ObjectIdentifier, false, asn1ObjectIdentifier.toASN1Primitive());

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate originalCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(clientCertificate.getBytes()));


            PublicKey publicKey = originalCert.getPublicKey();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

            X500Name issuerSubjectName = new X500Name(originalCert.getSubjectX500Principal().getName());

            boolean isSelfSigned = originalCert.getSubjectX500Principal().equals(originalCert.getIssuerX500Principal());

            if(!isSelfSigned){
                throw new Exception("lol");
            }

            ContentSigner certSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                    .build(privateKey);


            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                    new X500Name(originalCert.getIssuerX500Principal().getName()),
                    originalCert.getSerialNumber(),
                    originalCert.getNotBefore(),
                    originalCert.getNotAfter(),
                    new X500Name(originalCert.getSubjectX500Principal().getName()),
                    publicKeyInfo);

            certificateBuilder.addExtension(clientAuthExtention);

            X509CertificateHolder x509CertificateHolderNew = certificateBuilder.build(certSigner);

            Extensions extensions = x509CertificateHolderNew.getExtensions();

            extensions.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"));


//            KeyStore identityStore = KeyStore.getInstance(KeyStore.getDefaultType());
//            identityStore.load(null, null);
//            identityStore.setKeyEntry("client", privateKey, null, new Certificate[]{certificateChain});
//
//
//            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//            trustManagerFactory.init(trustStore);
//            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
//
//            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
//            keyManagerFactory.init(identityStore, null);
//            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
//
//            SSLContext sslContext = SSLContext.getInstance("TLS");
//            sslContext.init(keyManagers, trustManagers, null);
//
//            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
//
//            OkHttpClient client = new OkHttpClient.Builder()
//                    .sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0])
//                    .build();
//
//            Request exactRequest;
//            if (body.isEmpty()){
//                exactRequest = new Request.Builder()
//                        .url(url)
//                        .method(method, null) // Remove RequestBody argument for GET
//                        .build();
//            }
//            else {
//                exactRequest = new Request.Builder()
//                        .url(url)
//                        .method(method, RequestBody.create(body, MediaType.parse("text/plain")))
//                        .build();
//            }
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
            }
         catch (
                 InvalidKeySpecException | NoSuchAlgorithmException | IOException |
                 CertificateException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());} catch (Exception e) {
            throw new RuntimeException(e);
        }
        return null;
    }
}