package com.farsight.plugin;

import static org.bouncycastle.jce.ECKeyUtil.privateToExplicitParameters;
import static org.bouncycastle.jce.ECKeyUtil.publicToExplicitParameters;

import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
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
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
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

            // Create an ECNamedCurveParameterSpec object
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

// Create an ECGenParameterSpec object based on the ECNamedCurveParameterSpec object
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(ecSpec.getName());

// Initialize the KeyPairGenerator object with the ECGenParameterSpec object
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(ecGenSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Extract the private key
            PrivateKey ecPrivateKey = keyPair.getPrivate();

            String certContent = clientCertificate
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END CERTIFICATE-----", "");


            byte[] clientCertificateBytes = Base64.getDecoder().decode(certContent); // Specify encoding for clarity

            ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2");
            Extension ex = Extension.create(asn1ObjectIdentifier, false, asn1ObjectIdentifier.toASN1Primitive());

            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(clientCertificateBytes);
            X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(x509CertificateHolder);

            certificateBuilder.addExtension(ex);

            if(!certificateBuilder.hasExtension(Extension.keyUsage)){
                throw new RuntimeException();
            };
            if(!certificateBuilder.hasExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.2"))){
                throw new RuntimeException();
            };
            if(!certificateBuilder.hasExtension(Extension.extendedKeyUsage)){
                throw new RuntimeException();
            };
            if(!certificateBuilder.hasExtension(Extension.basicConstraints)){
                throw new RuntimeException();
            };





            AlgorithmIdentifier signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(
                    "SHA256withECDSA");

            AlgorithmIdentifier digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(signatureAlgorithm);
            BcECContentSignerBuilder bcECContentSignerBuilder = new BcECContentSignerBuilder(signatureAlgorithm,digestAlgorithm);
            bcECContentSignerBuilder.setSecureRandom(new SecureRandom());


            privateToExplicitParameters(ecPrivateKey, "BC");

            if (!(ecPrivateKey instanceof ECPrivateKey ecPrivateKeycast)) {
                throw new InvalidKeySpecException();
            }

            ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(ecPrivateKeycast.getD(), ecSpec);

            ECCurve curve = ecSpec.getCurve();
            ECPoint G = curve.decodePoint(
                    Hex.decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            );
            BigInteger n = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");

            ECDomainParameters ecDomainParameters = new ECDomainParameters(curve, G, n);


            ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(ecPrivateKeySpec.getD(),ecDomainParameters);

            ContentSigner contentSigner = bcECContentSignerBuilder.build(ecPrivateKeyParameters);

            X509CertificateHolder x509CertificateHolderNew = certificateBuilder.build(contentSigner);

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
                 InvalidKeySpecException
                 | NoSuchAlgorithmException
                 | IOException e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());} catch (
                OperatorCreationException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return null;
    }
}