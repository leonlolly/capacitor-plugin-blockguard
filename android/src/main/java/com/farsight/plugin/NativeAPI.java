package com.farsight.plugin;

import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;

public class NativeAPI {


    public String alias = "PrivateKeyClient";

    public Provider provider;
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
            String s = BouncyCastleJsseProvider.PROVIDER_NAME;
            Security.removeProvider(s);
            Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);

            this.provider = Security.getProvider(s);

            this.keyStore = KeyStore.getInstance("AndroidKeyStore"); //PKCS12-DEF //PKCS12  //BKS  -- no diff in KEY_USAGE_BIT_INCORRECT
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
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyAsBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

//            if (!(privateKey instanceof BCECPrivateKey )) {
//                throw new RuntimeException("privateKey is not BCECPrivateKey");
//            }

            //CERT
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",this.provider);
            byte[] clientCertificateBytes = certificateString.getBytes(StandardCharsets.UTF_8);
            InputStream certificateChainAsInputStream = new ByteArrayInputStream(clientCertificateBytes);
            X509Certificate originalCert = (X509Certificate) certificateFactory.generateCertificate(certificateChainAsInputStream);
            originalCert.checkValidity();
            byte[] a = originalCert.getEncoded();



//            if (!(originalCert.getPublicKey() instanceof BCECPublicKey)) {
//                throw new RuntimeException("originalCert public key is not BCECPublicKey");
//            }

            this.keyStore.setKeyEntry(this.alias, privateKey, null, new X509Certificate[]{originalCert});
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
            Signature signature = Signature.getInstance("SHA256withECDSA",this.provider);
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

            String a = certificate.getPublicKey().getAlgorithm();
            String b = publicKey.getAlgorithm();

            PublicKey publicKeyFromCert = certificate.getPublicKey();
//            if (!(publicKeyFromCert instanceof ECDSAPublicKey)) {
//                Log.e("CertificateValidation", "Public key in certificate is not ECDSAPublicKey");
//                return false;
//            }


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

//            if (!(privateKey instanceof ECDSAPublicKey)) {
//                Log.e("CertificateValidation", "PrivateKey in certificate is not ECDSAPublicKey");
//                return false;
//            }

            PublicKey publicKeyFromCertificate = certificate.getPublicKey();
            PublicKey publicKeyFromPrivateKey = KeyFactory.getInstance("EC",this.provider)
                    .generatePublic(new PKCS8EncodedKeySpec(privateKey.getEncoded()));

            return publicKeyFromPrivateKey.equals(publicKeyFromCertificate);
        } catch (Exception e) {
            Log.e("Blockguard", "validatePublicKey: ", e);
            return false;
        }
    }

    private X509Certificate getCertificate(){
        try {
            return (X509Certificate) this.keyStore.getCertificate(this.alias);
        } catch (ClassCastException | KeyStoreException e) {
            Log.e("CertificateError", "Invalid certificate type retrieved from keystore", e);
        }
        throw new RuntimeException("Failed to retrieve certificate from keystore");
    }


    public MTLSFetchResponse mtlsFetch(String method, String url, String body) {
        try {

            String s = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX",this.provider);
            trustManagerFactory.init(this.keyStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
//            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
//                throw new IllegalStateException("Unexpected default trust managers:"
//                        + Arrays.toString(trustManagers));
//            }
            X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

            SSLContext sslContext = SSLContext.getInstance("TLS",this.provider);
            sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            Gson gson = new GsonBuilder().create();

            OkHttpClient client = new OkHttpClient.Builder()
                    .sslSocketFactory(sslSocketFactory, trustManager)
                    .build();


            Retrofit retrofit = new Retrofit.Builder()
                    .baseUrl(url)
                    .addConverterFactory(GsonConverterFactory.create(gson))
                    .client(client)
                    .build();


            interface MyApi {
                @GET("/")
                Call<String> getStringWithCode();
            }

            MyApi api = retrofit.create(MyApi.class);

            Call<String> call = api.getStringWithCode();

            Request a = call.request();
            Response<String> b = call.execute();

            Log.d("Blockguard", "mtlsFetch: " + a.toString());


        } catch (
                Exception e
        ) {
            Log.e("Blockguard", "mtlsFetch: Exception during certificate processing", e);
            return new MTLSFetchResponse(false, -1, e.getMessage());
        }
        return new MTLSFetchResponse(false, -1, "null");
    }
}