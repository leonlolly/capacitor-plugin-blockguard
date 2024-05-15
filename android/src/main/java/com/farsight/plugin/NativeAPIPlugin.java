package com.farsight.plugin;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.util.Log;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.PermissionCallback;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@CapacitorPlugin(name = "NativeAPI")
public class NativeAPIPlugin extends Plugin {
    private MyVpnService vpnService;

    @Override
    public void load() {
        vpnService = new MyVpnService();
        super.load();
    }

    @PluginMethod
    public void connectVPN(PluginCall call) {
        Log.d("Blockguard", "connectVPN: Initiated");
        if (getPermissionState("internet") != PermissionState.GRANTED) {
            Log.i("Blockguard", "connectVPN: Requesting internet permissions");
            requestPermissionForAlias("internet", call, "internetPermissionCallback");
            return;
        }

        Log.d("Blockguard", "connectVPN: internet permission available");
        prepareVPNConnection(call);
    }

    @PluginMethod
    public void disconnectVPN(PluginCall call) {
        Log.d("Blockguard", "connectVPN: Initiated");
        if (getPermissionState("internet") != PermissionState.GRANTED) {
        Log.i("Blockguard", "connectVPN: Requesting internet permissions");
        requestPermissionForAlias("internet", call, "internetPermissionCallback");
        return;
    }

        Log.d("Blockguard", "disconnectVPN: internet permission available");
        disableVPNConnection(call);
}


    @PluginMethod
    public void GetConnectionStatus(PluginCall call) {
        Log.d("Blockguard", "GetConnectionStatus");
        if (getPermissionState("internet") != PermissionState.GRANTED) {
            Log.i("Blockguard", "GetConnectionStatus: Requesting internet permissions");
            requestPermissionForAlias("internet", call, "internetPermissionCallback");
            return;
        }

        Log.d("Blockguard", "GetConnectionStatus: internet permission available");
        disableVPNConnection(call);
    }

    @PermissionCallback
    private void internetPermissionCallback(PluginCall call) {
        if (getPermissionState("internet") == PermissionState.GRANTED) {
            Log.w("Blockguard", "internetPermissionCallback: Request granted");
            prepareVPNConnection(call);
            return;
        }

        Log.w("Blockguard", "internetPermissionCallback: Request rejected");
        call.reject("The app needs permissions to access the internet to continue!");
    }

    public void prepareVPNConnection(PluginCall call) {
        var prepareIntent = VpnService.prepare(getContext());

        if (prepareIntent != null) {
            Log.d("Blockguard", "prepareVPNConnection: Preparing Connection");
            startActivityForResult(call, prepareIntent, "prepareVPNCallback");
            getContext().startActivity(prepareIntent);
        } else {
            Log.d("Blockguard", "prepareVPNConnection: Already prepared");
            launchVpnService(call);
        }
    }

    public void disableVPNConnection(PluginCall call) {
        var prepareIntent = VpnService.prepare(getContext());

        if (prepareIntent != null) {
            Log.d("Blockguard", "disableVPNConnection: Preparing Connection");
            startActivityForResult(call, prepareIntent, "prepareVPNCallback");
            getContext().startActivity(prepareIntent);
        } else {
            Log.d("Blockguard", "disableVPNConnection: Already prepared");
            disableVpnService(call);
        }
    }

    @ActivityCallback
    private void prepareVPNCallback(PluginCall call, ActivityResult result) {
        if (VpnService.prepare(getContext()) != null) {
            Log.w("Blockguard", "Preparation rejected");
            call.reject("The app could not set your active VPN!");
            return;
        }

        launchVpnService(call);
    }

    private void disableVpnService(PluginCall call) {
        Log.i("Blockguard", "launchVpnService: Starting");
        Context context = getContext();

        Intent vpnIntent = new Intent(context, MyVpnService.class);
        context.stopService(vpnIntent);
        call.resolve();
    }

    private void launchVpnService(PluginCall call) {
        Log.i("Blockguard", "launchVpnService: Starting");
        Context context = getContext();

        Intent vpnIntent = new Intent(context, MyVpnService.class);
        context.startService(vpnIntent);

        call.resolve();
    }

    @PluginMethod
    public static MTLSFetchResponse mtlsFetch(PluginCall call) {
        try {
            Log.i("Blockguard", "mtlsFetch: Starting");

            String method = call.getString("method");
            String url = call.getString("url");
            String body = call.getString("body");
            String clientCertificate = call.getString("clientCertificate");
            String privateKey = call.getString("privateKey");


            String cleanPrivateKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                encoded = Base64.getDecoder().decode(cleanPrivateKey);
            } else {
                encoded = android.util.Base64.decode(cleanPrivateKey, android.util.Base64.DEFAULT);
            }

            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(
                new ByteArrayInputStream(clientCertificate.getBytes())
            );

            Key key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));

            KeyStore clientKeyStore = KeyStore.getInstance("jks");
            final char[] pwdChars = "1234".toCharArray();
            clientKeyStore.load(null, null);
            clientKeyStore.setKeyEntry("test", key, pwdChars, chain.toArray(new Certificate[0]));

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(clientKeyStore, pwdChars);

            // Create Trust Manager that will accept self signed certificates.

            TrustManager[] acceptAllTrustManager = {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            // Initialize ssl context.

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), acceptAllTrustManager, new java.security.SecureRandom());

            OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) sslContext.getSocketFactory())
                .hostnameVerifier((hostname, session) -> true)
                .build();

            Request exactRequest = new Request.Builder()
                .url(url)
                .method(method, RequestBody.create(body, MediaType.parse("text/plain")))
                .build();

            try (Response exactResponse = client.newCall(exactRequest).execute()) {
                if (exactResponse.code() < 200 || exactResponse.code() > 299) {
                    Log.w("Blockguard", "mtlsFetch: Response code: " + exactResponse.code());
                    return new MTLSFetchResponse(false, exactResponse.code(), "");
                }
                String responseBody = exactResponse.body().string();
                Log.d("Blockguard", "mtlsFetch: Response code: " + exactResponse.code() + ", Body: " + responseBody.substring(0, Math.min(responseBody.length(), 100)));
                return new MTLSFetchResponse(true, exactResponse.code(), exactResponse.body().string());
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
