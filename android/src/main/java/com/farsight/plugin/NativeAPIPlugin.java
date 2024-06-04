package com.farsight.plugin;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.system.ErrnoException;
import android.util.Log;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

@CapacitorPlugin(name = "NativeAPI", permissions = {@Permission(alias = NativeAPIPlugin.internet, strings = {Manifest.permission.INTERNET})})
public class NativeAPIPlugin extends Plugin {
    private MyVpnService vpnService;

    private NativeAPI nativeAPI = new NativeAPI();

    public static final String internet = "INTERNET";

    @Override
    public void load() {
        vpnService = new MyVpnService();
        super.load();
    }

    @PluginMethod
    public void connectVPN(PluginCall call) {
        Log.d("Blockguard", "connectVPN: Initiated");
        if (getPermissionState(NativeAPIPlugin.internet) != PermissionState.GRANTED) {
            Log.i("Blockguard", "connectVPN: Requesting internet permissions");
            requestPermissionForAlias(NativeAPIPlugin.internet, call, "internetPermissionCallback");
            return;
        }

        Log.d("Blockguard", "connectVPN: internet permission available");
        prepareVPNConnection(call);
    }

    @PluginMethod
    public void disconnectVPN(PluginCall call) {
        Log.d("Blockguard", "connectVPN: Initiated");
        if (getPermissionState(NativeAPIPlugin.internet) != PermissionState.GRANTED) {
            Log.i("Blockguard", "connectVPN: Requesting internet permissions");
            requestPermissionForAlias(NativeAPIPlugin.internet, call, "internetPermissionCallback");
            return;
        }

        Log.d("Blockguard", "disconnectVPN: internet permission available");
        disableVPNConnection(call);
    }


    @PluginMethod
    public VPNConnectionStatus getConnectionStatus(PluginCall call) throws ErrnoException {
        Log.d("Blockguard", "GetConnectionStatus");
        if (getPermissionState(NativeAPIPlugin.internet) != PermissionState.GRANTED) {
            Log.i("Blockguard", "GetConnectionStatus: Requesting internet permissions");
            requestPermissionForAlias(NativeAPIPlugin.internet, call, "internetPermissionCallback");

        }
        return vpnService.getConnectionStatus();
    }

    private void requestInternet(PluginCall call) {

        requestPermissionForAlias(NativeAPIPlugin.internet, call, "internetPermissionCallback");
    }

    @PermissionCallback
    private void internetPermissionCallback(PluginCall call) {
        if (getPermissionState(NativeAPIPlugin.internet) == PermissionState.GRANTED) {
            Log.w("Blockguard", "internetPermissionCallback: Request granted");
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

//
//    @PluginMethod()
//    public MTLSFetchResponse mtlsFetch(PluginCall call) {
//        Log.i("Blockguard", "mtlsFetch: Starting");
//
//        String method = call.getString("method");
//        String url = call.getString("url");
//        String body = call.getString("body");
//        String clientCertificate = call.getString("clientCertificate");
//        String privateKey = call.getString("privateKey");
//
//
//        if (clientCertificate == null || privateKey == null || method == null || url == null || body == null) {
//            call.reject("clientCertificate missing");
//            return new MTLSFetchResponse(false, -1, "input missing");
//        }
//        if (getPermissionState(NativeAPIPlugin.internet) != PermissionState.GRANTED) {
//            Log.i("Blockguard", "mtlsFetch: requestPermissions");
//            requestPermissions(call);
//        }
//        if (getPermissionState(NativeAPIPlugin.internet) != PermissionState.GRANTED) {
//            Log.i("Blockguard", "mtlsFetch: requestPermissions failed");
//            return new MTLSFetchResponse(false, 500, "no internet permission");
//        }
//        Log.i("Blockguard", method);
//        Log.i("Blockguard", url);
//        Log.i("Blockguard", body);
//        Log.i("Blockguard", clientCertificate);
//        Log.i("Blockguard", privateKey);
//        try {
//            return nativeAPI.mtlsFetch(method, url, body,1);
//        }
//        catch (Exception e){
//            throw new RuntimeException(e);
//        }
//
//
//    }
}