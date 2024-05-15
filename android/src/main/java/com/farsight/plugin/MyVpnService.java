package com.farsight.plugin;

import android.content.Context;
import android.content.Intent;
import android.net.TrafficStats;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

public class MyVpnService extends VpnService {
    private DatagramSocket tunnelSocket;
    private ParcelFileDescriptor vpnInterface;
    private static final String TAG = "MyVpnService";
    private VPNConnectionStatus status;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Step 1: Call VpnService.prepare() to ask for permission (when needed).
        Context context = getApplicationContext();
        if (prepare(context) != null) {
            // Caller should make sure that it is prepared
            stopService(intent);
            return START_NOT_STICKY;
        }

        // Step 2: Call VpnService.protect() to keep your app's tunnel socket outside of the system VPN and avoid a circular connection.
        tunnelSocket = createGatewaySocket();
        protect(tunnelSocket);

        // Step 3: Connect your tunnel socket to the VPN gateway
        try {
            // Replace with your actual VPN gateway address and port
            InetAddress gatewayAddress = InetAddress.getByName("your_vpn_gateway_address");
            int gatewayPort = 1;
            tunnelSocket.connect(new InetSocketAddress(gatewayAddress, gatewayPort));
        } catch (IOException e) {
            Log.e(TAG, "Failed to connect to VPN gateway", e);
            return START_NOT_STICKY;
        }

        // Step 4: Call VpnService.Builder methods to configure a new local TUN interface on the device for VPN traffic.
        // You can get IPs from the VPN gateway or define static addresses here
        Builder builder = new Builder();
        builder.setSession("MyVPNService")
                .addAddress("10.0.0.2", 32) // Local IP address
                .addRoute("0.0.0.0", 0);  // Default route

        // Step 5: Call VpnService.Builder.establish() to establish the local TUN interface and start routing traffic
        vpnInterface = builder.establish();

        // Notify plugin of service status change (implementation depends on your plugin)
        notifyPluginOfStatusChange(true); // Example function call (replace with your implementation)
        updateTrafficStats();
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing VPN interface", e);
            } finally {
                vpnInterface = null;
            }
        }
        if (tunnelSocket != null) {
            try {
                tunnelSocket.close();
            } catch (Exception ex) {
                Log.e(TAG, "Error closing tunnel socket", ex);
            } finally {
                tunnelSocket = null;
            }
        }

        // Notify plugin of service status change (implementation depends on your plugin)
        notifyPluginOfStatusChange(false); // Example function call (replace with your implementation)

        this.status = new VPNConnectionStatus();
        super.onRevoke();
    }

    public void updateTrafficStats() {
        long currentTotalRxBytes = TrafficStats.getTotalRxBytes();
        long currentTotalTxBytes = TrafficStats.getTotalTxBytes();

        // Calculate bytes transferred since last measurement
        this.status.incomingBytes  = currentTotalRxBytes - this.status.incomingBytes;
        this.status.outgoingBytes  = currentTotalTxBytes - this.status.outgoingBytes;
    }

    public VPNConnectionStatus getConnectionStatus() {
        return status;
    }

    private DatagramSocket createGatewaySocket() {
        DatagramSocket tunnel = null;
        try {
            tunnel = new DatagramSocket();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return tunnel;
    }

    // Function to notify plugin of service status change (implementation specific to your plugin)
    private void notifyPluginOfStatusChange(boolean isConnected) {
        // Implement  logic to send notification to your plugin based on connection status
        Log.d(TAG, "VPN service connection status: " + isConnected);
    }
}
