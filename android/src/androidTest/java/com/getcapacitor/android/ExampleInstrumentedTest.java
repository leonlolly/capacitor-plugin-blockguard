package com.getcapacitor.android;

import static org.junit.Assert.*;

import android.Manifest;
import android.content.Context;
import androidx.annotation.RequiresPermission;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.farsight.plugin.MTLSFetchResponse;
import com.farsight.plugin.NativeAPI;
import com.farsight.plugin.NativeAPIPlugin;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {

    @Test
    public void useAppContext() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        assertEquals("com.getcapacitor.android", appContext.getPackageName());
    }



    @RequiresPermission(Manifest.permission.INTERNET)
    @Test
    public void mtlsTest() throws Exception{

        NativeAPIPlugin plugin = new NativeAPIPlugin();

        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        // Replace with your actual values
        String url = "https://provider.dweb.computer:8443/lease/65048045/1/1/status";
        String url2 = "https://provider.europlots.com:8443/lease/79134340/1/1/status";
        String url3 = "https://provider.akashmining.com:8443/deployment/80172085/manifest";
        String method = "GET";
        String body = "";
        String clientCertificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBlzCCAT2gAwIBAgIGAY+Gj+mlMAoGCCqGSM49BAMCMDcxNTAzBgNVBAMTLGFrYXNoMWdlNmZmN3k3enQzeGd4cTI2ZGZhaGxtNDR1cXN6aHM0ODk0ano3MB4XDTI0MDUxNjIyMDAwMFoXDTI1MDUxNjIyMDAwMFowNzE1MDMGA1UEAxMsYWthc2gxZ2U2ZmY3eTd6dDN4Z3hxMjZkZmFobG00NHVxc3poczQ4OTRqejcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARtjkRxaYBdmYd6OAthRYWryZxF8FcOBvLfu0x8YqehpRGARbKTTVYa5edbRqHVz6p61FQ2O+tEH5y/+iR0T5/XozUwMzAOBgNVHQ8BAf8EBAMCADAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiAS/IGRPoxHShG5HCYhreyGINZqL6iHmSzav4Mp66hi7AIhAPBqRILOPo5Az8r0GnRLgCC7S9Xq4FLPHkyC+VL/sjkJ\n" +
                "-----END CERTIFICATE-----";
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXlSBIHAgs4BF8XvrWg8AryVE60xzZgDDnzyURWjh/VOhRANCAARtjkRxaYBdmYd6OAthRYWryZxF8FcOBvLfu0x8YqehpRGARbKTTVYa5edbRqHVz6p61FQ2O+tEH5y/+iR0T5/X\n" +
                "-----END PRIVATE KEY-----";

        String publicKey =  "-----BEGIN EC PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwX/Kimdew0w4Ryw0a4uYlBiuhdE5\n" +
                "D+R72wO/Zu/ySWdZLCE6zoUIZfwP46tBTFRGwfUwu1zDX6eQ8rFf8ul/gw==\n" +
                "-----END EC PUBLIC KEY-----";
        NativeAPI nativeAPI = new NativeAPI();
        MTLSFetchResponse response = nativeAPI.mtlsFetch(method, url3, body, clientCertificate, privateKey);

        assertNotNull(response);
        assertEquals(response.body,"");
        assertEquals(response.statusCode,200);
        assertEquals(response.success,true);
    }
}
