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
        String method = "GET";
        String body = "";
        String clientCertificate = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBRTCB66ADAgECAgYBj4bq2l0wCgYIKoZIzj0EAwIwDjEMMAoGA1UEAxMDbG9s\n" +
                "MB4XDTI0MDUxNjIyMDAwMFoXDTI1MDUxNjIyMDAwMFowDjEMMAoGA1UEAxMDbG9s\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwX/Kimdew0w4Ryw0a4uYlBiuhdE5\n" +
                "D+R72wO/Zu/ySWdZLCE6zoUIZfwP46tBTFRGwfUwu1zDX6eQ8rFf8ul/g6M1MDMw\n" +
                "DgYDVR0PAQH/BAQDAgAwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQC\n" +
                "MAAwCgYIKoZIzj0EAwIDSQAwRgIhAIINFT3GX6AaefE+mQTwbufT83BewE//QjHp\n" +
                "RgEjSVbyAiEA4+eX26z6sNX/QlNjgvhDxJxrC2A59BW7fT5c2lrttx4=\n" +
                "-----END CERTIFICATE-----";
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3KjtTAcag02TBPWu\n" +
                "gX1aJXsUqPsz6ggoMi8OQtMy0IShRANCAATBf8qKZ17DTDhHLDRri5iUGK6F0TkP\n" +
                "5HvbA79m7/JJZ1ksITrOhQhl/A/jq0FMVEbB9TC7XMNfp5DysV/y6X+D\n" +
                "-----END PRIVATE KEY-----";

        String publicKey =  "-----BEGIN EC PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwX/Kimdew0w4Ryw0a4uYlBiuhdE5\n" +
                "D+R72wO/Zu/ySWdZLCE6zoUIZfwP46tBTFRGwfUwu1zDX6eQ8rFf8ul/gw==\n" +
                "-----END EC PUBLIC KEY-----";
        NativeAPI nativeAPI = new NativeAPI();
        MTLSFetchResponse response = nativeAPI.mtlsFetch(method, url, body, clientCertificate, privateKey);

        assertNotNull(response);
        assertEquals(response.statusCode,200);
    }
}
