package com.getcapacitor.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.Manifest;
import android.content.Context;

import androidx.annotation.RequiresPermission;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.farsight.plugin.MTLSFetchResponse;
import com.farsight.plugin.NativeAPI;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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



        // Replace with your actual values
        String url = "https://certauth.cryptomix.com/";
        String method = "GET";
        String body = "";
        String clientCertificate = """
-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgYBj78SJ6IwCgYIKoZIzj0EAwIwDjEMMAoGA1UEAxMDbG9s
MB4XDTI0MDUyNzIyMDAwMFoXDTI1MDUyNzIyMDAwMFowDjEMMAoGA1UEAxMDbG9s
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEznNZhaNo9Iqs8ePfw5x1ON0JBSW7
qIEhCV4205FaP0X22Ucb4JEnocwOFO7y62taELR1M3/zuurxTD92D9ajK6M1MDMw
DgYDVR0PAQH/BAQDAgAwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQC
MAAwCgYIKoZIzj0EAwIDRwAwRAIgE3aNari5ksgMS8ViZbL+n2LYC3H8CQiC6xZr
sUSvdpsCIC/+VYuADvLElkAnqJHcN6WTKCgolMi+LEiJ1ejKHhhJ
-----END CERTIFICATE-----
                """;
        String privateKey = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgx3A0EQhDNp1cz348
dMDil55aS4OJJWHF3z0iGIHsBMGhRANCAATOc1mFo2j0iqzx49/DnHU43QkFJbuo
gSEJXjbTkVo/RfbZRxvgkSehzA4U7vLra1oQtHUzf/O66vFMP3YP1qMr
-----END PRIVATE KEY-----
                """;

        String publicKey = """
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEznNZhaNo9Iqs8ePfw5x1ON0JBSW7
qIEhCV4205FaP0X22Ucb4JEnocwOFO7y62taELR1M3/zuurxTD92D9ajKw==
-----END EC PUBLIC KEY-----
                """;

        NativeAPI nativeAPI = new NativeAPI();


        String publicKeyContent = publicKey
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END EC PUBLIC KEY-----", "");

        byte[] publicKeyAsBytes = Base64.getDecoder().decode(publicKeyContent);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyAsBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey generatedPublic = keyFactory.generatePublic(keySpec);


        nativeAPI.storePrivateKeyWithCertificate(privateKey,clientCertificate);
        //assertTrue(nativeAPI.validatePrivateKey(generatedPublic));
        //assertTrue(nativeAPI.validateCertificate(generatedPublic));
        //assertTrue(nativeAPI.validatePublicKey());


        MTLSFetchResponse response = nativeAPI.mtlsFetch(method, url, body);

        assertNotNull(response);
        assertEquals(response.statusCode,200);
    }



}
