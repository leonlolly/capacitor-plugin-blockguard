package com.getcapacitor.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.Manifest;
import android.content.Context;

import androidx.annotation.RequiresPermission;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.farsight.plugin.MTLSFetchResponse;
import com.farsight.plugin.NativeAPI;
import com.farsight.plugin.RawMtlsClient;

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
        String url = "https://provider.dweb.computer:8443/deployment/84347571/manifest/";
        String method = "GET";
        String body = "";
        String clientCertificate = """
-----BEGIN CERTIFICATE-----
MIIFqTCCA5GgAwIBAgIQUcphQ8VywwU3z0o83F1mOjANBgkqhkiG9w0BAQsFADCB
gTELMAkGA1UEBhMCSVQxEDAOBgNVBAgMB0JlcmdhbW8xGTAXBgNVBAcMEFBvbnRl
IFNhbiBQaWV0cm8xFzAVBgNVBAoMDkFjdGFsaXMgUy5wLkEuMSwwKgYDVQQDDCNB
Y3RhbGlzIENsaWVudCBBdXRoZW50aWNhdGlvbiBDQSBHMzAeFw0yNDA0MjMxMDM4
MjlaFw0yNTA0MjMxMDM4MjlaMBwxGjAYBgNVBAMMEUxlb25Ad2VuZGVyb3RoLmRl
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtbdYSuatqc4epFeuzz08
Y3b+LMGPJSEChv1uc/a39oozXG4fSvQVaOzdWhe6ntxwWr2/454cWSpPuIeVKyJJ
WLN6YffoQBcTrGgODpFXcXzckwsE3i+kSbasQKuqCsLIl/NtfXdZAgvxow+YCpYf
V45SdsYrQF5JQ8Ks+gVeNhZi+jGdnnu6V1IZ/rtQsgyzFyM2EVcibszyE9Rq903p
c0jDIFT5/8LLf3iEwQRj+a+34tWg/IOzMFk37oP4PwPbgyDi+9dh1LHKHyg6cbh7
K/98TqOBj+vwN+8mGfdHCGs2DoqWRtqca8GB4U965JdCugiO/pdyaayvht54zh9n
5QIDAQABo4IBfzCCAXswDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBS+l6mqhL+A
vxBTfQky+eEuMhvPdzB+BggrBgEFBQcBAQRyMHAwOwYIKwYBBQUHMAKGL2h0dHA6
Ly9jYWNlcnQuYWN0YWxpcy5pdC9jZXJ0cy9hY3RhbGlzLWF1dGNsaWczMDEGCCsG
AQUFBzABhiVodHRwOi8vb2NzcDA5LmFjdGFsaXMuaXQvVkEvQVVUSENMLUczMBwG
A1UdEQQVMBOBEUxlb25Ad2VuZGVyb3RoLmRlMBQGA1UdIAQNMAswCQYHZ4EMAQUB
ATAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwSAYDVR0fBEEwPzA9oDug
OYY3aHR0cDovL2NybDA5LmFjdGFsaXMuaXQvUmVwb3NpdG9yeS9BVVRIQ0wtRzMv
Z2V0TGFzdENSTDAdBgNVHQ4EFgQULbYNtiioNL8RE7pYmMoy1kFxCykwDgYDVR0P
AQH/BAQDAgWgMA0GCSqGSIb3DQEBCwUAA4ICAQBF3Nn0vT5h9mQ5TF9uDchfQCVO
e5GKlNOXPwxlkm3hlNYgvePtRdmSE00JsNv/nb4dWaFqHxw6d+nMwVWP06sbogU+
79lq8GDrGKWG4kxuhvI0WP7DB8OFLI5xN/i3StMGrG9jLJYu2pwSpH5e0OYNF8u4
cV1RDJR+Jp4qyYpU2sqUfuHJPRr6xQYTMHd11OJKHPm17lsICVxzf8o/W1wH8zUu
rM82dcyZlIOPtPTnlawhMSgXbDJkouI44zQQxUXg+8BBxagt8nrHsOFsAS3kpkE7
zbZsqL4ecXnVbY+2c5wyL/8fplWKwCBOj01MPgY35dpekNZNWrC6AVciGlwclyQo
uk5dBxP8Ggg6sm8GaZttiKfQ2Y3XnWKqgTRYDptAomcvuVe8YLg0f1hLhUFNw6Pf
9d+xGgNjKxrYVvsdM2z+Ubh3mIvdrIeV/Y2GTrj7jiADpo5f0XViSyhA0ZGb1tPv
f4kRmGDQjkbi0WEtVPnWhrdTBB2SODo+4eZAQLCVfhTj/zzhXDvjTVCGnfqSK6A2
/LngWY5jfIHR/4T7mcdO6qF1rYc+pz/DGkoUaYRGpBRxxnam/J4KhDwQTvhDoAY9
OdtoInxYBp7HWmkL01ITdQtqXCw+eE77ICho9Zqi16kKOQhKYOK6h0xSOtSGxU1/
ALxhPm/QSbUcPfg/1g==
-----END CERTIFICATE-----
                """;
        String privateKey = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1t1hK5q2pzh6k
V67PPTxjdv4swY8lIQKG/W5z9rf2ijNcbh9K9BVo7N1aF7qe3HBavb/jnhxZKk+4
h5UrIklYs3ph9+hAFxOsaA4OkVdxfNyTCwTeL6RJtqxAq6oKwsiX8219d1kCC/Gj
D5gKlh9XjlJ2xitAXklDwqz6BV42FmL6MZ2ee7pXUhn+u1CyDLMXIzYRVyJuzPIT
1Gr3TelzSMMgVPn/wst/eITBBGP5r7fi1aD8g7MwWTfug/g/A9uDIOL712HUscof
KDpxuHsr/3xOo4GP6/A37yYZ90cIazYOipZG2pxrwYHhT3rkl0K6CI7+l3JprK+G
3njOH2flAgMBAAECggEAArLUlZYr5Y3pUBT6RFsbMrnxZ94+/zToifMpCQFUtY1T
Wm/LOKx7xelglyYrkBDjfUF8oEd4kc1qTin7Sd7yOmY97scE9LCzCtgnv0kixI1v
ZCKhgaAw/yQ+lh5Gge7nFjSX/2k+keR2A+8nGZ8lm4ICUP+75DKSQXaaZYMfZUu0
4M4gKefdKTTB2JKOIokW6acq0ZxOrc+Y8HqgQd7PyJa7hCW4PjQzUMKgqrFfE/5+
HIGS2JJcUA8FN0rY41GomTvhZXIrkaTHDtKXWg/A5VEr97VQJ3ijLNsNIMspsiRn
4MMm7J1afJR5bIqrh4DkBT7d1u+dnEVZ/XgXrsjgCQKBgQDtDZAlS3cTaNC8Q6Hk
UiKcZkYL1GT70uvc3T5/iauX85fgEixC8M4bF+rhHcDG5/cKIOCxgnMYppQRdFf/
7onUwAJ5kHfDXEoAeC4GJNMOfMyA7Ps0E8+eWj3FjyASNVxhpk/gu0kAoMuS1jOD
g3ljwiluK18qlaDe9kQGwGmYzQKBgQDEPYNtIxKTUSpabARkQy83C9p57kPQK58g
X0X10bOBufMDTxEi7GGlkIlApt7uUSkIgWYDoGnvUqRlU434I53jBH0i59aB6gL9
54N2nG/bzHG0/C7hwy9qyl2rjGh4irI8U/e3pSRKVbj5XQUx7M9ZLbE0vHqeh1C6
MC3FiLrreQKBgC5Zbou8O6YR4m5NEwRfguDtplh9yNjsHq3qnGO3eVOWj2WCaCEW
kFX/0S7+8Ehz5nuWfhh3FyYEvALFqschztVITbOTKbeK/fUlimotHQ9CG4JB08QU
841Uu6s7Ftw4jr2RFSEtvVJgHi2xsBTQyhVVS2B9HnhnFTNDF33ydTMpAoGBAJfw
YK/BdgJl13sHIydV9VqTbOb3Gb416BCyc4JuiKOqi4NGVqhJiRkdnYdXLEgswq55
MbkhHKRVwj9JwCQdv4Mj2JeMFUOlIgfglqLhYKI32tocX1ghPbdbU8cdAU5DZNjc
0nF4BW8gjAVWhk0vYyNTA18nh3DyqAhggS/uO3tRAoGBAKF8EcWsIMGLWECdSgvg
VRN/JdgPbeiuO50Q5Gzv0u7wD5u2VdDRZd2s4TC+KzRj3OXER2cj9bCLthjnVzhJ
uXHjy2I4H/76Maf472Fr6uGzFcPiBV6sdLQQZbXlv9aFHxrztEsxe28bE3M1ikRp
LvYfFtlTfKQvcXKpiD8kbYjP
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

        RawMtlsClient client = new RawMtlsClient();
        //client.sendTLSRequest("PUT","https://certauth.cryptomix.com/","");

        //nativeAPI.storePrivateKeyWithCertificate(privateKey,clientCertificate);
        //assertTrue(nativeAPI.validatePrivateKey(generatedPublic));
        //assertTrue(nativeAPI.validateCertificate(generatedPublic));
        //assertTrue(nativeAPI.validatePublicKey());

        MTLSFetchResponse response = nativeAPI.mtlsFetch(method, url, body,privateKey,clientCertificate,1);
        assertFalse(response.success);
//        for (int i = 57578; i < 65535; i++) { //57578
//            MTLSFetchResponse response = nativeAPI.mtlsFetch(method, url, body,privateKey,clientCertificate,i);
//            assertFalse(response.success);
//        }

    }



}
