package com.zebra.basicintent1;


import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.text.format.Formatter;
import android.util.Log;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.RetryPolicy;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;

import org.apache.commons.codec.digest.DigestUtils;
import org.bitcoinj.core.Base58;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

public class DID {
    private final String api_key = "api-key=94F5BA49-12B6-4E45-A487-BF91C442276D";
    private final Context context;
    private String nonce = null;
    private String did_id = null;
    private String private_key = null;
    private String public_key = null;
    private String jwt = null;

    public DID(Context cont) {
        this.context = cont;
    }

    public void createDID(final VolleyCallBack callBack) {
        String postUrl = "https://ensuresec.solutions.iota.org/api/v0.1/identities/create?" + this.api_key;
        RequestQueue requestQueue = Volley.newRequestQueue(this.context);

        JSONObject postData = new JSONObject();
        WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        try {
            postData.put("username",  Build.USER)
                    .put("claim", new JSONObject().put("type", "Device").put("category", new JSONArray().put("actuator"))
                            .put("controlledProperty", new JSONArray().put("fillingLevel").put("temperature"))
                            .put("firmwareVersion", android.os.Build.VERSION.RELEASE)
                            .put("hardwareVersion", Build.BOARD)
                            .put("ipAddress", new JSONArray().put(Formatter.formatIpAddress(wm.getConnectionInfo().getIpAddress()))))
                    .toString();

        } catch (JSONException e) {
            e.printStackTrace();
        }

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, postData, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    did_id = response.getJSONObject("doc").getString("id");
                    private_key = response.getJSONObject("key").getString("secret");
                    public_key = response.getJSONObject("key").getString("public");
                    Log.i("DID_ID", did_id);
                    Log.i("PRIVATE_KEY", private_key);
                    Log.i("PUBLIC_KEY", public_key);
                    callBack.onSuccess();
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                error.printStackTrace();
            }
        }) {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("Accept", "application/json");
                params.put("Content-type", "application/json");
                return params;
            }
        };

        jsonObjectRequest.setRetryPolicy(new RetryPolicy() {
            @Override
            public int getCurrentTimeout() {
                return 20000;
            }

            @Override
            public int getCurrentRetryCount() {
                return 20000;
            }

            @Override
            public void retry(VolleyError error) throws VolleyError {

            }
        });
        requestQueue.add(jsonObjectRequest);
    }

    public void createNonce(final VolleyCallBack callBack) {
        String url = "https://ensuresec.solutions.iota.org/api/v0.1/authentication/prove-ownership/" + this.did_id + "?" + this.api_key;

        RequestQueue requestQueue = Volley.newRequestQueue(this.context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    nonce = response.getString("nonce");
                    Log.i("NONCE", nonce);
                    callBack.onSuccess();
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                error.printStackTrace();
            }
        });
        requestQueue.add(jsonObjectRequest);
    }


    public boolean signatureNonce(final VolleyCallBack callBack) throws CryptoException, InterruptedException {
        System.out.println("STO PER FIRMARE IL NONCE");
        byte[] b58key = Base58.decode(this.private_key);    // Decode a base58 key and encode it as hex key
        String b58key_hex = DatatypeConverter.printHexBinary(b58key).toLowerCase();
        byte[] convert_key = DatatypeConverter.parseHexBinary(b58key_hex);

        String hash_nonce_hex = DigestUtils.sha256Hex(nonce); // Hash a nonce with SHA-256 (apache_commons)
        byte[] convert_nonce = DatatypeConverter.parseHexBinary(hash_nonce_hex);

        //https://stackoverflow.com/questions/53921655/rebuild-of-ed25519-keys-with-bouncy-castle-java
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(convert_key, 0);  // Encode in PrivateKey
        Signer signer = new Ed25519Signer();    // Sign a nonce using the private key
        signer.init(true, privateKey);
        signer.update(convert_nonce, 0, convert_nonce.length);
        byte[] signature = signer.generateSignature();

        //https://stackoverflow.com/questions/6625776/java-security-invalidkeyexception-key-length-not-128-192-256-bits
        String sign = DatatypeConverter.printHexBinary(signature).toLowerCase();

        String postUrl = "https://ensuresec.solutions.iota.org/api/v0.1/authentication/prove-ownership/" + this.did_id + "?" + this.api_key;
        RequestQueue requestQueue = Volley.newRequestQueue(this.context);

        JSONObject postData = new JSONObject();
        try {
            postData.put("signedNonce", sign)
                    .toString();

        } catch (JSONException e) {
            e.printStackTrace();
        }

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, postData, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    jwt = response.getString("jwt");
                    Log.i("JWT", jwt);
                    callBack.onSuccess();
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                error.printStackTrace();
            }
        }) {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("Accept", "application/json");
                params.put("Content-type", "application/json");
                return params;
            }
        };

        jsonObjectRequest.setRetryPolicy(new RetryPolicy() {
            @Override
            public int getCurrentTimeout() {
                return 20000;
            }

            @Override
            public int getCurrentRetryCount() {
                return 20000;
            }

            @Override
            public void retry(VolleyError error) throws VolleyError {

            }
        });
        requestQueue.add(jsonObjectRequest);

        // Verify Signature
        byte[] b58key_primary = Base58.decode(public_key);
        String b58key_primary_hex = DatatypeConverter.printHexBinary(b58key_primary).toLowerCase();
        byte[] convert_primarykey = DatatypeConverter.parseHexBinary(b58key_primary_hex);

        Ed25519PublicKeyParameters primaryKeyVerify = new Ed25519PublicKeyParameters(convert_primarykey, 0);
        Signer verifier = new Ed25519Signer();
        verifier.init(false, primaryKeyVerify);
        verifier.update(convert_nonce, 0, convert_nonce.length);

        return verifier.verifySignature(signature);
    }

    public void storeData() {
        JSONObject data = new JSONObject();
        try {
            data.put("ID", this.did_id);
            data.put("PrivateKey", this.private_key);
            data.put("PublicKey", this.public_key);
            data.put("JWT", this.jwt);
            File.createTempFile("key.json", null, this.context.getCacheDir());
        } catch (JSONException | IOException e) {
            e.printStackTrace();
        }
        try (FileOutputStream fos = this.context.openFileOutput("key.json", Context.MODE_PRIVATE)) {
            fos.write(data.toString().getBytes(StandardCharsets.UTF_8));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("DATI SALVATI CORRETTAMENTE");
    }

}
