package com.zebra.basicintent1;


import android.content.Context;
import android.util.Log;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.RetryPolicy;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class LogAuditor {
    private final String api_key = "api-key=94F5BA49-12B6-4E45-A487-BF91C442276D";
    private final Context context;
    private String jwt = null;
    private String private_key = null;
    private String public_key = null;
    private String did_id = null;
    private String channel_address = "0c8408d166f6974d7e637dcafd0e5c1964a2e219b659e2d8963471721744b1370000000000000000:0dff2fa9963eebe2ac1b482b";
    private String subscriptionLink = null;

    public LogAuditor(Context context) {
        this.context = context;
        FileInputStream fis = null;
        try {
            fis = this.context.openFileInput("key.json");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        InputStreamReader inputStreamReader = new InputStreamReader(fis, StandardCharsets.UTF_8);
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(inputStreamReader)) {
            String line = reader.readLine();
            while (line != null) {
                stringBuilder.append(line).append('\n');
                line = reader.readLine();
            }
        } catch (IOException e) {
            // Error occurred when opening raw file for reading.
        } finally {
            String contents = stringBuilder.toString();
            try {
                JSONObject data = new JSONObject(contents);
                did_id = data.getString("ID");
                private_key = data.getString("PrivateKey");
                public_key = data.getString("PublicKey");
                jwt = data.getString("JWT");
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
    }

    public void requestSubscription(final VolleyCallBack callBack) {
        String postUrl = "https://ensuresec.solutions.iota.org/api/v0.1/subscriptions/request/" + this.channel_address + "?" + this.api_key;
        RequestQueue requestQueue = Volley.newRequestQueue(this.context);

        JSONObject postData = new JSONObject();
        try {
            postData.put("accessRights", "Read").toString();
        } catch (JSONException e) {
            e.printStackTrace();
        }

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, postData, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    subscriptionLink = response.getString("subscriptionLink");
                    Log.i("SUBSCRIPTIONLINK", subscriptionLink);
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
                params.put("Authorization:", "Bearer " + jwt);
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

    public void getDataFromChannel() {
        String url = "https://ensuresec.solutions.iota.org/api/v0.1/channels/logs/" + this.channel_address + "?limit=5&asc=true" + "&" + this.api_key;

        RequestQueue requestQueue = Volley.newRequestQueue(this.context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    JSONArray respons = new JSONArray(response);
                    System.out.println(respons);
                    System.out.println("Message from channel: " + respons.getJSONObject(0).getJSONObject("channelLog").getJSONObject("payload"));
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                error.printStackTrace();
            }
        })
        {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("Accept", "application/json");
                params.put("Authorization:", "Bearer " + jwt);
                return params;
            }
        };

        requestQueue.add(jsonObjectRequest);
    }

    public void getCertIDFromChannel() {
        String url = "https://ensuresec.solutions.iota.org/api/v0.1/channels/logs/" + this.channel_address + "?limit=5&asc=true" + "&" + this.api_key;

        RequestQueue requestQueue = Volley.newRequestQueue(this.context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    JSONArray respons = new JSONArray(response);
                    System.out.println(respons);
                    System.out.println("Message from channel: " + respons.getJSONObject(0).getJSONObject("channelLog").getJSONObject("payload"));
                    String base64String = respons.getJSONObject(0).getJSONObject("channelLog").getString("payload");
                    byte[] backToBytes = Base64.decodeBase64(base64String);
                    storeCertID(backToBytes);
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                error.printStackTrace();
            }
        })
        {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("Accept", "application/json");
                params.put("Authorization:", "Bearer " + jwt);
                return params;
            }
        };

        requestQueue.add(jsonObjectRequest);
    }

    public void storeCertID(byte[] cert){
        try {
            File.createTempFile("certfile", null, this.context.getCacheDir());
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (FileOutputStream fos = this.context.openFileOutput("certfile", Context.MODE_PRIVATE)) {
            fos.write(cert);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
