package com.zebra.basicintent1;


import android.content.Context;
import android.util.Log;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.RetryPolicy;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonArrayRequest;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;

import net.minidev.json.parser.JSONParser;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.util.EntityUtils;
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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

public class LogAuditor {
    private final String api_key = "api-key=94F5BA49-12B6-4E45-A487-BF91C442276D";
    private final Context context;
    private String jwt = null;
    private String private_key = null;
    private String public_key = null;
    private String did_id = null;
    private String channel_address = "364fa8eb955770c7612f13989a28e9702d74a1b80f2bfdc9e670dd4459daf4e70000000000000000:d5f9c971685e9a041b691fb0";
    private String subscriptionLink = null;
    private String channel_created = null;

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

    public void requestSubscription() {
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
                params.put("Authorization", "Bearer " + jwt);
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

    public void getCertIDFromChannel(final VolleyCallBack callBack) {
        channelInfo(new VolleyCallBack() {
            @Override
            public void onSuccess() {
                //String startDate = "2021-10-10T00:22:19+02:00";

                //Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone(channel_created)); // this would default to now
                //calendar.add(Calendar.MINUTE, 50);
                //String endDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX").format(calendar.getTime());
                //String endDate = "2021-10-10T03:22:19+02:00";
                //Log.i("CHANNEL CREATED ", startDate);
                //Log.i("CHANNEL CREATED AFTER", endDate);
                //String startDateQuery = startDate.replaceAll(":", "%3A").replaceAll("\\+", "%2B");
                //String endDateQuery = endDate.replaceAll(":", "%3A").replaceAll("\\+", "%2B");
                //String url_filter = "https://ensuresec.solutions.iota.org/api/v0.1/channels/logs/" + channel_address + "?limit=5&asc=true"  + "&start-date=" + startDate + "&end-date=" + endDate + "&" + api_key;
                String url = "https://ensuresec.solutions.iota.org/api/v0.1/channels/logs/" + channel_address + "?limit=5&asc=true" + "&" + api_key;

                RequestQueue requestQueue = Volley.newRequestQueue(context);
                JsonArrayRequest jsonObjectRequest = new JsonArrayRequest(Request.Method.GET, url, null, new Response.Listener<JSONArray>() {
                    @Override
                    public void onResponse(JSONArray response) {
                        try {
                            System.out.println(response);
                            System.out.println("Message from channel: " + response.getJSONObject(0).getJSONObject("log").getJSONObject("payload"));
                            String base64String = response.getJSONObject(0).getJSONObject("log").getString("payload");
                            JSONObject certID = new JSONObject(base64String);
                            Log.i("CERTIFICATO", certID.getString("cert"));
                            byte[] backToBytes = Base64.decodeBase64(certID.getString("cert"));
                            storeCertID(backToBytes);
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
                })
                {
                    @Override
                    public Map<String, String> getHeaders() throws AuthFailureError {
                        Map<String, String> params = new HashMap<String, String>();
                        params.put("Accept", "application/json");
                        params.put("Authorization", "Bearer " + jwt);
                        return params;
                    }
                };

                requestQueue.add(jsonObjectRequest);
            }
        });
    }

    public void channelInfo(final VolleyCallBack callBack) {
        String url = "https://ensuresec.solutions.iota.org/api/v0.1/channel-info/channel/" + this.channel_address + "?" + this.api_key;

        RequestQueue requestQueue = Volley.newRequestQueue(this.context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
            @Override
            public void onResponse(JSONObject response) {
                try {
                    channel_created = response.getString("created");
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
        })
        {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("Accept", "application/json");
                return params;
            }
        };

        requestQueue.add(jsonObjectRequest);
    }

    public void storeCertID(byte[] cert){
        Log.i("STORECERT", "SONO DENTRO");
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
