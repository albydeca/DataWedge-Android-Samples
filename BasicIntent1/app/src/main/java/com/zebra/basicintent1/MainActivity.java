// **********************************************************************************************
// *                                                                                            *
// *    This application is intended for demonstration purposes only. It is provided as-is      *
// *    without guarantee or warranty and may be modified to suit individual needs.             *
// *                                                                                            *
// **********************************************************************************************

package com.zebra.basicintent1;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.DialogInterface;
import android.os.StrictMode;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.ImageView;
import android.app.AlertDialog;

import java.io.File;
import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import com.zebra.utils.X509Importer;

import org.bouncycastle.crypto.CryptoException;
import org.json.JSONException;

import se.digg.dgc.payload.v1.DGCSchemaException;
import se.digg.dgc.service.impl.DefaultDGCDecoder;
import se.digg.dgc.signatures.impl.DefaultDGCSignatureVerifier;
import se.digg.dgc.payload.v1.DigitalCovidCertificate;

public class MainActivity extends AppCompatActivity {
    private boolean canScan;
    private boolean validCert;
    //
    // The section snippet below registers to receive the data broadcast from the
    // DataWedge intent output. In the example, a dynamic broadcast receiver is
    // registered in the onCreate() call of the target app. Notice that the filtered action
    // matches the "Intent action" specified in the DataWedge Intent Output configuration.
    //
    // For a production app, a more efficient way to the register and unregister the receiver
    // might be to use the onResume() and onPause() calls.

    // Note: If DataWedge had been configured to start an activity (instead of a broadcast),
    // the intent could be handled in the app's manifest by calling getIntent() in onCreate().
    // If configured as startService, then a service must be created to receive the intent.
    //
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final TextView birth = (TextView) findViewById(R.id.birth);
        final TextView name_surname = (TextView) findViewById(R.id.lblScanData);
        final TextView source = (TextView) findViewById(R.id.lblScanSource);
        birth.setVisibility(View.INVISIBLE);
        source.setVisibility(View.INVISIBLE);
        name_surname.setText("Waiting for scan...");

        IntentFilter filter = new IntentFilter();
        filter.addCategory(Intent.CATEGORY_DEFAULT);
        filter.addAction(getResources().getString(R.string.activity_intent_filter_action));
        registerReceiver(myBroadcastReceiver, filter);
        this.canScan = true;
        this.validCert = false;
        final ImageView resultImage = (ImageView) findViewById(R.id.outcomeImage);
        final TextView lblInfoData = (TextView) findViewById(R.id.info_lbl);
        lblInfoData.setVisibility(View.INVISIBLE);
        resultImage.setImageResource(R.drawable.logo);

        if(!control()) {
            Log.i("DID", "Sto creando il DID");
            DID test = new DID(MainActivity.this);
            test.createDID(new VolleyCallBack() {
                @Override
                public void onSuccess() {
                    System.out.println("DOCUMENTO DID CREATO");
                    test.createNonce(new VolleyCallBack() {
                        @Override
                        public void onSuccess() {
                            try {
                                test.signatureNonce(new VolleyCallBack() {
                                    @Override
                                    public void onSuccess() {
                                        test.storeData();
                                    }
                                });
                            } catch (CryptoException e) {
                                e.printStackTrace();
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        else {
            Log.i("DID", "Creato già in precedenza");
        }

    }

    @Override
    protected void onDestroy()
    {
        super.onDestroy();
        unregisterReceiver(myBroadcastReceiver);
    }

    //
    // After registering the broadcast receiver, the next step (below) is to define it.
    // Here it's done in the MainActivity.java, but also can be handled by a separate class.
    // The logic of extracting the scanned data and displaying it on the screen
    // is executed in its own method (later in the code). Note the use of the
    // extra keys defined in the strings.xml file.
    //
    private BroadcastReceiver myBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Bundle b = intent.getExtras();
            X509Certificate decoding_cert = null;
            File file = new File(context.getFilesDir(), "certfile");
            if(file.exists())
                Log.i("CERTFILE", "ESISTE");
            else {
                Log.i("CERTFILE", "NON ESISTE");
            }
            try {
                decoding_cert = X509Importer.importX509FromFile
                        (new File(context.getFilesDir(), "certfile"));
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            //  This is useful for debugging to verify the format of received intents from DataWedge
            //for (String key : b.keySet())
            //{
            //    Log.v(LOG_TAG, key);
            //}

            if (action.equals(getResources().getString(R.string.activity_intent_filter_action))) {
                //  Received a barcode scan
                try {
                    displayScanResult(intent, "via Broadcast", decoding_cert);
                } catch (Exception e) {
                    //  Catch if the UI does not exist when we receive the broadcast
                    e.printStackTrace();
                }
            }
        }
    };

    //
    // The section below assumes that a UI exists in which to place the data. A production
    // application would be driving much of the behavior following a scan.
    //

    @Override
    public void onBackPressed() {
        AlertDialog.Builder ab = new AlertDialog.Builder(MainActivity.this);
        ab.setTitle("Exit");
        ab.setMessage("Are you sure you want to exit?");
        ab.setPositiveButton("yes", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
                //if you want to kill app . from other then your main avtivity.(Launcher)
                android.os.Process.killProcess(android.os.Process.myPid());
                System.exit(1);

                //if you want to finish just current activity

                MainActivity.this.finish();
            }
        });
        ab.setNegativeButton("no", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });

        ab.show();
    }

    private void displayScanResult(Intent initiatingIntent, String howDataReceived,
                                   X509Certificate decoding_cert) throws IOException, JSONException {
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();

        StrictMode.setThreadPolicy(policy);
        if (this.canScan) {
            String decodedSource = initiatingIntent.getStringExtra(getResources().getString(R.string.datawedge_intent_key_source));
            String decodedData = initiatingIntent.getStringExtra(getResources().getString(R.string.datawedge_intent_key_data));
//        String decodedLabelType = initiatingIntent.getStringExtra(getResources().getString(R.string.datawedge_intent_key_label_type));
            final TextView lblInfoData = (TextView) findViewById(R.id.info_lbl);
            lblInfoData.setVisibility(View.VISIBLE);

            final TextView lblScanSource = (TextView) findViewById(R.id.lblScanSource);
            final TextView name_surname = (TextView) findViewById(R.id.lblScanData);
            final ImageView resultImage = (ImageView) findViewById(R.id.outcomeImage);
            final TextView text = (TextView) findViewById(R.id.textView);
//        final TextView lblScanLabelType = (TextView) findViewById(R.id.lblScanDecoder);

            final TextView birth = (TextView) findViewById(R.id.birth);
            text.setVisibility(View.VISIBLE);
            lblScanSource.setVisibility(View.VISIBLE);
            lblScanSource.setText(decodedSource + " " + howDataReceived);

            DefaultDGCDecoder dgcd = new DefaultDGCDecoder
                    (new DefaultDGCSignatureVerifier(), (x, y) -> Arrays.asList(decoding_cert));
            DigitalCovidCertificate dgc = null;
            try {
                dgc = dgcd.decode(decodedData);

                birth.setVisibility(View.VISIBLE);
                name_surname.setVisibility(View.VISIBLE);
                birth.setText(dgc.getDateOfBirth().toString());
                name_surname.setText(dgc.getNam().getFn() + " " + dgc.getNam().getGn());

                resultImage.setImageResource(R.drawable.checked);
                this.validCert = true;
            } catch (DGCSchemaException | CertificateExpiredException | SignatureException | IOException e) {
                name_surname.setVisibility(View.VISIBLE);
                name_surname.setText(e.getMessage());
                resultImage.setImageResource(R.drawable.check_failed);
                this.validCert = false;

            } catch (IllegalArgumentException e) {
                e.printStackTrace();
                name_surname.setVisibility(View.VISIBLE);
                name_surname.setText(R.string.not_eu_cert);
                resultImage.setImageResource(R.drawable.check_failed);
                this.validCert = false;
            }


//        lblScanLabelType.setText(decodedLabelType);
            this.canScan = false;
        }

    }

    public void clearButtonClicked(View view) {
        // Do something in response to button
        final TextView lblScanSource = (TextView) findViewById(R.id.lblScanSource);
        final TextView lblScanData = (TextView) findViewById(R.id.lblScanData);
        final ImageView resultImage = (ImageView) findViewById(R.id.outcomeImage);
        final TextView birth = (TextView) findViewById(R.id.birth);
        final TextView lblInfoData = (TextView) findViewById(R.id.info_lbl);
        final TextView name_surname = (TextView) findViewById(R.id.lblScanData);

        lblInfoData.setVisibility(View.INVISIBLE);
        lblScanSource.setVisibility(View.INVISIBLE);
        birth.setVisibility(View.INVISIBLE);
        name_surname.setVisibility(View.INVISIBLE);
        lblScanData.setVisibility(View.VISIBLE);

        lblScanData.setText(R.string.input_wait);
        resultImage.setImageResource(R.drawable.logo);


        this.canScan = true;
        this.validCert = false;


    }

    public void whatDoesThisMeanLblClicked(View view) {
        AlertDialog.Builder alert = new AlertDialog.Builder(this);
        alert.setTitle(R.string.result_info);
        if(this.validCert) {
            alert.setMessage(R.string.info_green_message);
        } else {
            alert.setMessage(R.string.info_red_message);
        }
        alert.setNegativeButton("Cancel",
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                    }
                });

        alert.show();
    }

    public boolean control() {
        File f = getFileStreamPath("key.json");
        if (f.length() == 0) {
            return false;
        } else {
            return true;
        }
    }
}
