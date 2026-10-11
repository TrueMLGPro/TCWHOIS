package thecollectiveweb.com.domaincheck;

import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import thecollectiveweb.com.tcwhois.TCWHOIS;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private String tldCode = "in";

    private TextView resultTextView;
    private RelativeLayout parentLayout;
    private Spinner tldSpinner;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final String[] tlds = {"ac", "ad", "ae", "aer", "af", "ag", "ai", "al", "am", "as", "asi", "at", "au", "aw", "ax", "az", "ba", "bar", "be", "ber", "bes", "bg", "bi", "biz", "bj", "bo", "br", "br.", "bt", "bw", "by", "bz", "bzh", "ca", "cat", "cc", "cd", "ceo", "cf", "ch", "ci", "ck", "cl", "clo", "clu", "cn", "cn.", "co", "co.", "com", "coo", "cx", "cy", "cz", "de", "dk", "dm", "dz", "ec", "edu", "ee", "eg", "es", "eu", "eu.", "eus", "fi", "fo", "fr", "gb", "gb.", "gb.", "qc.", "ge", "gg", "gi", "gl", "gm", "gov", "gr", "gs", "gy", "ham", "hip", "hk", "hm", "hn", "hos", "hr", "ht", "hu", "hu.", "id", "ie", "il", "im", "in", "inf", "ing", "ink", "int", "io", "iq", "ir", "is", "it", "je", "job", "jp", "ke", "kg", "ki", "kr", "kz", "la", "li", "lon", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg", "mil", "mk", "ml", "mo", "mob", "ms", "mt", "mu", "mus", "mx", "my", "mz", "na", "nam", "nc", "net", "nf", "ng", "nl", "no", "no.", "nu", "nz", "om", "ong", "ooo", "org", "par", "pe", "pf", "pic", "pl", "pm", "pr", "pre", "pro", "pt", "pub", "pw", "qa", "re", "ro", "rs", "ru", "sa", "sa.", "sb", "sc", "se", "se.", "se.", "sg", "sh", "si", "sk", "sm", "st", "so", "su", "sx", "sy", "tc", "tel", "tf", "th", "tj", "tk", "tl", "tm", "tn", "to", "top", "tp", "tr", "tra", "tw", "tv", "tz", "ua", "ug", "uk", "uk.", "uk.", "ac.", "gov", "us", "us.", "uy", "uy.", "uz", "va", "vc", "ve", "vg", "vu", "wan", "wf", "wik", "ws", "xxx", "xyz", "yu", "za"};

        parentLayout = findViewById(R.id.parent);
        resultTextView = new TextView(this);
        parentLayout.addView(resultTextView);

        tldSpinner = findViewById(R.id.spinner1);
        ArrayAdapter<String> tldAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, tlds);
        // Set the spinners adapter to the previously created one.
        tldSpinner.setAdapter(tldAdapter);
        tldSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View selectedView, int position, long id) {
                tldCode = tlds[position];
            }

            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
                tldCode = "com";
            }
        });

        final EditText domainEditText = findViewById(R.id.dmn);
        domainEditText.setOnKeyListener(new View.OnKeyListener() {
            @Override
            public boolean onKey(View view, int keyCode, KeyEvent keyEvent) {
                if ((keyEvent.getAction() == KeyEvent.ACTION_DOWN)
                        && (keyCode == KeyEvent.KEYCODE_ENTER)) {
                    String domainInput = domainEditText.getText().toString().trim();
                    if (domainInput.isEmpty()) {
                        domainEditText.setError("This field can't be empty");
                    } else {
                        lookupWhois(domainInput, tldCode);
                    }
                    return true;
                }
                return false;
            }
        });

        Button runButton = findViewById(R.id.run);
        Button clearButton = findViewById(R.id.clear);
        clearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                domainEditText.setText("");
                domainEditText.setHint("ex: google.com");
                resultTextView.setText("");
            }
        });

        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String domainInput = domainEditText.getText().toString().trim();
                if (domainInput.isEmpty()) {
                    domainEditText.setError("This field can't be empty");
                } else {
                    lookupWhois(domainInput, tldCode);
                }
            }
        });
    }

    private void lookupWhois(String domainName, String selectedTld) {
        resultTextView.setText("Loading...");
        TCWHOIS.getWhoisAsync(domainName, selectedTld, new TCWHOIS.WhoisCallback() {
            @Override
            public void onResult(final String data) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        Log.v(TAG, data);
                        resultTextView.setText(data);
                    }
                });
            }

            @Override
            public void onError(final Exception e) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        Log.e(TAG, "Whois lookup failed", e);
                        resultTextView.setText("Lookup failed: " + e.getMessage());
                    }
                });
            }
        });
    }
}
