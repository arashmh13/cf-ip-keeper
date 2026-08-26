package ir.arash.cfipkeeper;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Single-activity UI (programmatic views, no layout XML needed):
 *  Tab-less scroll form: config / subnets / scanner / keeper / log
 */
public class MainActivity extends Activity {

    private SharedPreferences prefs;
    private Engine engine;

    // config inputs
    private EditText etToken, etZone, etDomain, etRecords, etWorkers,
            etTimeout, etMargin, etInterval, etRangesUrl;
    private CheckBox chkKeeper;
    private TextView tvStatus, tvLog, tvRangeInfo, tvFound;
    private Button btnScan, btnImport;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("cfg", MODE_PRIVATE);
        File dataDir = new File(getFilesDir(), "data");
        if (!dataDir.exists()) dataDir.mkdirs();
        engine = new Engine(dataDir);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (14 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);

        /* ---------------- config ---------------- */
        root.addView(header("Cloudflare / VLESS config"));
        etToken     = addEdit(root, "API Token (Edit zone DNS)", true);
        etZone      = addEdit(root, "Zone ID", false);
        etDomain    = addEdit(root, "Fronting domain (= SNI/Host)", false);
        etRecords   = addEdit(root, "Grey records (comma sep: cn.x,cn2.x)", false);
        etRangesUrl = addEdit(root, "ranges.txt URL (optional import)", false);
        loadPrefsIntoUi();

        Button btnSave = button(root, "💾 Save config");
        btnSave.setOnClickListener(v -> {
            Engine.PrefsHolder.domain = etDomain.getText().toString().trim();
            prefs.edit()
                 .putString("token", txt(etToken))
                 .putString("zone", txt(etZone))
                 .putString("domain", txt(etDomain))
                 .putString("records", txt(etRecords))
                 .putString("ranges_url", txt(etRangesUrl))
                 .putString("workers", txt(etWorkers))
                 .putString("probe_timeout", txt(etTimeout))
                 .putString("margin_ms", txt(etMargin))
                 .putString("interval_min", txt(etInterval))
                 .putBoolean("keeper_enabled", chkKeeper.isChecked())
                 .apply();
            toast("config saved ✓");
            refreshStats();
        });

        /* ---------------- tuning ---------------- */
        root.addView(header("Tuning"));
        LinearLayout tuneRow = row(root);
        etWorkers = labeled(tuneRow, "workers", 4);
        etTimeout = labeled(tuneRow, "timeout(s)", 4);
        etMargin  = labeled(tuneRow, "margin(ms)", 5);
        etInterval= labeled(tuneRow, "check(min)", 5);
        bindSpinners();

        /* ---------------- ranges ---------------- */
        root.addView(header("Subnet source (ranges.txt)"));
        LinearLayout rngBtns = row(root);
        Button btnAddNet = button2(rngBtns, "+ add CIDR");
        btnImport = button2(rngBtns, "import file…");
        Button btnClearRng = button2(rngBtns, "clear all");
        tvRangeInfo = new TextView(this);
        tvRangeInfo.setTextIsSelectable(true);
        tvRangeInfo.setTextSize(12);
        root.addView(tvRangeInfo);
        refreshStats();

        btnAddNet.setOnClickListener(v -> {
            EditText inp = new EditText(this);
            inp.setHint("203.0.113.0/24");
            new android.app.AlertDialog.Builder(this)
                    .setTitle("Add network (CIDR)")
                    .setView(inp)
                    .setPositiveButton("add", (d, w) -> {
                        String cidr = inp.getText().toString().trim();
                        if (!cidr.matches("(\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}")) {
                            toast("invalid CIDR"); return;
                        }
                        try {
                            List<String> lines = engine.loadRanges();
                            if (!lines.contains(cidr)) {
                                lines.add(cidr);
                                java.util.Collections.sort(lines);
                                engine.saveRanges(lines);
                                refreshStats(); toast("added ✓");
                            }
                        } catch (Exception e) { toast("err: " + e); }
                    })
                    .setNegativeButton("cancel", null).show();
        });
        btnImport.setOnClickListener(v -> {
            try {
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.setType("*/*");
                startActivityForResult(
                        Intent.createChooser(i, "pick IP list"), 41);
            } catch (Exception e) { toast("no file picker: " + e); }
        });
        btnClearRng.setOnClickListener(v ->
                new android.app.AlertDialog.Builder(this)
                        .setTitle("Delete ALL networks?")
                        .setPositiveButton("yes", (d, w) -> {
                            try { engine.saveRanges(new ArrayList<>()); } catch (Exception ignored) {}
                            refreshStats();
                        })
                        .setNegativeButton("no", null).show());

        /* ---------------- scanner + keeper controls ---------------- */
        root.addView(header("Engine"));
        LinearLayout ctl = row(root);
        btnScan = button2(ctl, "▶ Start service");
        Button btnCheck = button2(ctl, "check now");
        Button btnStop = button2(ctl, "■ stop all");
        chkKeeper = new CheckBox(this);
        chkKeeper.setText("DNS keeper enabled (uncheck = dry mode)");
        chkKeeper.setOnCheckedChangeListener((g, on) ->
                prefs.edit().putBoolean("keeper_enabled", on).apply());
        root.addView(chkKeeper);

        btnScan.setOnClickListener(v -> {
            saveBeforeStart();
            Context0.start(this, CfService.ACTION_START_SCANNER);
            btnScan.setText("● running");
            toast("service started");
        });
        btnCheck.setOnClickListener(v -> {
            saveBeforeStart();
            Context0.start(this, CfService.ACTION_CHECK_NOW);
            toast("single check queued");
        });
        btnStop.setOnClickListener(v -> {
            Context0.stop(this);
            btnScan.setText("▶ Start service");
            toast("stopped");
        });

        /* ---------------- stats + log ---------------- */
        root.addView(header("State"));
        tvFound = new TextView(this); tvFound.setTextSize(13);
        root.addView(tvFound);
        Button btnLog = button(root, "refresh log");
        btnLog.setOnClickListener(v -> refreshStats());
        tvLog = new TextView(this);
        tvLog.setTextIsSelectable(true);
        tvLog.setTextSize(11);
        tvLog.setFontFeatureSettings("monospace");
        root.addView(tvLog);

        Engine.PrefsHolder.domain = prefs.getString("domain", "");
        refreshStats();
        setContentView(scroll);
    }

    private void saveBeforeStart() {
        Engine.PrefsHolder.domain = txt(etDomain);
        prefs.edit()
             .putString("token", txt(etToken)).putString("zone", txt(etZone))
             .putString("domain", txt(etDomain)).putString("records", txt(etRecords))
             .putString("ranges_url", txt(etRangesUrl))
             .putString("workers", txt(etWorkers))
             .putString("probe_timeout", txt(etTimeout))
             .putString("margin_ms", txt(etMargin))
             .putString("interval_min", txt(etInterval))
             .putBoolean("keeper_enabled", chkKeeper.isChecked())
             .apply();
    }

    private void loadPrefsIntoUi() {
        etToken.setText(prefs.getString("token", ""));
        etZone.setText(prefs.getString("zone", ""));
        etDomain.setText(prefs.getString("domain", ""));
        etRecords.setText(prefs.getString("records", ""));
        etRangesUrl.setText(prefs.getString("ranges_url", ""));
    }

    private void bindSpinners() {
        etWorkers.setText(prefs.getString("workers", "8"));
        etTimeout.setText(prefs.getString("probe_timeout", "6"));
        etMargin.setText(prefs.getString("margin_ms", "30"));
        etInterval.setText(prefs.getString("interval_min", "30"));
    }

    @Override
    protected void onActivityResult(int rq, int rc, Intent data) {
        super.onActivityResult(rq, rc, data);
        if (rq == 41 && rc == RESULT_OK && data != null && data.getData() != null) {
            try {
                InputStream is = getContentResolver().openInputStream(data.getData());
                List<String> lines = new ArrayList<>();
                BufferedReader r = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                String ln;
                while ((ln = r.readLine()) != null) {
                    ln = ln.split("#")[0].trim();
                    if (!ln.isEmpty()) lines.add(ln);
                }
                r.close();
                engine.saveRanges(lines);
                refreshStats();
                toast("imported " + lines.size() + " networks ✓");
            } catch (Exception e) { toast("import failed: " + e); }
        }
    }

    private void refreshStats() {
        try {
            int nets = engine.loadRanges().size();
            int alive = engine.aliveCount();
            tvRangeInfo.setText(nets + " networks in ranges.txt");
            tvFound.setText("alive relays known: " + alive);
            tvLog.setText(engine.readLog(6000));
        } catch (Exception ignored) {}
    }

    private void toast(String m) {
        Toast.makeText(this, m, Toast.LENGTH_SHORT).show();
    }

    private static String txt(EditText e) { return e.getText().toString().trim(); }

    private TextView header(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(16); t.setPadding(0, dp(18), 0, dp(6));
        return t;
    }

    private EditText addEdit(LinearLayout parent, String hint, boolean pw) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(InputType.TYPE_CLASS_TEXT
                | (pw ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_VARIATION_NORMAL));
        e.setTextSize(13);
        parent.addView(e);
        return e;
    }

    private LinearLayout row(LinearLayout parent) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        parent.addView(r);
        return r;
    }

    private EditText labeled(LinearLayout row, String label, int widthDp) {
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        TextView l = new TextView(this); l.setText(label); l.setTextSize(11);
        EditText e = new EditText(this);
        e.setInputType(InputType.TYPE_CLASS_NUMBER);
        e.setMinimumWidth(dp(widthDp * 7)); e.setTextSize(13);
        col.addView(l); col.addView(e);
        row.addView(col);
        return e;
    }

    private Button button(LinearLayout parent, String text) {
        Button b = new Button(this); b.setText(text);
        parent.addView(b); return b;
    }

    private Button button2(LinearLayout row, String text) {
        Button b = new Button(this); b.setText(text);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.rightMargin = dp(8);
        b.setLayoutParams(p);
        row.addView(b); return b;
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }

    /** tiny indirection so both Activity and Service start/stop uniformly */
    private static final class Context0 {
        static void start(Activity a, String action) {
            Intent i = new Intent(a, CfService.class);
            i.setAction(action);
            if (android.os.Build.VERSION.SDK_INT >= 26) a.startForegroundService(i);
            else a.startService(i);
        }
        static void stop(Activity a) {
            a.stopService(new Intent(a, CfService.class));
        }
    }
}
