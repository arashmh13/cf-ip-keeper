package ir.arash.cfipkeeper;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;

import java.io.File;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Foreground service: runs scanner + DNS-keeper cycles in the background.
 * Mirrors scan_loop.py + cf_ip_keeper.py behaviour.
 */
public class CfService extends Service {

    public static final String CHANNEL = "keeper";
    // intents
    public static final String ACTION_START_SCANNER = "START_SCANNER";
    public static final String ACTION_STOP_ALL      = "STOP_ALL";
    public static final String ACTION_CHECK_NOW     = "CHECK_NOW";

    private HandlerThread workerThread;
    private volatile Handler worker;
    private SharedPreferences prefs;
    private Engine engine;
    private volatile boolean scanning, keeping;
    private long scanCursor;          // index into expanded host list

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = getSharedPreferences("cfg", Context.MODE_PRIVATE);
        engine = new Engine(new File(getFilesDir(), "data"));
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(
                CHANNEL, "Keeper", NotificationManager.IMPORTANCE_LOW);
        nm.createNotificationChannel(ch);
        startForeground(1, buildNotification("idle"));
    }

    private Notification buildNotification(String text) {
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("CF IP Keeper")
                .setContentText(text)
                .setOngoing(true)
                .build();
    }

    private void notifyText(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(1, buildNotification(text));
    }

    private synchronized Handler handler() {
        if (worker == null) {
            workerThread = new HandlerThread("engine");
            workerThread.start();
            worker = new Handler(workerThread.getLooper());
        }
        return worker;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_STOP_ALL : intent.getAction();
        if (ACTION_STOP_ALL.equals(action)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CHECK_NOW.equals(action)) {
            handler().post(this::checkOnce);
            return START_STICKY;
        }
        if (ACTION_START_SCANNER.equals(action)) {
            handler().post(this::scannerLoop);
            keeperLoop();
            return START_STICKY;
        }
        return START_STICKY;
    }

    /* ---------------- scanner: endless walk of ranges ---------------- */
    private void scannerLoop() {
        if (scanning) return;
        scanning = true;
        handler().post(new Runnable() {
            @Override public void run() {
                try {
                    List<String> nets = engine.loadRanges();
                    if (nets.isEmpty()) { scanning = false; return; }
                    int workers = Integer.parseInt(prefs.getString("workers", "8"));
                    int chunkSize = Math.max(workers * 50, 400);
                    while (true) {
                        List<Engine.Host> hosts = engine.expandHosts(nets, scanCursor, chunkSize);
                        if (hosts.isEmpty()) {           // full cycle done -> restart
                            log("cycle complete — restarting with fresh priorities");
                            scanCursor = 0;
                            continue;
                        }
                        scanCursor += hosts.size();
                        List<Engine.Hit> hits = engine.scan(
                                Engine.hostsToIps(hosts), workers,
                                timeoutMs());
                        for (Engine.Hit h : hits) {
                            engine.recordHit(h);
                            log("FOUND " + h.ip + "  " + h.ms + "ms");
                        }
                        notifyText("scan cursor #" + scanCursor
                                + " · alive total: " + engine.aliveCount());
                    }
                } catch (Exception e) {
                    log("scan error: " + e);
                    scanning = false;
                }
            }
        });
    }

    /* ---------------- keeper: re-probe + DNS update every N min ----- */
    private void keeperLoop() {
        if (keeping) return;
        keeping = true;
        handler().post(new Runnable() {
            @Override public void run() {
                long intervalMin = Long.parseLong(prefs.getString("interval_min", "30"));
                while (keeping) {
                    try { checkOnce(); } catch (Exception e) { log("check error: " + e); }
                    long until = System.currentTimeMillis() + intervalMin * 60_000;
                    while (keeping && System.currentTimeMillis() < until) {
                        try { Thread.sleep(5_000); } catch (InterruptedException ie) { return; }
                    }
                }
            }
        });
    }

    private void checkOnce() {
        try {
            int timeout = timeoutMs();
            int margin = Integer.parseInt(prefs.getString("margin_ms", "30"));
            List<String> records = Engine.splitRecords(prefs.getString("records", ""));
            List<Engine.RecState> states = new ArrayList<>();
            boolean dry = !prefs.getBoolean("keeper_enabled", false);
            StringBuilder summary = new StringBuilder();

            for (String name : records) {
                Engine.RecState st = engine.fetchRecord(prefs.getString("token", ""),
                        prefs.getString("zone", ""), name);
                if (st != null) states.add(st);
            }
            List<String> ips = new ArrayList<>(engine.knownIps());
            for (Engine.RecState st : states) ips.add(st.content);
            List<Engine.Hit> fresh = engine.scan(ips, 1, timeout);

            if (dry) {
                summary.setLength(0);
                for (Engine.Hit h : fresh) summary.append(h.ip).append(' ').append(h.ms).append("ms\n");
                notifyText("[dry] alive: " + fresh.size()
                        + (fresh.isEmpty() ? "" : "  best=" + fresh.get(0).ip));
            } else {
                String result = engine.updateRecords(
                        prefs.getString("token", ""), prefs.getString("zone", ""),
                        prefs.getString("domain", ""), records, states, fresh, margin,
                        new Engine.Log() {
                            @Override public void log(String m) { CfService.this.log(m); }
                        });
                notifyText(result);
                summary.append(result);
            }
            engine.appendLog(summary.toString());
        } catch (Exception e) {
            log("checkOnce failed: " + e);
        }
    }

    private int timeoutMs() {
        return Integer.parseInt(prefs.getString("probe_timeout", "6")) * 1000;
    }

    private void log(String m) {
        String ts = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new Date());
        engine.appendLog(ts + "  " + m);
    }

    @Override
    public void onDestroy() {
        keeping = false;
        scanning = false;
        if (workerThread != null) workerThread.quitSafely();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent i) { return null; }
}
