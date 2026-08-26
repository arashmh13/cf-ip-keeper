package ir.arash.cfipkeeper;

import android.content.Context;
import android.os.*;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Probe + Cloudflare API engine. Same physics as the Python project:
 * real TLS handshake, certificate must validate for CF_DOMAIN,
 * HTTP request with Host header must answer HTTP/.
 */
public final class Engine {

    public interface Log { void log(String m); }

    public static class Hit {
        public final String ip; public final int ms;
        public Hit(String ip, int ms) { this.ip = ip; this.ms = ms; }
    }

    public static class RecState {
        public final String id, name, content;
        public RecState(String id, String name, String content) {
            this.id = id; this.name = name; this.content = content;
        }
    }

    private static final Pattern IPV4 =
            Pattern.compile("\\b((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}"
                    + "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b");

    private final File dir;
    public Engine(File dataDir) { dir = dataDir; if (!dir.exists()) dir.mkdirs(); }

    private File f(String n) { return new File(dir, n); }

    /* ------------------------- storage ------------------------- */

    public List<String> loadRanges() throws IOException {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(f("ranges.txt")), StandardCharsets.UTF_8))) {
            String ln;
            while ((ln = r.readLine()) != null) {
                ln = ln.split("#")[0].trim();
                if (!ln.isEmpty()) out.add(ln);
            }
        } catch (FileNotFoundException fnf) { /* empty */ }
        return out;
    }

    public void saveRanges(List<String> lines) throws IOException {
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(f("ranges.txt")), StandardCharsets.UTF_8))) {
            for (String l : lines) w.println(l);
        }
    }

    /** known relays from state.json-like store (ip -> ms,ts json lines) */
    public synchronized Set<String> knownIps() {
        Set<String> s = new LinkedHashSet<>();
        File kf = f("found.txt");
        if (kf.exists()) {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(
                    new FileInputStream(kf), StandardCharsets.UTF_8))) {
                String ln;
                while ((ln = r.readLine()) != null) {
                    ln = ln.trim();
                    if (IPV4.matcher(ln).matches()) s.add(ln);
                }
            } catch (IOException ignored) {}
        }
        return s;
    }

    public synchronized void recordHit(Hit h) {
        // dedupe: rewrite without ip then append
        File kf = f("found.txt");
        Set<String> cur = new LinkedHashSet<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(kf), StandardCharsets.UTF_8))) {
            String ln;
            while ((ln = r.readLine()) != null) {
                ln = ln.trim();
                if (!ln.equals(h.ip)) cur.add(ln);
            }
        } catch (IOException ignored) {}
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(kf), StandardCharsets.UTF_8))) {
            for (String x : cur) w.println(x);
            w.println(h.ip);
        } catch (IOException ignored) {}
    }

    public synchronized int aliveCount() { return knownIps().size(); }

    public synchronized void appendLog(String line) {
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(f("engine.log"), true), StandardCharsets.UTF_8))) {
            w.println(line);
        } catch (IOException ignored) {}
    }

    public synchronized String readLog(int maxChars) {
        File lf = f("engine.log");
        if (!lf.exists()) return "(no log yet)";
        try (RandomAccessFile raf = new RandomAccessFile(lf, "r")) {
            long len = Math.min(raf.length(), maxChars);
            raf.seek(raf.length() - len);
            byte[] b = new byte[(int) len];
            raf.readFully(b);
            return new String(b, StandardCharsets.UTF_8);
        } catch (Exception e) { return "(log error)"; }
    }

    public void clearState() {
        new File(dir, "found.txt").delete();
        new File(dir, "engine.log").delete();
    }

    /* ------------------------- probing ------------------------- */

    /** probe one IP: TLS with cert validation for domain + Host GET */
    public static Hit probe(String ip, String domain, int timeoutMs) {
        Socket plain = null;
        SSLSocket sock = null;
        long t0 = SystemClock.elapsedRealtime();
        try {
            plain = new Socket();
            plain.connect(new InetSocketAddress(ip, 443), timeoutMs);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);                       // default trust store
            SSLSocketFactory sf = ctx.getSocketFactory();
            sock = (SSLSocket) sf.createSocket(plain, domain, 443, true);
            sock.setUseClientMode(true);
            sock.startHandshake();                            // validates chain vs domain
            Certificate[] chain = sock.getSession().getPeerCertificates();
            X509Certificate leaf = (X509Certificate) chain[0];
            leaf.checkValidity();

            OutputStream os = sock.getOutputStream();
            os.write(("GET / HTTP/1.1\r\nHost: " + domain +
                    "\r\nUser-Agent: cf-keeper-android\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            os.flush();
            InputStream is = sock.getInputStream();
            StringBuilder head = new StringBuilder();
            int c, last = -1;
            while ((c = is.read()) != -1 && head.length() < 512) {
                head.append((char) c);
                if (c == '\n' && last == '\n') break;
                last = c;
            }
            boolean ok = head.toString().startsWith("HTTP/");
            int ms = (int) (SystemClock.elapsedRealtime() - t0);
            return ok ? new Hit(ip, ms) : null;
        } catch (Exception e) {
            return null;
        } finally {
            try { if (sock != null) sock.close(); } catch (Exception ignored) {}
            try { if (plain != null) plain.close(); } catch (Exception ignored) {}
        }
    }

    /** concurrent scan of ips at given worker count, sorted by latency */
    public List<Engine.Hit> scan(List<String> ips, int workers, int timeoutMs)
            throws InterruptedException {
        String domain = PrefsHolder.domain;   // set by MainActivity before calls
        ExecutorService ex = Executors.newFixedThreadPool(Math.max(workers, 1));
        List<Future<Hit>> fs = new ArrayList<>();
        for (final String ip : new LinkedHashSet<>(ips)) {
            fs.add(ex.submit(() -> probe(ip, domain, timeoutMs)));
        }
        List<Hit> hits = new ArrayList<>();
        for (Future<Hit> fu : fs) {
            try { Hit h = fu.get(); if (h != null) hits.add(h); }
            catch (Exception ignored) {}
        }
        Collections.sort(hits, (a, b) -> Integer.compare(a.ms, b.ms));
        ex.shutdownNow();
        return hits;
    }

    /* ---------------- host expansion over ranges ---------------- */

    public static class Host {
        public final String net; public final long idx;
        public Host(String net, long idx) { this.net = net; this.idx = idx; }
    }

    private static long netStart(String cidr) {
        String[] p = cidr.split("/");
        long base = ipToLong(p[0]);
        int plen = p.length > 1 ? Integer.parseInt(p[1]) : 32;
        long size = 1L << (32 - plen);
        long mask = plen == 0 ? 0L : (~0L << (32 - plen)) & 0xFFFFFFFFL;
        return base & mask;
    }

    private static long netSize(String cidr) {
        String[] p = cidr.split("/");
        int plen = p.length > 1 ? Integer.parseInt(p[1]) : 32;
        return 1L << (32 - plen);
    }

    private static long ipToLong(String ip) {
        String[] o = ip.split("\\.");
        return (Long.parseLong(o[0]) << 24) | (Long.parseLong(o[1]) << 16)
             | (Long.parseLong(o[2]) << 8) | Long.parseLong(o[3]);
    }

    private static String longToIp(long v) {
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "."
             + ((v >> 8) & 255) + "." + (v & 255);
    }

    /** expand nets into consecutive usable hosts starting at global cursor */
    public List<Host> expandHosts(List<String> nets, long cursor, int count) {
        List<Host> out = new ArrayList<>(count);
        long pos = 0;
        for (String net : nets) {
            long start = netStart(net), size = netSize(net);
            long lo = Math.max(start + 1, start + Math.max(0, cursor - pos));   // skip .0
            long hi = start + size - 1;                                          // exclude .255
            for (long h = lo; h < hi && out.size() < count; h++) {
                out.add(new Host(net, pos + (h - start)));
            }
            pos += size;
            if (out.size() >= count) break;
        }
        return out;
    }

    /* ------------------------- cloudflare api ------------------------- */

    @SuppressWarnings({"deprecation", "CharsetObjectCanBeUsed"})
    private static HttpsURLConnection cfConn(String urlStr, String token,
                                             String method, byte[] body)
            throws IOException {
        HttpsURLConnection c = (HttpsURLConnection) new java.net.URL(urlStr).openConnection();
        c.setRequestMethod(method);
        c.setRequestProperty("Authorization", "Bearer " + token);
        c.setRequestProperty("Content-Type", "application/json");
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        if (body != null) {
            c.setDoOutput(true);
            c.getOutputStream().write(body);
        }
        return c;
    }

    private static String readAll(InputStream is) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int n;
        while ((n = is.read(buf)) != -1) bo.write(buf, 0, n);
        return bo.toString("UTF-8");
    }

    /** crude JSON helpers (no external deps) */
    private static String jstr(String json, String key) {
        java.util.regex.Matcher m = Pattern.compile(
                "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    public RecState fetchRecord(String token, String zone, String name) {
        try {
            HttpsURLConnection c = cfConn(
                    "https://api.cloudflare.com/client/v4/zones/" + zone
                    + "/dns_records?type=A&name=" + name, token, "GET", null);
            String body = readAll(c.getInputStream());
            boolean ok = body.contains("\"success\":true");
            if (!ok || !body.contains("\"result\":[{")) return null;
            String id = jstr(body, "id"), content = jstr(body, "content");
            return new RecState(id, name, content);
        } catch (Exception e) { return null; }
    }

    public interface NotifUpd { void update(String text); }

    /**
     * Core keeper logic: assign each record a distinct best relay.
     * Returns human summary for notification/log.
     */
    public String updateRecords(String token, String zone, String domain,
                                List<String> records, List<RecState> states,
                                List<Hit> fresh, int marginMs, Log logf) {
        Map<String,Integer> freshMs = new HashMap<>();
        for (Hit h : fresh) freshMs.put(h.ip, h.ms);
        Set<String> rangeKnown = knownIps();
        Set<String> used = new HashSet<>();
        StringBuilder out = new StringBuilder();

        for (String name : records) {
            RecState st = null;
            for (RecState s : states) if (s.name.equals(name)) st = s;

            Map.Entry<String,Integer> best = null;
            for (Hit h : fresh) {
                if (!used.contains(h.ip)) { best = new AbstractMap.SimpleEntry<>(h.ip, h.ms); break; }
            }
            if (best == null) { out.append(name).append(": no free alive relay\n"); continue; }

            if (st == null) {
                String payload = "{\"type\":\"A\",\"name\":\"" + name
                        + "\",\"content\":\"" + best.getKey()
                        + "\",\"ttl\":60,\"proxied\":false}";
                try {
                    cfConn("https://api.cloudflare.com/client/v4/zones/" + zone
                            + "/dns_records", token, "POST",
                            payload.getBytes(StandardCharsets.UTF_8)).getInputStream();
                    out.append("created ").append(name).append(" -> ")
                       .append(best.getKey()).append('\n');
                    used.add(best.getKey());
                    continue;
                } catch (Exception e) {
                    out.append(name).append(": create failed ").append(e).append('\n');
                    continue;
                }
            }

            boolean curAlive = freshMs.containsKey(st.content);
            boolean curIsRelay = rangeKnown.contains(st.content);
            boolean needSwitch = !curAlive || !curIsRelay
                    || (best.getValue() + marginMs < freshMs.get(st.content));
            if (needSwitch) {
                String payload = "{\"type\":\"A\",\"name\":\"" + name
                        + "\",\"content\":\"" + best.getKey()
                        + "\",\"ttl\":60,\"proxied\":false}";
                try {
                    cfConn("https://api.cloudflare.com/client/v4/zones/" + zone
                            + "/dns_records/" + st.id, token, "PUT",
                            payload.getBytes(StandardCharsets.UTF_8)).getInputStream();
                    out.append("switched ").append(name).append(": ").append(st.content)
                       .append(" -> ").append(best.getKey()).append('\n');
                    used.add(best.getKey());
                    if (curAlive) used.add(st.content);
                } catch (Exception e) {
                    out.append(name).append(": switch failed ").append(e).append('\n');
                }
            } else {
                out.append("keeping ").append(name).append('=').append(st.content).append('\n');
                used.add(st.content);
            }
        }
        return out.toString().trim();
    }

    /* ------------------------- misc ------------------------- */

    public static List<String> splitRecords(String csv) {
        List<String> out = new ArrayList<>();
        for (String s : csv.split(",")) {
            s = s.trim();
            if (s.contains(".")) out.add(s);
        }
        return out;
    }

    public static List<String> hostsToIps(List<Host> hosts) {
        List<String> ips = new ArrayList<>(hosts.size());
        for (Host h : hosts) ips.add(longToIp(h.idx));
        return ips;
    }

    /** tiny prefs bridge so static scan() can see domain */
    public static final class PrefsHolder { public static volatile String domain = ""; }
}
