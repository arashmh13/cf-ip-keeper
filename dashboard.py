"""CF IP Keeper — live monitoring dashboard (zero dependencies, stdlib only).
Serves on :8787 — glass UI, SSE live logs, per-section control, EN/FA bilingual.
Runs on ZimaOS from /DATA/cf-ip-keeper alongside the scanner services.
"""
import json, os, re, subprocess, threading, time, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("DASH_PORT", "8787"))

SECTIONS = ["Iran", "Hetzner", "AmazonAWS", "Aeza", "DigitalOcean", "EthernetServer", "IONOS"]
UNIT = {"Iran": "cf-ip-scan.service"}
for s in SECTIONS[1:]:
    UNIT[s] = f"cf-ip-section@{s}.service"

def fpath(section, base, ext):
    if section == "Iran":
        return os.path.join(BASE, f"{base}.{ext}")
    return os.path.join(BASE, f"{base}_{section}.{ext}")

def read_json(p):
    try:
        with open(p, encoding="utf-8") as f: return json.load(f)
    except Exception: return None

def tail_lines(p, n=200):
    try:
        with open(p, "rb") as f:
            f.seek(0, 2); size = f.tell()
            f.seek(max(0, size - n * 220))
            return [l.decode("utf-8", "replace") for l in f.read().splitlines()[-n:]]
    except Exception: return []

def sh(*args):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception: return ""

def system_status():
    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for ln in f:
                k, v = ln.split(":", 1)
                mem[k.strip()] = int(v.split()[0])
    except Exception: pass
    try:
        up = float(open("/proc/uptime").read().split()[0])
    except Exception: up = 0
    load = sh("cat", "/proc/loadavg").split() or ["0"]
    total, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
    return {"load": load[0], "uptime_h": round(up / 3600, 1),
            "mem_used_mb": round((total - avail) / 1024), "mem_total_mb": round(total / 1024)}

def section_info(name):
    cur = read_json(fpath(name, "cursor", "json")) or {}
    state = read_json(fpath(name, "state", "json")) or {}
    hits = read_json(fpath(name, "hits", "json")) or {}
    nranges = 0
    try:
        with open(fpath(name, "ranges", "txt"), encoding="utf-8", errors="ignore") as f:
            nranges = sum(1 for ln in f if ln.split("#")[0].strip())
    except Exception: pass
    active = sh("systemctl", "is-active", UNIT[name]) or "unknown"
    since = sh("systemctl", "show", UNIT[name], "-p", "ActiveEnterTimestamp", "--value")
    last_found, last_ms = None, None
    if state:
        ip, d = max(state.items(), key=lambda kv: kv[1].get("ts", 0))
        last_found, last_ms = ip, d.get("ms")
        last_ts = d.get("ts")
    else:
        last_ts = None
    # current DNS record IP from checker log
    record_ip, record_ms = None, None
    for ln in reversed(tail_lines(fpath(name, "checker", "log"), 400)):
        m = re.search(r"switched \S+: \S+ \(\d+ms\) -> (\S+) \((\d+)ms\)", ln)
        if m: record_ip, record_ms = m.group(1), int(m.group(2)); break
        m = re.search(r"keeping \S+=(\S+) \((\d+)ms\)", ln)
        if m: record_ip, record_ms = m.group(1), int(m.group(2)); break
        m = re.search(r"created \S+ -> (\S+) \((\d+)ms\)", ln)
        if m: record_ip, record_ms = m.group(1), int(m.group(2)); break
    recs = read_json(os.path.join(BASE, "sections_config.json")) or {}
    cfg = (recs.get("sections") or {}).get(name, {})
    return {"name": name, "unit": UNIT[name], "active": active, "since": since,
            "cursor_i": cur.get("i", 0), "cursor_j": cur.get("j", 0), "nets": nranges,
            "found": len(state), "hits_total": sum(hits.values()), "hot_nets": len(hits),
            "last_found": last_found, "last_ms": last_ms, "last_ts": last_ts,
            "record_ip": record_ip, "record_ms": record_ms,
            "workers": cfg.get("workers"), "records": cfg.get("records", "")}

def api_status():
    secs = [section_info(s) for s in SECTIONS]
    alive_now = sum(1 for s in secs if s["active"] == "active")
    return {"sections": secs, "system": system_status(),
            "active_services": alive_now, "total_services": len(SECTIONS),
            "now": time.strftime("%F %T")}

LOGFILES = {"scanner.log", "checker.log"} | {f"{p}_{s}.log" for s in SECTIONS[1:] for p in ("scanner", "checker")} \
           | {"scanner_Iran.log", "checker_Iran.log"}

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            with open(os.path.join(BASE, "dashboard.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif u.path == "/api/status":
            self._send(200, json.dumps(api_status()).encode())
        elif u.path == "/icon.svg":
            try:
                with open(os.path.join(BASE, "icon.svg"), "rb") as f:
                    self._send(200, f.read(), "image/svg+xml")
            except Exception:
                self._send(404, b"{}")
        elif u.path == "/api/logs":
            q = parse_qs(u.query)
            name = (q.get("file") or ["scanner.log"])[0]
            if name not in LOGFILES:
                return self._send(403, b'{"error":"bad file"}')
            n = min(int((q.get("n") or [200])[0]), 1000)
            self._send(200, json.dumps({"lines": tail_lines(os.path.join(BASE, name), n)}).encode())
        elif u.path == "/stream":
            self.stream_sse(parse_qs(u.query))
        else:
            self._send(404, b"{}")

    def do_POST(self):
        if urlparse(self.path).path != "/api/action":
            return self._send(404, b"{}")
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except Exception:
            return self._send(400, b'{"error":"bad json"}')
        action = req.get("action"); section = req.get("section", "Iran")
        unit = UNIT.get(section)
        if action == "check" and section == "Iran":
            unit = "cf-ip-check.service"
        if action not in ("start", "stop", "restart", "check") or not unit or not unit.startswith("cf-ip-"):
            return self._send(400, b'{"error":"bad action"}')
        if action == "check": action = "start"
        out = sh("sudo", "-n", "systemctl", action, unit)
        ok = subprocess.run(["sudo", "-n", "systemctl", "is-active", unit],
                            capture_output=True, text=True).stdout.strip()
        self._send(200, json.dumps({"ok": ok == "active", "state": ok, "out": out}).encode())

    def stream_sse(self, q):
        name = (q.get("file") or ["scanner.log"])[0]
        if name not in LOGFILES:
            self._send(403, b"bad file"); return
        path = os.path.join(BASE, name)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            for ln in tail_lines(path, 150):
                self.wfile.write(f"data: {json.dumps(ln)}\n\n".encode())
            self.wfile.flush()
            p = subprocess.Popen(["tail", "-n", "0", "-F", path],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                while True:
                    ln = p.stdout.readline()
                    if not ln: break
                    self.wfile.write(f"data: {json.dumps(ln.decode('utf-8', 'replace'))}\n\n".encode())
                    self.wfile.flush()
            finally:
                p.terminate()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"dashboard on :{PORT} base={BASE}", flush=True)
    srv.serve_forever()
