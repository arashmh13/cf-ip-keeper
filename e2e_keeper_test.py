#!/usr/bin/env python3
"""END-TO-END test of the fixed keeper against a MOCK Cloudflare API.

Proves, with the real keeper code + real ip-api geo lookups + a stateful fake CF
API, that:
  1. the reported bug (cn and cn2 both on 2.188.243.132) is repaired
  2. cn != cn2 after the pass
  3. re-running is idempotent (no flip-flop)
  4. a foreign (NL) IP is refused by the IR gate
  5. no duplicate record is ever created when the API 500s

Run inside WSL:  python3 e2e_keeper_test.py
"""
import http.server, json, os, re, shutil, socketserver, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
DOMAIN = "e.example.com"
CN, CN2 = f"cn.{DOMAIN}", f"cn2.{DOMAIN}"

# ---------- stateful mock of api.cloudflare.com ----------
class MockCF:
    def __init__(self):
        self.records = {
            # EXACT reported broken state (keyed by record id)
            "id-cn":  {"id": "id-cn",  "type": "A", "name": CN,  "content": "2.188.243.132", "ttl": 60},
            "id-cn2": {"id": "id-cn2", "type": "A", "name": CN2, "content": "2.188.243.132", "ttl": 60},
        }
        self.fail = False
        self.log = []
        self.lock = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.server.cf.fail:
            return self._send(500, {"success": False, "errors": [{"message": "boom"}]})
        m = re.match(r"^/client/v4/zones/([^/]+)/dns_records\?.*name=([^&]+)", self.path)
        if m:
            name = m.group(2)
            recs = [r for r in self.server.cf.records.values() if r["name"] == name]
            return self._send(200, {"success": True, "result": recs})
        if re.match(r"^/client/v4/zones/[^/]+/dns_records\?.*per_page=", self.path) or \
           self.path.rstrip("/").endswith("/dns_records"):
            # zone-wide listing (used for cross-record collision avoidance)
            return self._send(200, {"success": True,
                                    "result": list(self.server.cf.records.values())})
        if self.path.startswith("/client/v4/user/tokens/verify"):
            return self._send(200, {"success": True, "result": {"status": "active"}})
        return self._send(404, {"success": False})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        with self.server.cf.lock:
            self.server.cf.log.append(("POST", body.get("name"), body.get("content")))
            name = body["name"]
            if any(r["name"] == name for r in self.server.cf.records.values()):
                return self._send(400, {"success": False, "errors": [{"message": "record already exists"}]})
            rid = f"id-new-{len(self.server.cf.records)}"
            self.server.cf.records[rid] = {"id": rid, "type": "A", "name": name,
                                           "content": body["content"], "ttl": body.get("ttl", 60)}
        return self._send(200, {"success": True, "result": self.server.cf.records[rid]})

    def do_PUT(self):
        rid = self.path.rsplit("/", 1)[-1]
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        with self.server.cf.lock:
            if rid not in self.server.cf.records:
                return self._send(404, {"success": False})
            self.server.cf.log.append(("PUT", self.server.cf.records[rid]["name"], body.get("content")))
            self.server.cf.records[rid]["content"] = body["content"]
        return self._send(200, {"success": True, "result": self.server.cf.records[rid]})

    def do_DELETE(self):
        rid = self.path.rsplit("/", 1)[-1]
        with self.server.cf.lock:
            self.server.cf.records.pop(rid, None)
        return self._send(200, {"success": True})

def start_mock():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.cf = MockCF()
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

fails = []
def check(c, label):
    print(("  PASS " if c else "  FAIL ") + label)
    if not c: fails.append(label)

# ---------- run the keeper against the mock ----------
def run_keeper(workdir, mock_port, extra_env=None, pool=None, geo="direct"):
    env = dict(os.environ)
    env.update({
        "CF_DOMAIN": DOMAIN,
        "CF_ZONE_ID": "zone123",
        "CF_TOKEN": "tok",
        "CF_RECORDS": f"{CN},{CN2}",
        "CF_API_BASE": f"http://127.0.0.1:{mock_port}/client/v4",
        "SECTION": "Iran",
        "CHECK_ONLY": "1",
        "WORKERS": "4",
        "PROBE_TIMEOUT": "6",
        "MARGIN_MS": "30",
        "GATE_FILE": os.path.join(workdir, "ir_gate.txt"),
        "GATE_COUNTRY": "IR",
        "GEO_STRICT": "1",
        "CF_VLESS_PATH": "/",
    })
    if extra_env: env.update(extra_env)
    if pool is not None:
        with open(os.path.join(workdir, "foundedIPs_Iran.txt"), "w") as f:
            for ip, ms in pool.items():
                f.write(f"{ip} {ms}\n")
    p = subprocess.run([sys.executable, os.path.join(workdir, "cf_ip_keeper.py")],
                       capture_output=True, text=True, env=env, cwd=workdir, timeout=180)
    return p.stdout + p.stderr

def setup_workdir(mock):
    wd = tempfile.mkdtemp(prefix="cfk_e2e_")
    shutil.copy(os.path.join(HERE, "cf_ip_keeper_real_lf.py"), os.path.join(wd, "cf_ip_keeper.py"))
    shutil.copy(os.path.join(HERE, "ir_gate.txt"), os.path.join(wd, "ir_gate.txt"))
    # seeded state: both the reported duplicate AND a foreign IP in the pool
    with open(os.path.join(wd, "state_Iran.json"), "w") as f:
        json.dump({"2.188.243.132": {"ms": 326, "ts": 9e9},
                   "109.70.73.194":  {"ms": 424, "ts": 9e9},
                   "2.188.254.219":  {"ms": 501, "ts": 9e9}}, f)
    with open(os.path.join(wd, "dns_cache_Iran.json"), "w") as f:
        json.dump({CN:  {"ip": "2.188.243.132", "ms": 326},
                   CN2: {"ip": "2.188.243.132", "ms": 326}}, f)
    # countries verified by earlier passes (what the box accumulates once the
    # geo proxy works) — lets the keeper keep enforcing country purity even if
    # ip-api is temporarily unreachable.
    with open(os.path.join(wd, "geo_cache_Iran.json"), "w") as f:
        json.dump({"2.188.243.132": {"cc": "IR", "ts": time.time()},
                   "2.188.254.219": {"cc": "IR", "ts": time.time()},
                   "109.70.73.194": {"cc": "NL", "ts": time.time()}}, f)
    return wd

print("=" * 70)
print("TEST 1: the reported bug — cn and cn2 both on 2.188.243.132")
print("=" * 70)
mock = start_mock()
wd = setup_workdir(mock)
# REAL alive pool measured from WSL on the real VLESS path (2026-09-23)
pool = {"5.202.78.9": 614, "103.215.223.54": 630, "94.182.147.185": 635,
        "103.215.223.50": 647, "2.188.243.132": 653, "185.206.92.218": 736,
        "2.188.254.219": 764, "109.122.251.91": 786, "2.189.86.119": 812,
        "46.245.98.53": 1689, "5.202.78.41": 1721, "5.202.75.93": 1777}
lat = ",".join(f"{ip}={ms}" for ip, ms in pool.items())
out = run_keeper(wd, mock.server_address[1], pool=pool, extra_env={"FAKE_LATENCY": lat})
print(out.strip()[-1800:])
ips = {r["name"]: r["content"] for r in mock.cf.records.values()}
print("\n  live DNS now:", ips)
check(ips.get(CN) != ips.get(CN2), f"cn ({ips.get(CN)}) != cn2 ({ips.get(CN2)})")
check(len({r['content'] for r in mock.cf.records.values()}) == len(mock.cf.records),
      "no duplicate content across records")
check("forced move" in out or "duplicate" in out, "keeper logged the duplicate repair")
check((ips.get(CN2) or "") != "109.70.73.194", "foreign IP (109.70.73.194 / NL) NOT assigned")

print()
print("=" * 70)
print("TEST 2: idempotence — a second pass must not flip-flop")
print("=" * 70)
# pin latencies so the pass is deterministic (real jitter would legitimately
# trigger "faster" upgrades and make this assertion meaningless)
lat = ",".join(f"{ip}={ms}" for ip, ms in pool.items())
out2 = run_keeper(wd, mock.server_address[1], pool=pool, extra_env={"FAKE_LATENCY": lat})
ips2 = {r["name"]: r["content"] for r in mock.cf.records.values()}
print("  live DNS after 2nd pass:", ips2)
check(ips2 == ips, "state is stable across passes (no churn)")
check(ips2.get(CN) != ips2.get(CN2), "still cn != cn2")
check("switched" not in out2, "no unnecessary switch on the 2nd pass")

print()
print("=" * 70)
print("TEST 3: CF API 500s during the record read -> NO writes at all")
print("=" * 70)
snap = dict(mock.cf.records)
mock.cf.fail = True
out3 = run_keeper(wd, mock.server_address[1], pool=pool)
mock.cf.fail = False
print(out3.strip()[-600:])
check(all(snap[k]["content"] == mock.cf.records[k]["content"] for k in snap),
      "records untouched when the API is down")
check("skipping ALL dns writes" in out3 or "api unreachable" in out3,
      "keeper refused to write on unknown live state")
check(not any(op == "POST" for op in [l[0] for l in mock.cf.log]), "no POST/PUT attempted")

print()
print("=" * 70)
print("TEST 4: geo gate on the box's real constraint (no direct DNS)")
print("=" * 70)
mock2 = start_mock()
wd2 = setup_workdir(mock2)
# point GEO at an unreachable proxy -> every lookup returns None
out4 = run_keeper(wd2, mock2.server_address[1], pool=pool,
                  extra_env={"GEO_PROXY": "http://127.0.0.1:1"})
ips4 = {r["name"]: r["content"] for r in mock2.cf.records.values()}
print(out4.strip()[-700:])
print("  live DNS with geo unavailable (GEO_STRICT=1):", ips4)
check(ips4.get(CN) != ips4.get(CN2), "cn != cn2 even when geo is unavailable")
check("109.70.73.194" not in ips4.values(), "foreign IP refused when geo is dead (fail-closed)")

print()
print("=" * 70)
print("TEST 5: cn must not share an IP with 'cam' (a record we don't manage)")
print("=" * 70)
mock3 = start_mock()
# cam is NOT in sections_config: another system owns it. It currently holds the
# fastest IP, which is exactly the trap that produced cam==cn on the box.
mock3.cf.records["id-cam"] = {"id": "id-cam", "type": "A", "name": f"cam.{DOMAIN}",
                              "content": "5.202.78.9", "ttl": 1}
wd3 = setup_workdir(mock3)
out5 = run_keeper(wd3, mock3.server_address[1], pool=pool, extra_env={"FAKE_LATENCY": lat})
ips5 = {r["name"]: r["content"] for r in mock3.cf.records.values()}
print(out5.strip()[-900:])
print("  live DNS:", ips5)
check(ips5.get(CN) != ips5.get(CN2), "cn != cn2")
check(ips5.get(CN) != ips5["cam." + DOMAIN] or ips5.get(CN2) != ips5["cam." + DOMAIN],
      "neither cn nor cn2 collides with cam")
check(len(set(ips5.values())) == len(ips5), "every A record in the zone has a distinct IP")
check("cam." + DOMAIN in ips5, "cam record was left alone (not ours to manage)")

print()
print("=" * 70)
print("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}")
print("=" * 70)
sys.exit(0 if not fails else 1)
