#!/usr/bin/env python3
"""Keeps grey-cloud A records pointed at live relay IPs that front your Cloudflare zone.
Supports multi-section namespacing via SECTION env var or --section arg.
VLESS address = RECORDS (grey cloud), SNI/Host = DOMAIN. Stdlib only, Python 3.10+."""
import asyncio, ipaddress, json, os, random, socket, ssl, sys, time, urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
DRY = "--dry" in sys.argv

# Extract section name if passed as --section <name>
SECTION = os.environ.get("SECTION", "")
for idx, arg in enumerate(sys.argv):
    if arg == "--section" and idx + 1 < len(sys.argv):
        SECTION = sys.argv[idx + 1]

def get_filename(base_name, ext="txt"):
    """Namespace file by section if section is provided."""
    if not SECTION or SECTION.lower() in ("default", "main"):
        return os.path.join(BASE, f"{base_name}.{ext}")
    return os.path.join(BASE, f"{base_name}_{SECTION}.{ext}")

DOMAIN = os.environ.get("CF_DOMAIN", "").strip()   # real proxied domain (vless sni + host)
RECORD = os.environ.get("CF_RECORD", "").strip()   # legacy single-record name
# backup subdomains: comma-separated, each gets its OWN distinct relay
RECORDS = [r.strip() for r in os.environ.get("CF_RECORDS", RECORD).split(",") if r.strip()]
TOKEN  = os.environ.get("CF_TOKEN", "").strip()
ZONE   = os.environ.get("CF_ZONE_ID", "").strip()
PORT, TIMEOUT  = 443, float(os.environ.get("PROBE_TIMEOUT", 6.0))
PROBE_BUDGET   = int(os.environ.get("PROBE_BUDGET", 600))
WORKERS        = int(os.environ.get("WORKERS", 8))
MARGIN_MS      = int(os.environ.get("MARGIN_MS", 30))
KEEP           = 300
STATE  = get_filename("state", "json")
CTX    = ssl.create_default_context()   # cert verification ON: probe only passes if IP fronts YOUR domain's cert
IPV6_API = os.environ.get("CF_API_FORCE_IPV6", "1").strip() not in ("0", "false", "no")

if IPV6_API:
    # On some home networks (Iranian 4G) IPv4 to api.cloudflare.com is black-holed while
    # IPv6 works. Try IPv6 FIRST for all connections (IPv4 stays as automatic fallback,
    # since socket.create_connection walks the address list until one connects).
    _orig_getaddrinfo = socket.getaddrinfo
    def _v6_first_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        res = _orig_getaddrinfo(host, port, family, type, proto, flags)
        if family in (0, socket.AF_UNSPEC):
            v6 = [r for r in res if r[0] == socket.AF_INET6]
            if v6:
                return v6 + [r for r in res if r[0] != socket.AF_INET6]
        return res
    socket.getaddrinfo = _v6_first_getaddrinfo

def log(m):
    prefix = f"[{SECTION}] " if SECTION else ""
    print(time.strftime("%F %T"), f"{prefix}{m}", flush=True)

def cf(method, path, body=None, retries=5):
    if not TOKEN:
        raise ValueError("CF_TOKEN is not set")
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4{path}",
                data=json.dumps(body).encode() if body else None,
                headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
                method=method)
            with urllib.request.urlopen(req, timeout=20) as r:
                d = json.load(r)
            if not d.get("success"):
                raise RuntimeError(d.get("errors"))
            return d["result"]
        except Exception as e:
            last = e
            if attempt < retries - 1:
                time.sleep(4 * (attempt + 1))   # backoff: 4s, 8s, 12s, 16s, 20s
    raise last

def hosts_of(n):
    if n.num_addresses <= 4096:
        return [str(h) for h in n.hosts()]
    base = int(n.network_address)
    return [str(ipaddress.ip_address(base + random.randrange(1, n.num_addresses - 1))) for _ in range(256)]

def load_ranges():
    rpath = get_filename("ranges", "txt")
    if not os.path.exists(rpath):
        # fallback to default ranges.txt if section-specific not found yet
        default_p = os.path.join(BASE, "ranges.txt")
        if os.path.exists(default_p):
            rpath = default_p
        else:
            return []
    nets = []
    with open(rpath, encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.split("#")[0].strip()
            if ln:
                try:
                    nets.append(ipaddress.ip_network(ln, strict=False))
                except ValueError:
                    pass
    return nets

RANGES_URL = os.environ.get("RANGES_URL", "")

def ensure_ranges():
    p = get_filename("ranges", "txt")
    if RANGES_URL and (not os.path.exists(p) or time.time() - os.path.getmtime(p) > 604800):
        req = urllib.request.Request(RANGES_URL, headers={"User-Agent": "curl/8.5"})
        with urllib.request.urlopen(req, timeout=30) as r, open(p, "wb") as f:
            f.write(r.read())
    return p

def sample_hosts(nets):
    flat = [h for n in nets for h in hosts_of(n)]
    if len(flat) > PROBE_BUDGET:
        flat = random.sample(flat, PROBE_BUDGET)
    return flat

async def probe(ip, sem):
    async with sem:
        t0 = time.perf_counter()
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, PORT, ssl=CTX, server_hostname=DOMAIN), TIMEOUT)
            w.write(f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            return (ip, ms) if line.startswith(b"HTTP/") else None
        except Exception:
            return None

async def scan(ips):
    sem = asyncio.Semaphore(WORKERS)
    res = await asyncio.gather(*(probe(i, sem) for i in ips))
    return {r[0]: r[1] for r in res if r}

def save(state):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(dict(sorted(state.items(), key=lambda kv: kv[1]["ms"])), f, indent=1)
        f.flush()
        os.fsync(f.fileno())          # power-loss safe
    os.replace(tmp, STATE)

def main():
    if not DOMAIN:
        log("ERROR: CF_DOMAIN is required")
        sys.exit(1)
    if not RECORDS:
        log("ERROR: CF_RECORDS is required")
        sys.exit(1)

    # preflight: if the CF API is unreachable (4G IPv4 black-hole etc), fail fast
    # (~1-2 min) and let the next 30-min pass retry, instead of stalling for hours.
    if not DRY:
        try:
            cf("GET", "/user/tokens/verify")
            log("api reachable")
        except Exception as e:
            log(f"api unreachable ({e}); skipping this pass")
            return

    state = {}
    if os.path.exists(STATE):
        try:
            with open(STATE, encoding="utf-8") as f: state = json.load(f)
        except Exception: pass
    now = time.time()
    state = {ip: v for ip, v in state.items() if now - v.get("ts", 0) < 86400}

    if RANGES_URL and "--dry" not in sys.argv:
        ensure_ranges()
    known = set(state.keys())
    ffound = get_filename("foundedIPs", "txt")
    if os.path.exists(ffound):
        for ln in open(ffound, encoding="utf-8", errors="ignore"):
            parts = ln.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3:
                    known.add(ip)
    if os.environ.get("CHECK_ONLY") != "1":
        known |= set(sample_hosts(load_ranges()))
    range_ips = set(known)
    ips = set(known)

    # fetch the records' current IPs (also makes sure they get probed)
    record_ips_now = set()
    if not DRY and ZONE and TOKEN:
        for name in RECORDS:
            try:
                recs = cf("GET", f"/zones/{ZONE}/dns_records?type=A&name={name}")
                if recs:
                    record_ips_now.add(recs[0]["content"])
            except Exception as e:
                log(f"warning: failed to fetch current record {name}: {e}")
    ips |= record_ips_now

    # CHECK_ONLY: cap the recheck set to (live record IPs + fastest known candidates)
    # so huge pools (1000+ found IPs) still finish well inside the 30-min cycle
    # even at WORKERS=1. Full pool discovery continues via the scanner.
    if os.environ.get("CHECK_ONLY") == "1":
        TOPN = int(os.environ.get("CHECK_TOP_N", 60))
        if len(ips) > TOPN:
            ranked = sorted(state.items(), key=lambda kv: kv[1].get("ms", 9999))
            keep = {ip for ip, _ in ranked[:TOPN]} | record_ips_now
            for ip in known:                     # fill remaining slots with finds not yet in state
                if len(keep) >= TOPN:
                    break
                if ip not in state:
                    keep.add(ip)
            ips = keep

    log(f"probing {len(ips)} IPs{' (dry)' if DRY else ''} ...")
    fresh = asyncio.run(scan(sorted(ips)))
    log(f"{len(fresh)} alive")
    for ip, ms in fresh.items():
        state[ip] = {"ms": ms, "ts": now}
    save(state)

    if not fresh:
        log("no alive relay found; DNS untouched"); return

    relay_fresh = {ip: ms for ip, ms in fresh.items() if ip in range_ips}
    pool = relay_fresh or fresh
    used = set()
    for name in RECORDS:
        recs = []
        if not DRY and ZONE and TOKEN:
            try:
                recs = cf("GET", f"/zones/{ZONE}/dns_records?type=A&name={name}")
            except Exception as e:
                # API unreachable: NEVER assume the record is missing (that would
                # create duplicates) — leave it untouched and retry next pass.
                log(f"error querying {name}: {e}; skipping this pass")
                continue
        rec = recs[0] if recs else None
        for extra in recs[1:]:                   # self-heal duplicate records if any exist
            try:
                cf("DELETE", f"/zones/{ZONE}/dns_records/{extra['id']}")
                log(f"removed duplicate {name} -> {extra['content']}")
            except Exception as e:
                log(f"warning: could not remove duplicate {name}: {e}")
        cur = rec["content"] if rec else None
        cand = {ip: ms for ip, ms in pool.items() if ip not in used}
        if not cand:
            log(f"{name}: no free alive relay; untouched"); continue
        best = min(cand, key=cand.get)
        cur_ms = fresh.get(cur)
        cur_is_relay = cur in range_ips
        dup_cur = cur in used   # another record already claimed this IP this run
        if DRY:
            log(f"[dry] would ensure {name} -> {best} ({fresh[best]}ms); current={cur} ({cur_ms})")
            used.add(best); continue
        try:
            if cur is None:
                cf("POST", f"/zones/{ZONE}/dns_records",
                   {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
                log(f"created {name} -> {best} ({fresh[best]}ms)")
            elif not cur_is_relay or cur_ms is None or dup_cur or fresh[best] + MARGIN_MS < cur_ms:
                cf("PUT", f"/zones/{ZONE}/dns_records/{rec['id']}",
                   {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
                why = ("dead" if cur_ms is None else
                       "duplicate" if dup_cur else
                       "not-a-relay" if not cur_is_relay else "faster")
                log(f"switched {name}: {cur} ({cur_ms}ms) -> {best} ({fresh[best]}ms) [{why}]")
            else:
                log(f"keeping {name}={cur} ({cur_ms}ms); best alt {best} {fresh[best]}ms")
        except Exception as e:
            log(f"error updating {name}: {e}; will retry next pass")
        if cur and cur_ms is not None:
            used.add(cur)
        used.add(best)

if __name__ == "__main__":
    main()
