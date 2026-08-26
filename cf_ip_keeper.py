#!/usr/bin/env python3
"""Keeps a grey-cloud A record pointed at a live CN relay IP that fronts your Cloudflare zone.
VLESS address = RECORD (grey cloud), SNI/Host = DOMAIN. Stdlib only, Python 3.10+."""
import asyncio, ipaddress, json, os, random, ssl, sys, time, urllib.request

BASE   = os.path.dirname(os.path.abspath(__file__))
DRY    = "--dry" in sys.argv
DOMAIN = os.environ["CF_DOMAIN"]   # real proxied domain (vless sni + host)
RECORD = os.environ.get("CF_RECORD", "")   # legacy single-record name
# backup subdomains: comma-separated, each gets its OWN distinct relay
RECORDS = [r.strip() for r in os.environ.get("CF_RECORDS", RECORD).split(",") if r.strip()]
TOKEN  = os.environ["CF_TOKEN"]
ZONE   = os.environ["CF_ZONE_ID"]
PORT, TIMEOUT  = 443, float(os.environ.get("PROBE_TIMEOUT", 2.0))
PROBE_BUDGET   = int(os.environ.get("PROBE_BUDGET", 600))
WORKERS        = int(os.environ.get("WORKERS", 200))
MARGIN_MS      = int(os.environ.get("MARGIN_MS", 30))
KEEP           = 300
STATE  = os.path.join(BASE, "state.json")
CTX    = ssl.create_default_context()   # cert verification ON: probe only passes if IP fronts YOUR domain's cert

def log(m): print(time.strftime("%F %T"), m, flush=True)

def cf(method, path, body=None):
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        method=method)
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.load(r)
    if not d.get("success"):
        raise RuntimeError(d.get("errors"))
    return d["result"]

def hosts_of(n):
    # ponytail: ranges > /20 get 256 random draws instead of full enumeration; split big blocks in ranges.txt if you want exhaustive
    if n.num_addresses <= 4096:
        return [str(h) for h in n.hosts()]
    base = int(n.network_address)
    return [str(ipaddress.ip_address(base + random.randrange(1, n.num_addresses - 1))) for _ in range(256)]

def load_ranges():
    nets = []
    with open(os.path.join(BASE, "ranges.txt")) as f:
        for ln in f:
            ln = ln.split("#")[0].strip()
            if ln:
                nets.append(ipaddress.ip_network(ln, strict=False))
    return nets

RANGES_URL = os.environ.get("RANGES_URL", "")   # e.g. https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt

def ensure_ranges():
    p = os.path.join(BASE, "ranges.txt")
    if RANGES_URL and (not os.path.exists(p) or time.time() - os.path.getmtime(p) > 604800):
        req = urllib.request.Request(RANGES_URL, headers={"User-Agent": "curl/8.5"})  # some CDNs 403 the default python UA
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
    with open(tmp, "w") as f:
        json.dump(dict(sorted(state.items(), key=lambda kv: kv[1]["ms"])), f, indent=1)
    os.replace(tmp, STATE)

def main():
    state = {}
    if os.path.exists(STATE):
        with open(STATE) as f: state = json.load(f)
    now = time.time()
    state = {ip: v for ip, v in state.items() if now - v["ts"] < 86400}

    if RANGES_URL and "--dry" not in sys.argv:
        ensure_ranges()                  # auto-download / weekly refresh
    known = set(state.keys())            # all found relays from last 24h
    ffound = os.path.join(BASE, "foundedIPs.txt")
    if os.path.exists(ffound):           # every IP the scanner ever found stays under health-check
        for ln in open(ffound):
            ip = ln.split()[0]
            if ip.count(".") == 3:
                known.add(ip)
    if os.environ.get("CHECK_ONLY") != "1":     # checker mode: skip subnet sampling
        known |= set(sample_hosts(load_ranges()))
    range_ips = known
    ips = set(known)
    rec = None
    if not DRY:                          # dry mode never touches the API
        for name in RECORDS:             # health-check every record's current IP
            recs = cf("GET", f"/zones/{ZONE}/dns_records?type=A&name={name}")
            if recs:
                ips.add(recs[0]["content"])
    log(f"probing {len(ips)} IPs{' (dry)' if DRY else ''} ...")
    fresh = asyncio.run(scan(sorted(ips)))
    log(f"{len(fresh)} alive")
    for ip, ms in fresh.items():
        state[ip] = {"ms": ms, "ts": now}
    save(state)

    if not fresh:
        log("no alive relay found; DNS untouched"); return
    # prefer relays found in ranges; current record IP only as last-resort fallback
    relay_fresh = {ip: ms for ip, ms in fresh.items() if ip in range_ips}
    pool = relay_fresh or fresh
    used = set()                             # each record gets a DISTINCT relay
    for name in RECORDS:
        recs = DRY and [] or cf("GET", f"/zones/{ZONE}/dns_records?type=A&name={name}")
        rec = recs[0] if recs else None
        cur = rec["content"] if rec else None
        cand = {ip: ms for ip, ms in pool.items() if ip not in used}
        if not cand:
            log(f"{name}: no free alive relay; untouched"); continue
        best = min(cand, key=cand.get)
        cur_ms = fresh.get(cur)
        cur_is_relay = cur in range_ips
        if DRY:
            log(f"[dry] would ensure {name} -> {best} ({fresh[best]}ms); current={cur} ({cur_ms})")
            used.add(best); continue
        if cur is None:
            cf("POST", f"/zones/{ZONE}/dns_records",
               {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
            log(f"created {name} -> {best} ({fresh[best]}ms)")
        elif not cur_is_relay:                   # placeholder/edge in record -> real relay
            cf("PUT", f"/zones/{ZONE}/dns_records/{rec['id']}",
               {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
            log(f"switched {name}: {cur} ({cur_ms}ms) -> {best} ({fresh[best]}ms)")
        elif cur_ms is None or fresh[best] + MARGIN_MS < cur_ms:
            cf("PUT", f"/zones/{ZONE}/dns_records/{rec['id']}",
               {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
            log(f"switched {name}: {cur} ({cur_ms}ms) -> {best} ({fresh[best]}ms)")
        else:
            log(f"keeping {name}={cur} ({cur_ms}ms); best alt {best} {fresh[best]}ms")
        if cur and cur_ms is not None:
            used.add(cur)                # keep current assignment distinct from the next record
        used.add(best)

if __name__ == "__main__":
    main()
