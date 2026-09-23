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

def legacy_path(base_name, ext="txt"):
    """Un-namespaced path (pre-SECTION history). Iran used to run as the default
    section, so its earlier finds/pool live under these legacy names."""
    return os.path.join(BASE, f"{base_name}.{ext}")

def read_paths(base_name, ext="txt"):
    """Files that may hold THIS section's data, namespaced first.

    Only merge the legacy name for Iran/default: for a real section (Hetzner,
    Aeza, ...) the un-namespaced file holds a DIFFERENT section's IPs, and
    merging it would let foreign IPs into that section's pool.
    """
    out = [get_filename(base_name, ext)]
    if SECTION and SECTION.lower() in ("default", "main", "iran"):
        lp = legacy_path(base_name, ext)
        if lp not in out:
            out.append(lp)
    return out

DOMAIN = os.environ.get("CF_DOMAIN", "").strip()   # real proxied domain (vless sni + host)
RECORD = os.environ.get("CF_RECORD", "").strip()   # legacy single-record name
# backup subdomains: comma-separated, each gets its OWN distinct relay
RECORDS = [r.strip() for r in os.environ.get("CF_RECORDS", RECORD).split(",") if r.strip()]
TOKEN  = os.environ.get("CF_TOKEN", "").strip()
ZONE   = os.environ.get("CF_ZONE_ID", "").strip()
PORT, TIMEOUT  = 443, float(os.environ.get("PROBE_TIMEOUT", 6.0))
# Offline-test hook: pin probe latencies so a pass is deterministic. Empty in
# production (real measured latencies are used).
FAKE_LATENCY = {}
for _pair in os.environ.get("FAKE_LATENCY", "").split(","):
    if "=" in _pair:
        _k, _v = _pair.split("=", 1)
        try: FAKE_LATENCY[_k.strip()] = int(_v)
        except ValueError: pass
PROBE_BUDGET   = int(os.environ.get("PROBE_BUDGET", 600))
WORKERS        = int(os.environ.get("WORKERS", 8))
MARGIN_MS      = int(os.environ.get("MARGIN_MS", 30))
KEEP           = 300
# Ground truth: validate on the REAL VLESS path, not just /. Some edges serve /
# with 2xx but 403 the xhttp path — those are useless for the client.
VLESS_PATH     = os.environ.get("CF_VLESS_PATH", "/").strip()
# Geo gate (optional): a CIDR list file; only IPs inside these nets may ever be
# assigned to this section's records. Set ONLY for sections that must stay
# country-pure (e.g. Iran); other sections simply don't set GATE_FILE.
GATE_FILE = os.environ.get("GATE_FILE", "").strip()
GATE_NETS = []
if GATE_FILE and os.path.exists(GATE_FILE):
    with open(GATE_FILE, encoding="utf-8", errors="ignore") as _f:
        for _ln in _f:
            _ln = _ln.split("#")[0].strip()
            if _ln:
                try: GATE_NETS.append(ipaddress.ip_network(_ln, strict=False))
                except ValueError: pass

def gate(ip):
    if not GATE_NETS:
        return True
    try:
        _a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(_a in _n for _n in GATE_NETS)

# Optional live-country gate (e.g. GATE_COUNTRY=IR): an IP must ALSO geo-locate
# to this country. The lookup must go through GEO_PROXY on this box (its DNS is
# only resolvable through the local proxy: direct lookups fail with
# "Temporary failure in name resolution", which silently disabled this gate).
GATE_COUNTRY = os.environ.get("GATE_COUNTRY", "").strip()
# Fail-closed switch: GEO_STRICT=1 rejects candidates whose country cannot be
# resolved (gea API down) instead of trusting the CIDR list alone.
GEO_STRICT = os.environ.get("GEO_STRICT", "0").strip() not in ("0", "false", "no", "")
GEO_PROXY = os.environ.get("GEO_PROXY", os.environ.get("CF_API_PROXY", "")).strip()
# Countries verified earlier are remembered on disk, so a geo-API outage cannot
# force the keeper to either trust an unverified IP or leave a duplicate in DNS.
GEO_CACHE_FILE = get_filename("geo_cache", "json")
GEO_CACHE_TTL = int(os.environ.get("GEO_CACHE_TTL", 604800))   # 7 days
_geo_cache = {}          # ip -> "IR"/"NL"/...  (or None when geo unavailable)
_geo_disk = {}

def _geo_disk_load():
    global _geo_disk
    try:
        with open(GEO_CACHE_FILE, encoding="utf-8") as f:
            _geo_disk = json.load(f)
    except Exception:
        _geo_disk = {}

def _geo_disk_save():
    try:
        tmp = GEO_CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_geo_disk, f, indent=1)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, GEO_CACHE_FILE)
    except Exception:
        pass

_geo_disk_load()

def geo_country(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    cc = None
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/" + ip + "?fields=status,countryCode",
            headers={"User-Agent": "curl/8.5"})
        if GEO_PROXY:
            _op = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": GEO_PROXY, "https": GEO_PROXY}))
            with _op.open(req, timeout=8) as r:
                d = json.load(r)
        else:
            with urllib.request.urlopen(req, timeout=8) as r:
                d = json.load(r)
        cc = d.get("countryCode") if d.get("status") == "success" else None
    except Exception:
        cc = None
    if cc:
        if _geo_disk.get(ip, {}).get("cc") != cc:
            _geo_disk[ip] = {"cc": cc, "ts": time.time()}
            _geo_disk_save()
    else:
        # lookup failed: fall back to a country verified earlier (survives an
        # ip-api outage) so the country gate keeps working instead of no-op'ing.
        e = _geo_disk.get(ip) or {}
        if e.get("cc") and time.time() - e.get("ts", 0) < GEO_CACHE_TTL:
            cc = e["cc"]
    _geo_cache[ip] = cc
    return cc

def geo_ok(ip):
    """True when live geo matches GATE_COUNTRY. When the lookup is unavailable,
    fail OPEN by default (don't lock out a working relay) but fail CLOSED when
    GEO_STRICT=1 (country purity is worth more than a swap this pass)."""
    if not GATE_COUNTRY:
        return True
    cc = geo_country(ip)
    if cc is None:
        return not GEO_STRICT
    return cc == GATE_COUNTRY

# Optional HTTP proxy for the Cloudflare API only (probes stay DIRECT — never
# proxied, latency must be real). Used when the local route to
# api.cloudflare.com is flaky (Iranian 4G black-holing).
API_PROXY = os.environ.get("CF_API_PROXY", "").strip()
# API endpoint (overridable ONLY for offline tests against a mock server;
# production always talks to the real Cloudflare API).
API_BASE = os.environ.get("CF_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/")
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
                f"{API_BASE}{path}",
                data=json.dumps(body).encode() if body else None,
                headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
                method=method)
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.load(r)
            except Exception:
                if not API_PROXY:
                    raise
                _op = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": API_PROXY, "https": API_PROXY}))
                with _op.open(req, timeout=25) as r:
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
            w.write(f"GET {VLESS_PATH} HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), TIMEOUT)
            ms = round((time.perf_counter() - t0) * 1000)
            w.close()
            try: await w.wait_closed()
            except Exception: pass
            # STRICT: only a real 2xx counts. 403 "error code: 1034" (Edge IP
            # Restricted) means the edge refuses to proxy this zone — useless for VLESS.
            parts = line.split()
            ok = (len(parts) >= 2 and parts[0].startswith(b"HTTP/")
                  and parts[1].isdigit() and 200 <= int(parts[1]) < 300)
            if ok and FAKE_LATENCY:
                # offline-test hook: fixed latencies make keeper passes
                # deterministic (real network jitter would cause false churn)
                ms = FAKE_LATENCY.get(ip, ms)
            return (ip, ms) if ok else None
        except Exception:
            return None

async def scan(ips):
    sem = asyncio.Semaphore(WORKERS)
    res = await asyncio.gather(*(probe(i, sem) for i in ips))
    return {r[0]: r[1] for r in res if r}

def save(state):
    # merge with the on-disk state under an flock so a concurrent scanner write
    # is never clobbered by the keeper (and vice versa).
    try:
        import fcntl
    except Exception:
        fcntl = None
    fh = None
    if fcntl:
        try:
            fh = open(STATE + ".lock", "w")
            fcntl.flock(fh, fcntl.LOCK_EX)
        except Exception:
            fh = None
    try:
        if os.path.exists(STATE):
            try:
                with open(STATE, encoding="utf-8") as f:
                    disk = json.load(f)
            except Exception:
                disk = {}
            for ip, v in disk.items():
                if ip not in state or v.get("ts", 0) > state[ip].get("ts", 0):
                    state[ip] = v
        tmp = STATE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dict(sorted(state.items(), key=lambda kv: kv[1]["ms"])), f, indent=1)
            f.flush()
            os.fsync(f.fileno())          # power-loss safe
        os.replace(tmp, STATE)
    finally:
        if fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_UN)
            except Exception:
                pass
            fh.close()


def plan_records(records, live, pool, margin_ms, avoid=None):
    """PURE decision core: give every record its OWN distinct IP.

    records : record names in priority order (cn before cn2 - config order)
    live    : {name: ip or None}  live DNS content (None = unknown -> skip)
    pool    : {ip: ms} alive + gate-passing candidates
    avoid   : {ip: "owner-name"}  IPs already used by records OUTSIDE this
              section (other systems' records). Prefer not to collide with
              them, but they are allowed if nothing else is alive.
    returns : {"assign": {...}, "keep": {...}, "skip": {...}, "forced": set,
               "unresolved": {...}}

    Guarantee: an IP already owned by a sibling can never be handed to another
    record, and a record sharing its IP with a sibling is forced to move — even
    when that shared IP is the fastest one available. If nothing else is alive,
    the record is marked "unresolved" instead of silently keeping the duplicate,
    so the keeper can never leave cn == cn2 behind.
    """
    avoid = avoid or {}
    owner = {}
    for name in records:                       # first record in order owns a shared IP
        ip = live.get(name)
        if ip and ip not in owner:
            owner[ip] = name
    forced = {n for n in records if live.get(n) and owner.get(live[n]) != n}

    assign, keep, skip, unresolved = {}, {}, {}, {}
    claimed = set()
    for name in records:
        cur = None if name in forced else live.get(name)
        free = {ip: ms for ip, ms in pool.items()
                if ip not in claimed and owner.get(ip, name) == name}
        if not free:
            if name in forced:
                # This record shares an IP with a sibling and there is nothing
                # else alive to move it to. Leaving it alone would keep the
                # duplicate, so report it as unresolved for the caller to retry.
                unresolved[name] = "duplicate but no alternative alive"
            else:
                skip[name] = "no free alive relay"
            continue
        # prefer an IP no other record in the zone currently uses
        clear = {ip: ms for ip, ms in free.items() if ip not in avoid}
        best = min(clear or free, key=(clear or free).get)
        cur_ok = (cur is not None and cur in pool and owner.get(cur, name) == name)
        collides = bool(cur_ok and cur in avoid)   # another system's record holds it
        if collides and clear:
            # Our IP is also used by a record this keeper does not manage.
            # A distinct IP is strictly better than a shared one, so move even
            # when the alternative is only marginally faster/slower.
            assign[name] = best
            claimed.add(best)
            owner[best] = name
        elif cur_ok and (best == cur or pool[best] + margin_ms >= pool[cur]):
            keep[name] = cur
            claimed.add(cur)
            owner.setdefault(cur, name)
        else:
            assign[name] = best
            claimed.add(best)
            owner[best] = name
    return {"assign": assign, "keep": keep, "skip": skip,
            "forced": forced, "unresolved": unresolved}

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
    nfound = 0
    for ffound in read_paths("foundedIPs", "txt"):
        if not os.path.exists(ffound):
            continue
        for ln in open(ffound, encoding="utf-8", errors="ignore"):
            parts = ln.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3:
                    known.add(ip)
                    nfound += 1
    if nfound:
        log(f"pool: {len(known)} candidates from {len(read_paths('foundedIPs','txt'))} file(s)")
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
    if GATE_NETS:
        # geo-gate every candidate; even the live record IPs (a foreign/dead
        # current then shows cur_ms=None -> "not-a-relay/dead" -> replaced)
        ips = {ip for ip in ips if ip.count(".") == 3 and gate(ip) and geo_ok(ip)}

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

    relay_fresh = {ip: ms for ip, ms in fresh.items() if ip in range_ips and gate(ip) and geo_ok(ip)}
    pool = relay_fresh or {ip: ms for ip, ms in fresh.items() if gate(ip) and geo_ok(ip)}

    # ---- read live DNS first: the decision must be based on what is ACTUALLY
    # deployed, not on a possibly-stale local cache -------------------------
    DNSC = get_filename("dns_cache", "json")
    live, rec_id, unknown = {}, {}, set()
    mine = set(RECORDS)
    zone_used = {}        # ip -> name of a record this keeper does NOT manage
    if not DRY and ZONE and TOKEN:
        try:
            allrecs = cf("GET", f"/zones/{ZONE}/dns_records?type=A&per_page=200")
            for r in allrecs:
                if r["name"] not in mine and r.get("content"):
                    zone_used.setdefault(r["content"], r["name"].split(".")[0])
        except Exception as e:
            log(f"warning: could not list zone records ({e}); cross-record "
                f"collision avoidance is off this pass")
    for name in RECORDS:
        if DRY or not (ZONE and TOKEN):
            live[name] = None
            continue
        try:
            recs = cf("GET", f"/zones/{ZONE}/dns_records?type=A&name={name}")
        except Exception as e:
            # API unreachable for this record: never assume it is missing
            # (a blind POST would create a duplicate record).
            log(f"error querying {name}: {e}")
            unknown.add(name)
            continue
        rec = recs[0] if recs else None
        for extra in recs[1:]:                   # self-heal duplicate records if any exist
            try:
                cf("DELETE", f"/zones/{ZONE}/dns_records/{extra['id']}")
                log(f"removed duplicate {name} -> {extra['content']}")
            except Exception as e:
                log(f"warning: could not remove duplicate {name}: {e}")
        live[name] = rec["content"] if rec else ""
        if rec:
            rec_id[name] = rec["id"]

    if unknown:
        # We cannot see every sibling's real IP, so "cn != cn2" cannot be
        # guaranteed this pass. Writing anything now could CREATE the very
        # duplicate this keeper exists to prevent (e.g. POST a record that
        # already exists). Do nothing and let the next 30-min pass retry.
        log(f"live DNS unknown for {sorted(n.split('.')[0] for n in unknown)}; "
            f"skipping ALL dns writes this pass")
        return

    # pool must never contain an IP that a sibling record still owns in live DNS
    # (an unknown '' content is not an owner; a known IP is).
    live_owned = {}
    for name in RECORDS:
        ip = live.get(name)
        if ip:
            live_owned.setdefault(ip, name)
    if DRY:
        log("[dry] would plan " + ", ".join(f"{n.split('.')[0]}={live.get(n) or '-'}" for n in RECORDS))
    pool = {ip: ms for ip, ms in pool.items() if ip not in zone_used} or pool
    plan = plan_records(RECORDS, live, pool, MARGIN_MS, avoid=zone_used)

    # If a record shares an IP with a sibling and nothing else is alive yet, the
    # pool is too thin to satisfy "cn != cn2". Expand the probe set with the
    # remaining known candidates and re-plan (the absolute rule wins over cost).
    expand_rounds = 0
    while plan["unresolved"] and expand_rounds < 3:
        expand_rounds += 1
        unprobed = sorted(known - set(fresh))
        if not unprobed:
            break
        budget = int(os.environ.get("EXPAND_BUDGET", 180))
        take = unprobed[:budget]
        log(f"{len(plan['unresolved'])} record(s) unresolved; probing {len(take)} "
            f"more candidates (round {expand_rounds})")
        more = asyncio.run(scan(take))
        if not more:
            break
        fresh.update(more)
        for ip, ms in more.items():
            state[ip] = {"ms": ms, "ts": now}
        save(state)
        all_ok = {ip: ms for ip, ms in fresh.items() if gate(ip) and geo_ok(ip)}
        relay_ok = {ip: ms for ip, ms in all_ok.items() if ip in range_ips}
        pool = relay_ok or all_ok
        # keep live_owned in sync (unchanged: live DNS is untouched so far)
        pool = {ip: ms for ip, ms in pool.items() if ip not in zone_used} or pool
        plan = plan_records(RECORDS, live, pool, MARGIN_MS, avoid=zone_used)

    def _save_cache():
        tmp = DNSC + ".tmp"
        with open(tmp, "w", encoding="utf-8") as _f:
            json.dump(dnsc, _f, indent=1)
            _f.flush(); os.fsync(_f.fileno())
        os.replace(tmp, DNSC)

    dnsc = {}
    if os.path.exists(DNSC):
        try:
            with open(DNSC, encoding="utf-8") as _f: dnsc = json.load(_f)
        except Exception: pass

    if plan["forced"]:
        log(f"duplicate detected in live DNS; forcing move: {sorted(plan['forced'])}")
    for name in plan["skip"]:
        log(f"{name}: {plan['skip'][name]}; untouched")
    for name in plan.get("unresolved", {}):
        log(f"{name}: {plan['unresolved'][name]}; DNS LEFT AS-IS (will retry next pass)")

    # ---- write phase: keep or move, one IP per record ---------------------
    for name in RECORDS:
        if name in plan["keep"]:
            ip = plan["keep"][name]
            dnsc[name] = {"ip": ip, "ms": fresh.get(ip), "ts": now}
            log(f"keeping {name}={ip} ({fresh.get(ip)}ms)")
            continue
        if name not in plan["assign"]:
            continue
        best = plan["assign"][name]
        cur = live.get(name) or None
        cur_ms = fresh.get(cur)
        why = ("dead" if cur and cur_ms is None else
               "duplicate" if (cur and live_owned.get(cur) != name) else
               "not-a-relay" if (cur and cur not in range_ips) else "faster")
        if DRY:
            log(f"[dry] would set {name} -> {best} ({fresh[best]}ms); current={cur} ({cur_ms}) [{why}]")
            continue
        try:
            if not cur:
                cf("POST", f"/zones/{ZONE}/dns_records",
                   {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
                log(f"created {name} -> {best} ({fresh[best]}ms)")
            else:
                cf("PUT", f"/zones/{ZONE}/dns_records/{rec_id[name]}",
                   {"type": "A", "name": name, "content": best, "ttl": 60, "proxied": False})
                log(f"switched {name}: {cur} ({cur_ms}ms) -> {best} ({fresh[best]}ms) [{why}]")
            dnsc[name] = {"ip": best, "ms": fresh.get(best), "ts": now}
        except Exception as e:
            log(f"error updating {name}: {e}; will retry next pass")
            continue

    # final invariant check: if the same IP is still on two sibling records,
    # scream about it in the log rather than staying silent.
    by_ip = {}
    for name, c in dnsc.items():
        ip = c.get("ip")
        if ip:
            by_ip.setdefault(ip, []).append(name.split(".")[0])
    for ip, labels in by_ip.items():
        if len(labels) > 1:
            log(f"WARNING: duplicate assignment still present {ip} -> {labels}")
    _save_cache()

if __name__ == "__main__":
    main()
