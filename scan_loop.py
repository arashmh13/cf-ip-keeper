"""Continuous subnet scanner with learned priority and section support.
- walks ranges[_<section>].txt exhaustively, resumable cursor
- records hits per /24 in hits[_<section>].json
- each new cycle sorts nets: most-productive /24s FIRST, dead ones last
- appends finds to foundedIPs[_<section>].txt + shared state[_<section>].json"""
import asyncio, ipaddress, json, os, ssl, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
SECTION = os.environ.get("SECTION", "")
for idx, arg in enumerate(sys.argv):
    if arg == "--section" and idx + 1 < len(sys.argv):
        SECTION = sys.argv[idx + 1]

def get_filename(base_name, ext="txt"):
    if not SECTION or SECTION.lower() in ("default", "main"):
        return os.path.join(BASE, f"{base_name}.{ext}")
    return os.path.join(BASE, f"{base_name}_{SECTION}.{ext}")

WORKERS = int(os.environ.get("WORKERS", 8))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", 6))
DOMAIN  = os.environ.get("CF_DOMAIN", "").strip()
RANGES  = get_filename("ranges", "txt")
FOUND   = get_filename("foundedIPs", "txt")
STATE   = get_filename("state", "json")
CURSOR  = get_filename("cursor", "json")
HITS    = get_filename("hits", "json")
CTX     = ssl.create_default_context()

def log(m):
    prefix = f"[{SECTION}] " if SECTION else ""
    print(time.strftime("%F %T"), f"{prefix}{m}", flush=True)

def _load(p):
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f: return json.load(f)
        except Exception:
            return None
    return None

def _save(p, d):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
        f.flush()
        os.fsync(f.fileno())          # power-loss safe: data reaches disk
    os.replace(tmp, p)
    # fsync the directory so the rename itself survives power loss
    dfd = os.open(os.path.dirname(p) or ".", os.O_RDONLY)
    try: os.fsync(dfd)
    finally: os.close(dfd)

def nets():
    rpath = RANGES
    if not os.path.exists(rpath):
        default_p = os.path.join(BASE, "ranges.txt")
        if os.path.exists(default_p):
            rpath = default_p
        else:
            return []
    out = []
    with open(rpath, encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.split("#")[0].strip()
            if ln:
                try:
                    n = ipaddress.ip_network(ln, strict=False)
                    if n.num_addresses >= 4:
                        out.append(n)
                except ValueError:
                    pass
    return out

def slash24s(net):
    if net.prefixlen >= 24:
        return [net]
    first = int(net.network_address) >> 8
    last = int(net.broadcast_address) >> 8
    return [ipaddress.ip_network(f"{ipaddress.ip_address(k << 8)}/24")
            for k in range(first, last + 1)]

def prioritize(allnets):
    hits = _load(HITS) or {}
    def score(net):
        return sum(hits.get(str(s24), 0) for s24 in slash24s(net))
    ranked = sorted(allnets, key=score, reverse=True)
    hot = sum(1 for n in allnets if score(n) > 0)
    log(f"priority: {hot} hot nets first ({sum(score(n) for n in allnets)} lifetime hits)")
    return ranked

async def probe(ip, sem):
    async with sem:
        t0 = time.perf_counter()
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=CTX, server_hostname=DOMAIN), TIMEOUT)
            w.write(f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n".encode())
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
            return (ip, ms) if ok else None
        except Exception:
            return None

async def run_cycle():
    if not DOMAIN:
        log("ERROR: CF_DOMAIN is required")
        sys.exit(1)
    sem = asyncio.Semaphore(WORKERS)
    allnets = prioritize(nets())
    if not allnets:
        log(f"No valid networks found in {RANGES}")
        return
    cur = _load(CURSOR) or {"i": 0, "j": 0}
    log(f"start: {len(allnets)} nets, resume at #{cur['i']} (+{cur['j']}) [workers={WORKERS}, timeout={TIMEOUT}s]")
    total = 0
    for i in range(cur.get("i", 0), len(allnets)):
        net = allnets[i]
        chunks = []
        for s24 in slash24s(net):
            hosts = [str(h) for h in s24.hosts()]
            step = max(WORKERS * 25, 100)
            for j in range(0, len(hosts), step):
                chunks.append(hosts[j:j + step])
        if not chunks:
            # For tiny blocks /31, /32
            chunks = [[str(ip) for ip in net.hosts()] or [str(net.network_address)]]

        j0 = cur.get("j", 0)
        start_k = 0
        if i == cur.get("i", 0) and j0 > 0:
            step = max(WORKERS * 25, 100)
            start_k = min(j0 // step, len(chunks))

        for k in range(start_k, len(chunks)):
            chunk = chunks[k]
            res = await asyncio.gather(*(probe(ip, sem) for ip in chunk))
            hits_now = [x for x in res if x]
            if hits_now:
                st = _load(STATE) or {}
                hh = _load(HITS) or {}
                now = time.time()
                with open(FOUND, "a", encoding="utf-8") as f:
                    for ip, ms in sorted(hits_now, key=lambda x: x[1]):
                        f.write(f"{ip} {ms}\n")
                        log(f"FOUND {ip} {ms}ms")
                        st[ip] = {"ms": ms, "ts": now}
                        s24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                        hh[s24] = hh.get(s24, 0) + 1
                    f.flush()
                    os.fsync(f.fileno())   # power-loss safe: found IPs never lost
                _save(STATE, st)
                _save(HITS, hh)
            step = max(WORKERS * 25, 100)
            cur = {"i": i, "j": (k + 1) * step}
            _save(CURSOR, cur)
            total += len(hits_now)
        cur = {"i": i + 1, "j": 0}
        _save(CURSOR, cur)
    log(f"cycle complete: {total} new alive. restarting with fresh priorities.")
    _save(CURSOR, {"i": 0, "j": 0})

if __name__ == "__main__":
    asyncio.run(run_cycle())
