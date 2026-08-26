"""Continuous subnet scanner with learned priority.
- walks ranges.txt exhaustively, resumable cursor, WORKERS<=8
- records hits per /24 in hits.json
- each new cycle sorts nets: most-productive /24s FIRST, dead ones last
- appends finds to foundedIPs.txt + shared state.json"""
import asyncio, ipaddress, json, os, ssl, time

BASE    = os.path.dirname(os.path.abspath(__file__))
WORKERS = int(os.environ.get("WORKERS", 8))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", 6))
DOMAIN  = os.environ["CF_DOMAIN"]
RANGES  = os.path.join(BASE, "ranges.txt")
FOUND   = os.path.join(BASE, "foundedIPs.txt")
STATE   = os.path.join(BASE, "state.json")
CURSOR  = os.path.join(BASE, "cursor.json")
HITS    = os.path.join(BASE, "hits.json")
CTX     = ssl.create_default_context()

def log(m): print(time.strftime("%F %T"), m, flush=True)

def _load(p):
    if os.path.exists(p):
        with open(p) as f: return json.load(f)
    return None

def _save(p, d):
    tmp = p + ".tmp"
    with open(tmp, "w") as f: json.dump(d, f)
    os.replace(tmp, p)

def nets():
    out = []
    for ln in open(RANGES):
        ln = ln.split("#")[0].strip()
        if ln:
            n = ipaddress.ip_network(ln, strict=False)
            if n.num_addresses >= 64:
                out.append(n)
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
            return (ip, ms) if line.startswith(b"HTTP/") else None
        except Exception:
            return None

async def run_cycle():
    sem = asyncio.Semaphore(WORKERS)
    allnets = prioritize(nets())
    cur = _load(CURSOR) or {"i": 0, "j": 0}
    log(f"start: {len(allnets)} nets, resume at #{cur['i']} (+{cur['j']})")
    total = 0
    for i in range(cur["i"], len(allnets)):
        net = allnets[i]
        chunks = []
        for s24 in slash24s(net):
            hosts = [str(h) for h in s24.hosts()]
            for j in range(0, len(hosts), 200):
                chunks.append(hosts[j:j + 200])
        j0 = cur["j"]
        for k in range(j0 // 200, len(chunks)):
            chunk = chunks[k]
            res = await asyncio.gather(*(probe(ip, sem) for ip in chunk))
            hits_now = [x for x in res if x]
            if hits_now:
                st = _load(STATE) or {}
                hh = _load(HITS) or {}
                now = time.time()
                with open(FOUND, "a") as f:
                    for ip, ms in sorted(hits_now, key=lambda x: x[1]):
                        f.write(f"{ip} {ms}\n")
                        log(f"FOUND {ip} {ms}ms")
                        st[ip] = {"ms": ms, "ts": now}
                        s24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                        hh[s24] = hh.get(s24, 0) + 1
                _save(STATE, st)
                _save(HITS, hh)
            cur = {"i": i, "j": (k + 1) * 200}
            _save(CURSOR, cur)
            total += len(hits_now)
        cur = {"i": i + 1, "j": 0}
        _save(CURSOR, cur)
    log(f"cycle complete: {total} new alive. restarting with fresh priorities.")
    _save(CURSOR, {"i": 0, "j": 0})

if __name__ == "__main__":
    asyncio.run(run_cycle())
