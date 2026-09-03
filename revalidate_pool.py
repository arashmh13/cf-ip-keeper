#!/usr/bin/env python3
"""One-off maintenance: STRICTLY revalidate every found-IP pool.
Keeps only IPs that serve the domain with a real 2xx. Purges 403/1034
"Edge IP Restricted" IPs from foundedIPs/state/hits so keepers never
assign them and hot-/24 priority learning is honest again.
Usage: python3 revalidate_pool.py   (run from the project dir; reads keeper.env)"""
import asyncio, ipaddress, json, os, ssl, time

BASE = os.path.dirname(os.path.abspath(__file__))

# standalone env read (works even when called directly, not via wrapper)
env = {}
for ln in open(os.path.join(BASE, "keeper.env"), encoding="utf-8", errors="ignore"):
    ln = ln.strip()
    if ln and "=" in ln and not ln.startswith("#"):
        k, v = ln.split("=", 1)
        env[k.strip()] = v.strip()

DOMAIN = env.get("CF_DOMAIN", "")
assert DOMAIN, "CF_DOMAIN missing from keeper.env"
WORKERS = 8        # home network: >8 concurrent TLS probes false-kill
TIMEOUT = 6.0
CTX = ssl.create_default_context()

def log(m):
    print(time.strftime("%F %T"), m, flush=True)

SECTIONS = ["", "Hetzner", "AmazonAWS", "Aeza", "DigitalOcean", "EthernetServer", "IONOS"]

def fname(base, sec, ext):
    return os.path.join(BASE, f"{base}{('_' + sec) if sec else ''}.{ext}")

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
            parts = line.split()
            ok = (len(parts) >= 2 and parts[0].startswith(b"HTTP/")
                  and parts[1].isdigit() and 200 <= int(parts[1]) < 300)
            return (ip, ms) if ok else None
        except Exception:
            return None

async def scan(ips):
    sem = asyncio.Semaphore(WORKERS)
    res = await asyncio.gather(*(probe(i, sem) for i in ips))
    return {r[0]: r[1] for r in res if r}

def fsync_save(path, data_text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data_text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

async def main():
    log(f"strict revalidation of all pools against {DOMAIN} (2xx only)")
    for sec in SECTIONS:
        tag = sec or "Iran(main)"
        fpath = fname("foundedIPs", sec, "txt")
        if not os.path.exists(fpath):
            log(f"[{tag}] no pool file; skip")
            continue
        ips = []
        for ln in open(fpath, encoding="utf-8", errors="ignore"):
            p = ln.split()
            if p and p[0].count(".") == 3:
                ips.append(p[0])
        ips = list(dict.fromkeys(ips))          # dedupe, keep order
        if not ips:
            log(f"[{tag}] empty pool; skip")
            continue
        log(f"[{tag}] probing {len(ips)} found IPs strictly ...")
        good = await scan(ips)
        now = time.time()
        # rewrite pool
        fsync_save(fpath, "".join(f"{ip} {good[ip]}\n" for ip in good))
        # rewrite state: only survivors
        state = {ip: {"ms": ms, "ts": now} for ip, ms in good.items()}
        fsync_save(fname("state", sec, "json"), json.dumps(state, indent=1))
        # recompute hits from survivors only
        hits = {}
        for ip in good:
            s24 = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            hits[s24] = hits.get(s24, 0) + 1
        fsync_save(fname("hits", sec, "json"), json.dumps(hits, indent=1))
        log(f"[{tag}] kept {len(good)}/{len(ips)} ({100*len(good)//max(len(ips),1)}%)")
    log("REVALIDATION-DONE")

if __name__ == "__main__":
    asyncio.run(main())
