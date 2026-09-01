"""Generic honest probe: probe_ips.py IP [IP...] — uses CF_DOMAIN env (clean, no keeper.env)."""
import asyncio, os, ssl, sys, time

DOMAIN = os.environ.get("CF_DOMAIN", "").strip()
IPS = [a.strip() for a in sys.argv[1:] if a.strip()]
CTX = ssl.create_default_context()

async def probe(ip, sem):
    async with sem:
        t0 = time.perf_counter()
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=CTX, server_hostname=DOMAIN), 8)
            w.write(f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            line = await asyncio.wait_for(r.readline(), 8)
            ms = round((time.perf_counter() - t0) * 1000)
            w.close()
            return (ip, "ALIVE" if line.startswith(b"HTTP/") else f"BADRESP {line[:20]!r}", ms)
        except Exception as e:
            return (ip, f"DEAD {type(e).__name__}: {str(e)[:50]}", -1)

async def main():
    sem = asyncio.Semaphore(4)
    res = await asyncio.gather(*(probe(ip, sem) for ip in IPS))
    for ip, st, ms in res:
        print(f"{ip:18} {st:34} {'%dms' % ms if ms > 0 else ''}")
    print(f"SUMMARY: {sum(1 for x in res if x[1]=='ALIVE')}/{len(res)} alive  (domain={DOMAIN!r})")

asyncio.run(main())
