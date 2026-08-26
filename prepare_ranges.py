"""Clean provider range list: parse, dedupe exact, drop nets contained in bigger ones."""
import ipaddress, sys

src, dst = sys.argv[1], sys.argv[2]
seen, nets = set(), []
for ln in open(src):
    ln = ln.split("#")[0].strip()
    if not ln:
        continue
    try:
        n = ipaddress.ip_network(ln, strict=False)
    except ValueError:
        print("skip:", ln)
        continue
    if n.num_addresses < 64:
        continue
    key = (int(n.network_address), n.prefixlen)
    if key in seen:
        continue
    seen.add(key)
    nets.append(n)

# drop nets fully inside another kept net
nets.sort(key=lambda n: (int(n.network_address), -n.prefixlen))
kept, covered_until = [], -1
for n in nets:
    s, e = int(n.network_address), int(n.broadcast_address)
    if s <= covered_until:          # inside previous (bigger or equal-start) net
        continue
    kept.append(n)
    covered_until = e

total_hosts = sum(n.num_addresses - 2 for n in kept)
with open(dst, "w") as f:
    for n in kept:
        f.write(f"{n}\n")
print(f"{len(nets)} parsed -> {len(kept)} unique top-level nets, {total_hosts:,} hosts")
