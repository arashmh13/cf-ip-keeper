import json, urllib.request
env = {}
for ln in open("/DATA/cf-ip-keeper/keeper.env"):
    ln = ln.strip()
    if ln and "=" in ln and not ln.startswith("#"):
        k, v = ln.split("=", 1)
        env[k.strip()] = v.strip()
req = urllib.request.Request(
    f"https://api.cloudflare.com/client/v4/zones/{env['CF_ZONE_ID']}/dns_records?per_page=100",
    headers={"Authorization": f"Bearer {env['CF_TOKEN']}"})
d = json.load(urllib.request.urlopen(req, timeout=40))
for r in sorted(d["result"], key=lambda r: r["name"]):
    print(r["type"], r["name"], "->", r["content"], "| grey" if not r["proxied"] else "| PROXIED", "| ttl", r["ttl"])
print("TOTAL", len(d["result"]))
