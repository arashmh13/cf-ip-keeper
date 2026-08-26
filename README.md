# CF IP Keeper

Self-healing Cloudflare DNS relay keeper: continuously scans IP subnets for
live relays that front your proxied domain (real TLS + certificate +
Host-header verification — false positives are impossible), then keeps one or
more **grey-cloud** A records pinned to the fastest alive relays. If a record's
IP dies, it is replaced automatically at the next check.

Built for VLESS/VMess-style setups where you need a stable `address=` that
survives relay churn, while SNI/Host stay on your real proxied domain.

```
VLESS client ──> cn.example.com (grey A, TTL 60)  ──> live relay IP :443
                        │  auto-updated                │
                        └────────── by this tool       └── SNI/Host = example.com
                                                          (proxied/orange in CF)
```

## What it does

| Piece | Job |
|---|---|
| **Scanner** | walks your subnet list (`ranges.txt`) forever at N workers, finds relays that pass TLS-cert+Host validation, records them with latency |
| **Keeper / Checker** | every N minutes re-probes *all* found IPs **plus** whatever each managed record currently points to; replaces dead/slower IPs |
| **Multi-record** | manages several records (`cn.`, `cn2.`, …) and guarantees each gets a **different** relay |
| **Learning** | counts hits per /24; each new scan cycle starts at the most productive subnets first |

## Versions

| Version | Location | Needs |
|---|---|---|
| Linux (VPS) | `scan_daemon.sh` + cron | Python 3 (stdlib only) |
| Windows GUI | `cf_keeper_gui.py` | Python + tkinter (stdlib only) |
| Android | see Releases | none (APK) |

## Quick start — Linux VPS

```bash
# as root
mkdir -p /opt/cf-ip-keeper && cd /opt/cf-ip-keeper
# copy this repo's files here, then:
cp keeper.env.example keeper.env
nano keeper.env            # fill token / zone / domains

chmod +x *.sh
bash vps_setup.sh          # installs systemd service + 30-min cron checker

systemctl status cf-ip-scan
tail -f scanner.log        # watch FOUND lines appear
```

Full step-by-step guide (including smoke tests, multi-VPS rules,
troubleshooting, uninstall): **[SETUP.txt](SETUP.txt)**.

## Quick start — Windows

1. Install Python 3 from python.org (tick "Add to PATH").
2. Put this folder anywhere, e.g. `C:\tools\cf-ip-keeper`.
3. Copy `keeper.env.example` → `keeper.env`, fill your values.
4. Double-click **`start_gui.bat`** (or `pythonw cf_keeper_gui.py`).

The GUI has four tabs: Cloudflare/VLESS config · subnet editor (add /
delete / import CIDR lists) · scanner start-stop with worker-speed control ·
DNS keeper on/off with interval, margin, dry-run and a live record viewer.

## Android app

Grab `CF-IP-Keeper-debug.apk` from **Releases** (Android 8+). Same features:
config fields, subnet import from phone storage, worker count, keeper
enable/disable, foreground-service background scanning, live log.
Set the app's battery setting to **Unrestricted** so scanning survives
screen-off.

## How "alive" is decided

An IP counts only if:
1. TCP 443 connects,
2. TLS handshake succeeds **and the certificate validates for your
   fronting domain** (default OS trust store),
3. an HTTP request with your domain as Host returns any HTTP response.

Random open-443 hosts can't false-positive; the probe is exactly what your
VLESS client will experience.

## Configuration reference (`keeper.env`)

| Key | Meaning |
|---|---|
| `CF_DOMAIN` | your proxied domain = VLESS SNI/Host |
| `CF_RECORDS` | comma-separated grey-cloud records this tool owns (each gets its own distinct relay) |
| `CF_TOKEN` | API token scoped **Zone → DNS → Edit** on ONE zone |
| `CF_ZONE_ID` | zone ID from dashboard |
| `RANGES_URL` | optional auto-download for ranges.txt |

GUI-only knobs (saved next to the scripts): workers, probe timeout,
switch margin (ms), check interval (min), keeper enable/disable.

## Security notes

* The real `keeper.env` is gitignored — never commit it.
* Scope the token to a single zone, DNS-Edit only; rotate if leaked.
* Found IPs, logs and state files stay local (also gitignored).
* This tool changes only the A records you list in `CF_RECORDS`. It never
  touches other DNS, never proxies anything itself.

## Troubleshooting

| Symptom | Fix |
|---|---|
| service active but log empty | restart once (`systemctl restart cf-ip-scan`); older builds buffered stdout |
| no FOUND for hours | normal early (hit-rate ~0.1–1 %); confirm `cursor.json` advances |
| checker says "no free alive relay" | fewer live relays than records — let the scanner run |
| SSH rate-limit errors while administering | wait a minute between reconnects |
| restricted network drops probes | lower workers to ≤ 8 (that's why defaults are conservative) |

## License

MIT — see [LICENSE](LICENSE).
