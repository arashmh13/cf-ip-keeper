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
| Linux (VPS / ZimaOS / Ubuntu) | `scan_daemon.sh` / `run_section.sh` + systemd | Python 3 (stdlib only) |
| Web dashboard | `dashboard.py` (:8787) | Python 3 (stdlib only) — works on any Linux + WSL |
| Windows GUI | `cf_keeper_gui.py` | Python + tkinter (stdlib only) |
| Android | see Releases | none (APK) |

## Web dashboard (any Linux, port 8787)

Real-time glass UI: section cards (scan cursor, hot /24s, found pool, current
DNS record + latency, service health), live SSE log viewer for every scanner
and the keeper, one-click start/stop/restart per section, EN/FA bilingual.
Zero dependencies — pure stdlib, reads the project's state files directly.

```bash
# quick manual run (from the project dir)
python3 dashboard.py          # http://<host>:8787/

# or install as a boot service (Ubuntu / Debian / ZimaOS):
sudo bash install_dashboard.sh /opt/cf-ip-keeper
```

- `install_dashboard.sh` installs `cf-ip-dash.service` (enabled at boot,
  restart-on-crash) and an optional passwordless-sudoers rule so the UI's
  control buttons work for `cf-ip-*` units only — nothing else.
- Works even where `tail -F` is missing (pure-Python streaming fallback) and
  degrades gracefully where systemd/sudo is unavailable.
- Files it reads: `sections_config.json`, `cursor_*/state_*/hits_*/ranges_*`,
  `scanner_*.log`, `checker_*.log`. It never reads or exposes `keeper.env`.

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

## Geo-verification (IR section)

The IR scanner runs `SECTION=Iran`, scanning ONLY `ranges_Iran.txt`
(authoritative Iranian CIDR list). Two independent gates keep IR country-pure:

1. **In-list check** — every find must belong to a range in `ranges_Iran.txt`
   (also `ir_gate.txt`, the keeper's gate file).
2. **Live country lookup** — every in-list find is additionally checked against
   ip-api.com (no key, 45 req/min). IPs that geo-locate outside `GATE_COUNTRY`
   (e.g. host-announced ranges like LeaseWeb NL that are in the list but
   physically foreign) are **re-routed to the EthernetServer section**
   (`foundedIPs_EthernetServer.txt` / `state_EthernetServer.json`) instead of
   the IR pool — they still get harvested for the `eth.` record.
3. **Keeper geo-gate** — `zima_keeper_pass.sh` runs the IR pass with
   `GATE_COUNTRY=IR`, so the keeper's `gate()` requires BOTH the CIDR list AND
   the live country; DNS for `cn.`/`cn2.` can only ever point at verified
   Iranian IPs. Run with `GEO_STRICT=1` to fail closed when the country cannot
   be resolved (never trust the CIDR list alone). Verified countries are cached
   in `geo_cache_<section>.json`, so a geo-API outage does not disable the gate.
   **On hosts whose DNS resolution fails** (common on tightly-firewalled boxes)
   ip-api.com cannot be reached directly — set `GEO_PROXY` (e.g.
   `http://127.0.0.1:20171`) or the lookup returns nothing and the gate no-ops.

EthernetServer stays a general pool: its own scanner feeds it, and the IR
scanner's foreign sends join it.

## The cn != cn2 invariant

A section's records must **never** share an IP. `cn.` and `cn2.` are the same
section, so they are the case that matters. The keeper enforces this in a pure,
unit-tested decision core (`plan_records()`):

* an IP currently owned by a sibling record can **never** be offered to another
  record in the same section;
* a record already sharing an IP with a sibling is **forced to move**, even when
  the shared IP is the fastest one available (the rule beats latency);
* if nothing else is alive, the record is reported `unresolved` and the keeper
  probes more candidates instead of silently keeping the duplicate;
* the decision is based on **live DNS read from the Cloudflare API**, never on
  the local `dns_cache` (a stale or self-contradictory cache is exactly how the
  original duplicate became self-perpetuating);
* if a record cannot be read, the pass writes **nothing** (a blind `POST` would
  create a duplicate record);
* the keeper also avoids IPs held by records it does not manage (e.g. a `cam.`
  record owned by another system), so the zone never gets an accidental
  collision.

Regression tests (no network or credentials needed):

```bash
python test_plan_records.py     # unit + 4000-case fuzz, asserts zero duplicates
python repro_cn_dup.py          # reproduces the original bug, shows the fix
```

Full end-to-end test against a mock Cloudflare API (`e2e_keeper_test.py`)
covers: repairing an existing duplicate, idempotence across passes, an API
outage (no writes), a geo outage with `GEO_STRICT=1`, and a cross-system
collision. Run it in WSL/Linux:

```bash
python3 e2e_keeper_test.py
```

## How "alive" is decided

An IP counts only if:
1. TCP 443 connects,
2. TLS handshake succeeds **and the certificate validates for your
   fronting domain** (default OS trust store),
3. an HTTP request with your domain as Host, **on the real VLESS path**
   (`CF_VLESS_PATH`, default `/`), returns **HTTP 2xx**.

Cloudflare edges that present a valid cert but refuse to proxy your zone
(403 "error code: 1034" — Edge IP Restricted) are rejected automatically;
the probe is exactly what your VLESS client will experience.

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
