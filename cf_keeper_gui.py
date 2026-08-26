"""CF IP Keeper — Windows Control Panel
Single-file GUI (tkinter, stdlib only). Place INSIDE the cf-ip-keeper folder
(next to cf_ip_keeper.py / scan_loop.py / ranges.txt) and run:
    pythonw cf_keeper_gui.py        (or double-click start_gui.bat)

Manages:
  * keeper.env      : CF token, zone id, fronting domain, grey-cloud records
  * ranges.txt      : subnet source - add / delete / import CIDRs
  * Scanner         : start/stop continuous subnet scan, worker speed
  * DNS keeper      : on/off, interval, run-now, live record viewer
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "CF IP Keeper — Control Panel"
BASE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE, "keeper.env")
RANGES_FILE = os.path.join(BASE, "ranges.txt")
SETTINGS_FILE = os.path.join(BASE, "gui_settings.json")
ENGINE_CHECKER = os.path.join(BASE, "cf_ip_keeper.py")
ENGINE_SCANNER = os.path.join(BASE, "scan_loop.py")

CREATE_NO_WINDOW = 0x08000000  # keep child consoles hidden on Windows


# ---------------------------------------------------------------- helpers
def load_env():
    data, order = {}, []
    if os.path.exists(ENV_FILE):
        for ln in open(ENV_FILE, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                k, v = k.strip(), v.strip()
                order.append(k)
                data[k] = v
    return data, order


def save_env(data, order):
    order = order + [k for k in data if k not in order]
    lines = [f"{k}={data[k]}" for k in order if data.get(k, "") != ""]
    tmp = ENV_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, ENV_FILE)


def load_settings():
    d = {"workers": 8, "probe_timeout": 6, "margin_ms": 30,
         "check_interval_min": 30, "checker_enabled": False}
    if os.path.exists(SETTINGS_FILE):
        try:
            d.update(json.load(open(SETTINGS_FILE)))
        except Exception:
            pass
    return d


def save_settings(d):
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, SETTINGS_FILE)


def cf_api(token, method, path, body=None):
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        method=method)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


# ---------------------------------------------------------------- app
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("860x640")
        self.minsize(760, 560)

        self.env, self.env_order = load_env()
        self.settings = load_settings()

        self.scanner_proc = None          # subprocess.Popen
        self.scanner_reader = None
        self.log_q = queue.Queue()
        self.checker_stop = threading.Event()
        self.checker_thread = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.tab_cfg = ttk.Frame(nb)
        self.tab_rng = ttk.Frame(nb)
        self.tab_scan = ttk.Frame(nb)
        self.tab_dns = ttk.Frame(nb)
        nb.add(self.tab_cfg, text=" 1 · Cloudflare / VLESS ")
        nb.add(self.tab_rng, text=" 2 · Subnets (ranges.txt) ")
        nb.add(self.tab_scan, text=" 3 · Scanner ")
        nb.add(self.tab_dns, text=" 4 · DNS Keeper ")

        self._build_cfg()
        self._build_ranges()
        self._build_scan()
        self._build_dns()
        self._build_statusbar()

        self.after(150, self._poll_log)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        missing = [p for p in (ENGINE_CHECKER, ENGINE_SCANNER) if not os.path.exists(p)]
        if missing:
            messagebox.showwarning(
                APP_TITLE,
                "Engine files not found:\n  " + "\n  ".join(missing) +
                "\n\nPlace this program inside your cf-ip-keeper folder.")
        if not os.path.exists(RANGES_FILE):
            with open(RANGES_FILE, "w"):
                pass

    # ============================== TAB 1 : CONFIG
    def _build_cfg(self):
        f = self.tab_cfg
        pad = {"padx": 10, "pady": 4}

        ttk.Label(f, text="Cloudflare credentials", font=("", 11, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=10, pady=(12, 2))
        rows = [
            ("API Token (Edit-zone-DNS scope)", "CF_TOKEN", True),
            ("Zone ID (dashboard Overview sidebar)", "CF_ZONE_ID", False),
            ("Fronting domain  (= VLESS SNI + Host header)", "CF_DOMAIN", False),
            ("Grey-cloud records, comma separated (VLESS address)",
             "CF_RECORDS", False),
        ]
        self.cfg_vars = {}
        for i, (label, key, secret) in enumerate(rows, start=1):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", **pad)
            var = tk.StringVar(value=self.env.get(key, ""))
            ent = ttk.Entry(f, textvariable=var, width=58,
                            show="*" if secret else "")
            ent.grid(row=i, column=1, columnspan=2, sticky="we", **pad)
            self.cfg_vars[key] = var
        f.columnconfigure(1, weight=1)

        ttk.Button(f, text="Save keeper.env",
                   command=self.save_cfg).grid(row=len(rows) + 1, column=1,
                                               sticky="e", **pad)

        box = ttk.Labelframe(f, text=" How it plugs into your VLESS client ",
                             padding=10)
        box.grid(row=len(rows) + 2, column=0, columnspan=3,
                 sticky="we", padx=10, pady=14)
        ttk.Label(box, justify="left", text=(
            "address   = one of your records above   (e.g. cn.yourdomain.ir)\n"
            "port      = 443\n"
            "SNI/Host  = the Fronting domain above   (must be proxied/orange in CF)\n"
            "path/uuid = unchanged\n\n"
            "Records are kept as DNS-only (grey cloud) A records, TTL 60,\n"
            "each pinned to a DIFFERENT live relay IP by the DNS keeper."
        )).pack(anchor="w")

    def save_cfg(self):
        for k, var in self.cfg_vars.items():
            self.env[k] = var.get().strip()
        try:
            save_env(self.env, self.env_order)
            os.chmod(ENV_FILE, 0o600)
        except Exception:
            pass  # chmod is POSIX-only nicety
        self.set_status("keeper.env saved ✓")
        self.refresh_dns_view()

    # ============================== TAB 2 : RANGES
    def _build_ranges(self):
        f = self.tab_rng
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(top, text="Add network (CIDR, e.g. 203.0.113.0/24):").pack(side="left")
        self.rng_entry = ttk.Entry(top, width=28)
        self.rng_entry.pack(side="left", padx=6)
        self.rng_entry.bind("<Return>", lambda e: self.rng_add())
        ttk.Button(top, text="Add", command=self.rng_add).pack(side="left")
        ttk.Button(top, text="Import file…",
                   command=self.rng_import).pack(side="left", padx=6)

        mid = ttk.Frame(f)
        mid.pack(fill="both", expand=True, padx=10, pady=4)
        self.rng_list = tk.Listbox(mid, activestyle="dotbox", width=40)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.rng_list.yview)
        self.rng_list.config(yscrollcommand=sb.set)
        self.rng_list.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        btns = ttk.Frame(mid)
        btns.pack(side="left", fill="y", padx=8)
        ttk.Button(btns, text="Delete selected",
                   command=self.rng_del).pack(fill="x", pady=2)
        ttk.Button(btns, text="Clear all",
                   command=self.rng_clear).pack(fill="x", pady=2)

        bot = ttk.Frame(f)
        bot.pack(fill="x", padx=10, pady=(2, 10))
        self.rng_count_lbl = tk.Label(bot, anchor="w")
        self.rng_count_lbl.pack(side="left")
        ttk.Button(bot, text="Save ranges.txt",
                   command=self.rng_save).pack(side="right")
        ttk.Button(bot, text="Reload from disk",
                   command=self.rng_reload).pack(side="right", padx=6)

        self.rng_lines = []
        self.rng_reload()

    def rng_reload(self):
        self.rng_lines = [l.strip() for l in open(RANGES_FILE)
                          if l.strip() and not l.strip().startswith("#")]
        self._rng_refresh()

    def _rng_refresh(self):
        self.rng_list.delete(0, "end")
        for l in self.rng_lines:
            self.rng_list.insert("end", l)
        hosts = 0
        import ipaddress as _ip
        for l in self.rng_lines[:5000]:
            try:
                n = _ip.ip_network(l, strict=False)
                hosts += max(n.num_addresses - 2, 1)
            except ValueError:
                pass
        est = hosts / 8 * 1.3 / 3600  # hours @ thr=8, ~1.3 s/host worst case
        self.rng_count_lbl.config(
            text=f"{len(self.rng_lines)} networks · ≈{hosts:,} hosts · "
                 f"full cycle @ 8 workers ≈ {est:.1f} h (upper bound)")

    def rng_add(self):
        v = self.rng_entry.get().strip()
        if not v:
            return
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            messagebox.showerror(APP_TITLE, f"Not a valid CIDR:\n{v}")
            return
        if v not in self.rng_lines:
            self.rng_lines.append(v)
            self.rng_lines.sort()
            self._rng_refresh()
            self.rng_save(silent=True)
        self.rng_entry.delete(0, "end")

    def rng_del(self):
        for idx in reversed(self.rng_list.curselection()):
            del self.rng_lines[idx]
        self._rng_refresh()
        self.rng_save(silent=True)

    def rng_clear(self):
        if messagebox.askyesno(APP_TITLE, "Delete ALL networks?"):
            self.rng_lines = []
            self._rng_refresh()
            self.rng_save(silent=True)

    def rng_import(self):
        p = filedialog.askopenfilename(title="Import IP list (CIDR per line)")
        if not p:
            return
        added = 0
        for l in open(p, encoding="utf-8", errors="ignore"):
            l = l.split("#")[0].strip()
            if l and l not in self.rng_lines:
                self.rng_lines.append(l)
                added += 1
        self.rng_lines.sort()
        self._rng_refresh()
        self.rng_save(silent=True)
        self.set_status(f"imported {added} networks ✓")

    def rng_save(self, silent=False):
        tmp = RANGES_FILE + ".tmp"
        with open(tmp, "w") as fh:
            fh.write("\n".join(self.rng_lines) + ("\n" if self.rng_lines else ""))
        os.replace(tmp, RANGES_FILE)
        if not silent:
            self.set_status("ranges.txt saved ✓")

    # ============================== TAB 3 : SCANNER
    def _build_scan(self):
        f = self.tab_scan
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(top, text="Workers (speed / concurrency):").pack(side="left")
        self.wrk_var = tk.IntVar(value=self.settings["workers"])
        ttk.Spinbox(top, from_=1, to=64, width=4, textvariable=self.wrk_var
                    ).pack(side="left", padx=6)
        ttk.Label(top, text="(keep ≤ 8 on restricted networks)").pack(side="left")

        self.btn_scan = ttk.Button(top, text="▶ Start scanner",
                                   command=self.scan_toggle)
        self.btn_scan.pack(side="right")
        self.found_lbl = ttk.Label(top, text="found this session: 0")
        self.found_lbl.pack(side="right", padx=14)

        self.scan_log = tk.Text(f, height=24, state="disabled",
                                font=("Consolas", 9))
        sb = ttk.Scrollbar(f, orient="vertical", command=self.scan_log.yview)
        self.scan_log.configure(yscrollcommand=sb.set)
        sb.place(relx=0.985, rely=0.08, relheight=0.88)
        self.scan_log.pack(fill="both", expand=True, padx=10, pady=(4, 10))

    def scan_toggle(self):
        if self.scanner_proc and self.scanner_proc.poll() is None:
            self.scanner_proc.terminate()
            self.btn_scan.config(text="▶ Start scanner")
            self.set_status("scanner stopped")
            return
        env = dict(os.environ)
        env.update({k: v for k, v in (
            (k, var.get().strip()) for k, var in self.cfg_vars.items()) if v})
        env["WORKERS"] = str(self.wrk_var.get())
        env["PROBE_TIMEOUT"] = str(self.settings["probe_timeout"])
        try:
            self.scanner_proc = subprocess.Popen(
                [sys.executable, "-u", ENGINE_SCANNER], cwd=BASE, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Cannot start scanner:\n{e}")
            return
        self.scanner_reader = threading.Thread(
            target=self._read_pipe, args=(self.scanner_proc.stdout,), daemon=True)
        self.scanner_reader.start()
        self.btn_scan.config(text="■ Stop scanner")
        self.set_status("scanner running …")

    def _read_pipe(self, pipe):
        for line in pipe:
            self.log_q.put(("scan", line.rstrip()))

    def _poll_log(self):
        try:
            while True:
                tag, line = self.log_q.get_nowait()
                w = self.scan_log
                w.config(state="normal")
                w.insert("end", line + "\n")
                if w.index("end-1c").split(".")[0] != "1":
                    pass
                w.see("end")
                w.config(state="disabled")
                if line.startswith("FOUND"):
                    self.session_finds += 1
                    self.found_lbl.config(
                        text=f"found this session: {self.session_finds}")
                elif "cycle complete" in line:
                    self.set_status("scan cycle complete — restarting …")
        except queue.Empty:
            pass
        self.after(200, self._poll_log)

    # ============================== TAB 4 : DNS KEEPER
    def _build_dns(self):
        f = self.tab_dns
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))

        self.chk_enabled = tk.BooleanVar(value=self.settings["checker_enabled"])
        ttk.Checkbutton(top, text="Enable automatic DNS keeper",
                        variable=self.chk_enabled,
                        command=self.checker_toggle).pack(side="left")
        ttk.Label(top, text="interval (min):").pack(side="left", padx=(16, 2))
        self.iv_var = tk.IntVar(value=self.settings["check_interval_min"])
        ttk.Spinbox(top, from_=5, to=720, width=4, increment=5,
                    textvariable=self.iv_var).pack(side="left")
        ttk.Label(top, text="probe timeout (s):").pack(side="left", padx=(16, 2))
        self.pt_var = tk.IntVar(value=self.settings["probe_timeout"])
        ttk.Spinbox(top, from_=2, to=15, width=3,
                    textvariable=self.pt_var).pack(side="left")
        ttk.Label(top, text="switch margin (ms):").pack(side="left", padx=(16, 2))
        self.mg_var = tk.IntVar(value=self.settings["margin_ms"])
        ttk.Spinbox(top, from_=0, to=500, width=4,
                    textvariable=self.mg_var).pack(side="left")

        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=10, pady=4)
        ttk.Button(btns, text="Run check now",
                   command=lambda: self.checker_run(dry=False)).pack(side="left")
        ttk.Button(btns, text="Dry run (no DNS write)",
                   command=lambda: self.checker_run(dry=True)).pack(side="left", padx=6)
        ttk.Button(btns, text="Refresh DNS view",
                   command=self.refresh_dns_view).pack(side="left", padx=6)

        self.dns_log = tk.Text(f, height=8, state="disabled",
                               font=("Consolas", 9))
        self.dns_log.pack(fill="x", padx=10, pady=(4, 6))
        self.dns_view = tk.Text(f, height=10, state="disabled",
                                font=("Consolas", 10))
        self.dns_view.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.session_finds = 0
        self.refresh_dns_view()

    def checker_toggle(self):
        self.settings["checker_enabled"] = self.chk_enabled.get()
        self._persist_settings()
        if self.chk_enabled.get():
            self.checker_stop.clear()
            self.checker_thread = threading.Thread(
                target=self._checker_loop, daemon=True)
            self.checker_thread.start()
            self.set_status("DNS keeper enabled ✓")
        else:
            self.checker_stop.set()
            self.set_status("DNS keeper disabled")

    def _checker_loop(self):
        # first run immediately, then every N minutes
        while not self.checker_stop.is_set():
            self.checker_run(dry=False, from_thread=True)
            for _ in range(self.iv_var.get() * 60):
                if self.checker_stop.is_set():
                    return
                time.sleep(1)

    def checker_run(self, dry, from_thread=False):
        if not from_thread and self.chk_enabled.get():
            messagebox.showinfo(APP_TITLE,
                                "Auto-keeper already handles this. Disable it first "
                                "for manual/dry runs.")
            return
        env = dict(os.environ)
        env.update({k: v for k, v in (
            (k, var.get().strip()) for k, var in self.cfg_vars.items()) if v})
        env["WORKERS"] = "1"
        env["CHECK_ONLY"] = "1"
        env["PROBE_TIMEOUT"] = str(self.pt_var.get())
        env["MARGIN_MS"] = str(self.mg_var.get())
        if dry:
            env["MARGIN_MS"] = "-99999"
        cmd = [sys.executable, ENGINE_CHECKER] + (["--dry"] if dry else [])
        def job():
            try:
                p = subprocess.run(cmd, cwd=BASE, env=env, timeout=1200,
                                   capture_output=True, text=True,
                                   encoding="utf-8", errors="replace",
                                   creationflags=CREATE_NO_WINDOW)
                out = (p.stdout or "") + (p.stderr or "")
            except Exception as e:
                out = f"ERROR: {e}"
            self.log_q.put(("dns", None))  # trigger refresh marker below
            def push():
                self._dns_log_append(out)
                self.refresh_dns_view()
            self.after(0, push)
        threading.Thread(target=job, daemon=True).start()
        self.set_status("check started …")

    def _dns_log_append(self, text):
        w = self.dns_log
        w.config(state="normal")
        w.delete("1.0", "end")
        w.insert("end", text.strip())
        w.see("end")
        w.config(state="disabled")

    def refresh_dns_view(self):
        token = self.cfg_vars["CF_TOKEN"].get().strip()
        zone = self.cfg_vars["CF_ZONE_ID"].get().strip()
        recs = [r.strip() for r in
                self.cfg_vars["CF_RECORDS"].get().split(",") if r.strip()]
        w = self.dns_view
        w.config(state="normal")
        w.delete("1.0", "end")
        if not (token and zone and recs):
            w.insert("end", "(fill in Cloudflare tab, save, then Refresh)\n")
        else:
            for name in recs:
                try:
                    d = cf_api(token, "GET",
                               f"/zones/{zone}/dns_records?type=A&name={name}")
                    if d.get("success") and d["result"]:
                        r = d["result"][0]
                        cloud = "GREY" if not r["proxied"] else "ORANGE!"
                        w.insert("end",
                                 f"{name:<60} -> {r['content']:<16} [{cloud}] ttl {r['ttl']}\n")
                    else:
                        w.insert("end", f"{name:<60} -> (not created yet)\n")
                except Exception as e:
                    w.insert("end", f"{name:<60} -> API error: {e}\n")
        w.config(state="disabled")

    # ============================== misc
    def _build_statusbar(self):
        self.status = tk.StringVar(value="ready")
        ttk.Label(self, relief="sunken", anchor="w",
                  textvariable=self.status).pack(fill="x", side="bottom")

    def set_status(self, msg):
        self.status.set(msg)
        self.update_idletasks()

    def _persist_settings(self):
        self.settings.update({
            "workers": self.wrk_var.get(),
            "probe_timeout": self.pt_var.get(),
            "margin_ms": self.mg_var.get(),
            "check_interval_min": self.iv_var.get(),
            "checker_enabled": self.chk_enabled.get(),
        })
        save_settings(self.settings)

    def _on_close(self):
        if self.scanner_proc and self.scanner_proc.poll() is None:
            if not messagebox.askyesno(APP_TITLE, "Scanner still running. Stop and exit?"):
                return
            self.scanner_proc.terminate()
        self.checker_stop.set()
        self._persist_settings()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
