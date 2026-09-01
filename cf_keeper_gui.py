"""CF IP Keeper — Multi-Section Windows Control Panel
Supports multiple concurrent sections (e.g. Iran, China, Cloudflare Official, Europe, etc.),
each with its own independent subnets, subdomains, worker speeds, logs, and scanners.
Pure stdlib tkinter (Python 3.10+).
"""
import json, os, queue, subprocess, sys, threading, time, urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_TITLE = "CF IP Keeper — Multi-Section Control Panel"
BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE, "sections_config.json")
LEGACY_ENV = os.path.join(BASE, "keeper.env")
ENGINE_CHECKER = os.path.join(BASE, "cf_ip_keeper.py")
ENGINE_SCANNER = os.path.join(BASE, "scan_loop.py")

CREATE_NO_WINDOW = 0x08000000  # keep child consoles hidden on Windows

def load_legacy_env():
    data = {}
    if os.path.exists(LEGACY_ENV):
        for ln in open(LEGACY_ENV, encoding="utf-8", errors="ignore"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                data[k.strip()] = v.strip()
    return data

def get_default_config():
    legacy = load_legacy_env()
    return {
        "global": {
            "token": legacy.get("CF_TOKEN", ""),
            "zone": legacy.get("CF_ZONE_ID", ""),
            "domain": legacy.get("CF_DOMAIN", "example.com")
        },
        "sections": {
            "Iran": {
                "records": legacy.get("CF_RECORDS", "cn.example.com,cn2.example.com"),
                "workers": 8,
                "probe_timeout": 6,
                "margin_ms": 30,
                "check_interval_min": 30,
                "keeper_enabled": True
            },
            "Cloudflare_Official": {
                "records": "cf.example.com,cf2.example.com",
                "workers": 32,
                "probe_timeout": 3,
                "margin_ms": 20,
                "check_interval_min": 30,
                "keeper_enabled": False
            }
        }
    }

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if "global" in d and "sections" in d and d["sections"]:
                    return d
        except Exception:
            pass
    cfg = get_default_config()
    save_config(cfg)
    return cfg

def save_config(cfg):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)
    # Also sync global + active section to keeper.env for single-run bash scripts
    try:
        lines = [
            f"CF_DOMAIN={cfg['global'].get('domain', '')}",
            f"CF_TOKEN={cfg['global'].get('token', '')}",
            f"CF_ZONE_ID={cfg['global'].get('zone', '')}",
        ]
        first_sec = list(cfg["sections"].keys())[0] if cfg["sections"] else ""
        if first_sec:
            sec_rec = cfg["sections"][first_sec].get("records", "")
            lines.append(f"CF_RECORDS={sec_rec}")
        with open(LEGACY_ENV + ".tmp", "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(LEGACY_ENV + ".tmp", LEGACY_ENV)
    except Exception:
        pass

def get_section_file(sec_name, base_name, ext="txt"):
    if sec_name.lower() in ("default", "main", "iran") and not os.path.exists(os.path.join(BASE, f"{base_name}_{sec_name}.{ext}")):
        # If legacy ranges.txt exists, keep using it for Iran/Default
        legacy_p = os.path.join(BASE, f"{base_name}.{ext}")
        if os.path.exists(legacy_p):
            return legacy_p
    return os.path.join(BASE, f"{base_name}_{sec_name}.{ext}")

def cf_api(token, method, path, body=None):
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x720")
        self.minsize(860, 620)

        self.cfg = load_config()
        self.active_sec = list(self.cfg["sections"].keys())[0] if self.cfg["sections"] else "Iran"
        if self.active_sec not in self.cfg["sections"]:
            self.cfg["sections"][self.active_sec] = {
                "records": "", "workers": 8, "probe_timeout": 6, "margin_ms": 30,
                "check_interval_min": 30, "keeper_enabled": False
            }

        # Concurrency & Process controllers per section
        self.scanner_procs = {}   # sec_name -> Popen
        self.scanner_threads = {}
        self.log_queues = {}     # sec_name -> queue.Queue
        self.session_finds = {}   # sec_name -> int
        self.checker_stops = {}   # sec_name -> Event
        self.checker_threads = {}

        self._build_top_global()
        self._build_section_bar()
        self._build_notebook()
        self._build_statusbar()

        self.load_section_ui(self.active_sec)
        self.after(150, self._poll_all_logs)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------- TOP GLOBAL
    def _build_top_global(self):
        frame = ttk.LabelFrame(self, text=" Global Cloudflare & Account Settings ", padding=8)
        frame.pack(fill="x", padx=10, pady=(6, 4))

        # Row 1: Token, Zone, Domain
        ttk.Label(frame, text="API Token:").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.var_token = tk.StringVar(value=self.cfg["global"].get("token", ""))
        e_tok = ttk.Entry(frame, textvariable=self.var_token, width=32, show="*")
        e_tok.grid(row=0, column=1, sticky="we", padx=4, pady=2)

        ttk.Label(frame, text="Zone ID:").grid(row=0, column=2, sticky="w", padx=(10, 4), pady=2)
        self.var_zone = tk.StringVar(value=self.cfg["global"].get("zone", ""))
        ttk.Entry(frame, textvariable=self.var_zone, width=28).grid(row=0, column=3, sticky="we", padx=4, pady=2)

        ttk.Label(frame, text="Fronting Domain:").grid(row=0, column=4, sticky="w", padx=(10, 4), pady=2)
        self.var_domain = tk.StringVar(value=self.cfg["global"].get("domain", ""))
        ttk.Entry(frame, textvariable=self.var_domain, width=22).grid(row=0, column=5, sticky="we", padx=4, pady=2)

        btn_save_global = ttk.Button(frame, text="Save Global", command=self.save_global)
        btn_save_global.grid(row=0, column=6, padx=(10, 4), pady=2)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)
        frame.columnconfigure(5, weight=1)

    def save_global(self):
        self.cfg["global"]["token"] = self.var_token.get().strip()
        self.cfg["global"]["zone"] = self.var_zone.get().strip()
        self.cfg["global"]["domain"] = self.var_domain.get().strip()
        save_config(self.cfg)
        self.set_status("Global Cloudflare settings saved ✓")

    # ------------------------------------------------------------- SECTION BAR
    def _build_section_bar(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=(2, 4))

        ttk.Label(bar, text="Target Section:", font=("", 10, "bold")).pack(side="left", padx=(0, 6))
        self.sec_combo = ttk.Combobox(bar, values=list(self.cfg["sections"].keys()), state="readonly", width=22)
        self.sec_combo.set(self.active_sec)
        self.sec_combo.pack(side="left", padx=4)
        self.sec_combo.bind("<<ComboboxSelected>>", self._on_section_change)

        ttk.Button(bar, text="+ Add Section", command=self._add_section).pack(side="left", padx=4)
        ttk.Button(bar, text="Rename", command=self._rename_section).pack(side="left", padx=2)
        ttk.Button(bar, text="Delete Section", command=self._del_section).pack(side="left", padx=2)

        # Global multi-section buttons
        ttk.Button(bar, text="■ Stop ALL Scanners", command=self.stop_all_scanners).pack(side="right", padx=4)
        ttk.Button(bar, text="▶ Start ALL Scanners", command=self.start_all_scanners).pack(side="right", padx=4)

    def _on_section_change(self, event=None):
        self._save_current_section_ui()
        self.active_sec = self.sec_combo.get()
        self.load_section_ui(self.active_sec)

    def _add_section(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add New Section")
        dialog.geometry("340x130")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Section Name (e.g. France, China, Europe):").pack(padx=10, pady=(12, 4))
        entry = ttk.Entry(dialog, width=28)
        entry.pack(padx=10, pady=4)
        entry.focus()

        def do_add():
            name = entry.get().strip().replace(" ", "_")
            if not name: return
            if name in self.cfg["sections"]:
                messagebox.showerror("Error", f"Section '{name}' already exists!")
                return
            self.cfg["sections"][name] = {
                "records": f"{name.lower()[:3]}.example.com",
                "workers": 8,
                "probe_timeout": 6,
                "margin_ms": 30,
                "check_interval_min": 30,
                "keeper_enabled": False
            }
            save_config(self.cfg)
            self.sec_combo["values"] = list(self.cfg["sections"].keys())
            self.sec_combo.set(name)
            self._on_section_change()
            dialog.destroy()

        entry.bind("<Return>", lambda e: do_add())
        ttk.Button(dialog, text="Create Section", command=do_add).pack(pady=8)

    def _rename_section(self):
        old_name = self.active_sec
        dialog = tk.Toplevel(self)
        dialog.title(f"Rename '{old_name}'")
        dialog.geometry("340x130")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="New Section Name:").pack(padx=10, pady=(12, 4))
        entry = ttk.Entry(dialog, width=28)
        entry.insert(0, old_name)
        entry.pack(padx=10, pady=4)
        entry.focus()

        def do_rename():
            new_name = entry.get().strip().replace(" ", "_")
            if not new_name or new_name == old_name:
                dialog.destroy(); return
            if new_name in self.cfg["sections"]:
                messagebox.showerror("Error", f"Section '{new_name}' already exists!")
                return
            self._save_current_section_ui()
            self.cfg["sections"][new_name] = self.cfg["sections"].pop(old_name)
            save_config(self.cfg)
            self.sec_combo["values"] = list(self.cfg["sections"].keys())
            self.sec_combo.set(new_name)
            self._on_section_change()
            dialog.destroy()

        entry.bind("<Return>", lambda e: do_rename())
        ttk.Button(dialog, text="Rename", command=do_rename).pack(pady=8)

    def _del_section(self):
        if len(self.cfg["sections"]) <= 1:
            messagebox.showwarning("Warning", "Cannot delete the only remaining section.")
            return
        sec = self.active_sec
        if messagebox.askyesno("Confirm Delete", f"Delete section '{sec}' and stop its scanner?"):
            self.stop_scanner(sec)
            del self.cfg["sections"][sec]
            save_config(self.cfg)
            self.active_sec = list(self.cfg["sections"].keys())[0]
            self.sec_combo["values"] = list(self.cfg["sections"].keys())
            self.sec_combo.set(self.active_sec)
            self._on_section_change()

    # ------------------------------------------------------------- NOTEBOOK TABS
    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=4)

        self.tab_sec_cfg = ttk.Frame(self.nb)
        self.tab_subnets = ttk.Frame(self.nb)
        self.tab_scanner = ttk.Frame(self.nb)
        self.tab_dns = ttk.Frame(self.nb)
        self.tab_all_status = ttk.Frame(self.nb)

        self.nb.add(self.tab_sec_cfg, text=" 1 · Subdomains & Tuning ")
        self.nb.add(self.tab_subnets, text=" 2 · Subnet CIDRs (ranges) ")
        self.nb.add(self.tab_scanner, text=" 3 · Scanner ")
        self.nb.add(self.tab_dns, text=" 4 · DNS Keeper ")
        self.nb.add(self.tab_all_status, text=" 5 · All Sections Live Table ")

        self._build_tab_sec_cfg()
        self._build_tab_subnets()
        self._build_tab_scanner()
        self._build_tab_dns()
        self._build_tab_all_status()

    # --- TAB 1: Section Config
    def _build_tab_sec_cfg(self):
        f = self.tab_sec_cfg
        pad = {"padx": 10, "pady": 6}

        self.lbl_sec_banner = ttk.Label(f, text=f"Settings for Section: {self.active_sec}", font=("", 11, "bold"))
        self.lbl_sec_banner.pack(anchor="w", padx=10, pady=(12, 6))

        grid_frame = ttk.Frame(f)
        grid_frame.pack(fill="x", padx=10, pady=4)

        ttk.Label(grid_frame, text="Subdomains (comma-separated):").grid(row=0, column=0, sticky="w", **pad)
        self.var_records = tk.StringVar()
        ttk.Entry(grid_frame, textvariable=self.var_records, width=54).grid(row=0, column=1, sticky="we", **pad)

        ttk.Label(grid_frame, text="Workers (Concurrency):").grid(row=1, column=0, sticky="w", **pad)
        self.var_workers = tk.IntVar(value=8)
        w_spin = ttk.Spinbox(grid_frame, from_=1, to=256, width=6, textvariable=self.var_workers)
        w_spin.grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(grid_frame, text="Probe Timeout (seconds):").grid(row=2, column=0, sticky="w", **pad)
        self.var_timeout = tk.IntVar(value=6)
        ttk.Spinbox(grid_frame, from_=1, to=30, width=6, textvariable=self.var_timeout).grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(grid_frame, text="Switch Latency Margin (ms):").grid(row=3, column=0, sticky="w", **pad)
        self.var_margin = tk.IntVar(value=30)
        ttk.Spinbox(grid_frame, from_=0, to=500, width=6, textvariable=self.var_margin).grid(row=3, column=1, sticky="w", **pad)

        ttk.Button(f, text="Save Section Config", command=self.save_current_section).pack(anchor="e", padx=14, pady=10)

        box = ttk.Labelframe(f, text=" How This Section Operates ", padding=10)
        box.pack(fill="x", padx=10, pady=10)
        ttk.Label(box, justify="left", text=(
            "• Each section maintains its own independent subnets, scanner process, and DNS records.\n"
            "• You can run Iran at 8 workers, Cloudflare Direct at 64 workers, and France at 16 workers simultaneously.\n"
            "• Each record in 'Subdomains' receives a unique, cert-verified alive relay from this section's subnets."
        )).pack(anchor="w")

    # --- TAB 2: Subnets
    def _build_tab_subnets(self):
        f = self.tab_subnets
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(top, text="Add CIDR (e.g. 203.0.113.0/24):").pack(side="left")
        self.rng_entry = ttk.Entry(top, width=24)
        self.rng_entry.pack(side="left", padx=6)
        self.rng_entry.bind("<Return>", lambda e: self.rng_add())
        ttk.Button(top, text="Add", command=self.rng_add).pack(side="left")
        ttk.Button(top, text="Import File…", command=self.rng_import).pack(side="left", padx=6)

        mid = ttk.Frame(f)
        mid.pack(fill="both", expand=True, padx=10, pady=4)
        self.rng_list = tk.Listbox(mid, activestyle="dotbox", width=40)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.rng_list.yview)
        self.rng_list.config(yscrollcommand=sb.set)
        self.rng_list.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        btns = ttk.Frame(mid)
        btns.pack(side="left", fill="y", padx=8)
        ttk.Button(btns, text="Delete Selected", command=self.rng_del).pack(fill="x", pady=2)
        ttk.Button(btns, text="Clear All", command=self.rng_clear).pack(fill="x", pady=2)

        bot = ttk.Frame(f)
        bot.pack(fill="x", padx=10, pady=(2, 10))
        self.rng_count_lbl = tk.Label(bot, anchor="w")
        self.rng_count_lbl.pack(side="left")
        ttk.Button(bot, text="Save Subnets", command=self.rng_save).pack(side="right")
        ttk.Button(bot, text="Reload", command=self.rng_reload).pack(side="right", padx=6)
        self.rng_lines = []

    # --- TAB 3: Scanner
    def _build_tab_scanner(self):
        f = self.tab_scanner
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))

        self.btn_scan = ttk.Button(top, text="▶ Start Scanner", command=self.toggle_active_scanner)
        self.btn_scan.pack(side="left")

        self.lbl_scan_status = ttk.Label(top, text="Status: idle", font=("", 9, "bold"))
        self.lbl_scan_status.pack(side="left", padx=14)

        self.lbl_found = ttk.Label(top, text="Found: 0 alive")
        self.lbl_found.pack(side="right", padx=10)

        self.scan_log = tk.Text(f, height=20, state="disabled", font=("Consolas", 9))
        sb = ttk.Scrollbar(f, orient="vertical", command=self.scan_log.yview)
        self.scan_log.configure(yscrollcommand=sb.set)
        sb.place(relx=0.985, rely=0.08, relheight=0.88)
        self.scan_log.pack(fill="both", expand=True, padx=10, pady=(4, 10))

    # --- TAB 4: DNS Keeper
    def _build_tab_dns(self):
        f = self.tab_dns
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=(10, 4))

        self.chk_keeper = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Enable Automatic DNS Keeper", variable=self.chk_keeper,
                        command=self.toggle_active_keeper).pack(side="left")
        ttk.Label(top, text="Interval (min):").pack(side="left", padx=(14, 2))
        self.var_interval = tk.IntVar(value=30)
        ttk.Spinbox(top, from_=5, to=720, width=4, increment=5, textvariable=self.var_interval).pack(side="left")

        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=10, pady=4)
        ttk.Button(btns, text="Run Check Now", command=lambda: self.run_checker(self.active_sec, dry=False)).pack(side="left")
        ttk.Button(btns, text="Dry Run", command=lambda: self.run_checker(self.active_sec, dry=True)).pack(side="left", padx=6)
        ttk.Button(btns, text="Refresh Cloudflare DNS Status", command=self.refresh_active_dns_view).pack(side="left", padx=6)

        self.dns_log = tk.Text(f, height=8, state="disabled", font=("Consolas", 9))
        self.dns_log.pack(fill="x", padx=10, pady=(4, 6))

        self.dns_view = tk.Text(f, height=10, state="disabled", font=("Consolas", 10))
        self.dns_view.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # --- TAB 5: All Sections Live Table
    def _build_tab_all_status(self):
        f = self.tab_all_status
        top = ttk.Frame(f)
        top.pack(fill="x", padx=10, pady=8)

        ttk.Label(top, text="Live Overview of All Sections & Cloudflare Records", font=("", 11, "bold")).pack(side="left")
        ttk.Button(top, text="Refresh All Records", command=self.refresh_all_table).pack(side="right")

        self.all_tree = ttk.Treeview(f, columns=("Section", "Subdomain", "Current_IP", "Cloud", "Scanner_Status", "Workers"), show="headings")
        self.all_tree.heading("Section", text="Section")
        self.all_tree.heading("Subdomain", text="Subdomain Record")
        self.all_tree.heading("Current_IP", text="Target IP")
        self.all_tree.heading("Cloud", text="CF Status")
        self.all_tree.heading("Scanner_Status", text="Scanner")
        self.all_tree.heading("Workers", text="Workers")

        self.all_tree.column("Section", width=120)
        self.all_tree.column("Subdomain", width=220)
        self.all_tree.column("Current_IP", width=140)
        self.all_tree.column("Cloud", width=90)
        self.all_tree.column("Scanner_Status", width=100)
        self.all_tree.column("Workers", width=70)

        self.all_tree.pack(fill="both", expand=True, padx=10, pady=4)

    # ------------------------------------------------------------- UI SYNC & LOAD
    def load_section_ui(self, sec_name):
        sec = self.cfg["sections"].get(sec_name, {})
        self.lbl_sec_banner.config(text=f"Settings for Section: {sec_name}")
        self.var_records.set(sec.get("records", ""))
        self.var_workers.set(sec.get("workers", 8))
        self.var_timeout.set(sec.get("probe_timeout", 6))
        self.var_margin.set(sec.get("margin_ms", 30))
        self.var_interval.set(sec.get("check_interval_min", 30))
        self.chk_keeper.set(sec.get("keeper_enabled", False))

        # Update scanner status indicators
        proc = self.scanner_procs.get(sec_name)
        if proc and proc.poll() is None:
            self.btn_scan.config(text="■ Stop Scanner")
            self.lbl_scan_status.config(text="Status: RUNNING", foreground="green")
        else:
            self.btn_scan.config(text="▶ Start Scanner")
            self.lbl_scan_status.config(text="Status: idle", foreground="black")

        self.lbl_found.config(text=f"Found: {self.session_finds.get(sec_name, 0)} alive")
        self.rng_reload()
        self.refresh_active_dns_view()

    def _save_current_section_ui(self):
        sec = self.active_sec
        if sec in self.cfg["sections"]:
            self.cfg["sections"][sec].update({
                "records": self.var_records.get().strip(),
                "workers": self.var_workers.get(),
                "probe_timeout": self.var_timeout.get(),
                "margin_ms": self.var_margin.get(),
                "check_interval_min": self.var_interval.get(),
                "keeper_enabled": self.chk_keeper.get()
            })
            save_config(self.cfg)

    def save_current_section(self):
        self._save_current_section_ui()
        self.set_status(f"Section '{self.active_sec}' settings saved ✓")

    # ------------------------------------------------------------- RANGES MANAGEMENT
    def get_cur_ranges_path(self):
        return get_section_file(self.active_sec, "ranges", "txt")

    def rng_reload(self):
        p = self.get_cur_ranges_path()
        self.rng_lines = []
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as f:
                self.rng_lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        self._rng_refresh()

    def _rng_refresh(self):
        self.rng_list.delete(0, "end")
        for l in self.rng_lines:
            self.rng_list.insert("end", l)
        import ipaddress as _ip
        hosts = 0
        for l in self.rng_lines[:3000]:
            try:
                n = _ip.ip_network(l, strict=False)
                hosts += max(n.num_addresses - 2, 1)
            except ValueError:
                pass
        self.rng_count_lbl.config(text=f"{len(self.rng_lines)} networks · ≈{hosts:,} hosts in {os.path.basename(self.get_cur_ranges_path())}")

    def rng_add(self):
        v = self.rng_entry.get().strip()
        if not v: return
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            messagebox.showerror("Error", f"Invalid CIDR: {v}")
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
        if messagebox.askyesno("Confirm", f"Clear all subnets for section '{self.active_sec}'?"):
            self.rng_lines = []
            self._rng_refresh()
            self.rng_save(silent=True)

    def rng_import(self):
        p = filedialog.askopenfilename(title="Import CIDR text list")
        if not p: return
        added = 0
        for l in open(p, encoding="utf-8", errors="ignore"):
            l = l.split("#")[0].strip()
            if l and l not in self.rng_lines:
                self.rng_lines.append(l)
                added += 1
        self.rng_lines.sort()
        self._rng_refresh()
        self.rng_save(silent=True)
        self.set_status(f"Imported {added} networks to {self.active_sec} ✓")

    def rng_save(self, silent=False):
        p = self.get_cur_ranges_path()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.rng_lines) + ("\n" if self.rng_lines else ""))
        os.replace(tmp, p)
        if not silent:
            self.set_status(f"Saved {os.path.basename(p)} ✓")

    # ------------------------------------------------------------- SCANNER PROCESS
    def toggle_active_scanner(self):
        sec = self.active_sec
        proc = self.scanner_procs.get(sec)
        if proc and proc.poll() is None:
            self.stop_scanner(sec)
        else:
            self.start_scanner(sec)
        self.load_section_ui(sec)

    def start_scanner(self, sec_name):
        self._save_current_section_ui()
        proc = self.scanner_procs.get(sec_name)
        if proc and proc.poll() is None:
            return

        sec_cfg = self.cfg["sections"].get(sec_name, {})
        env = dict(os.environ)
        env["CF_DOMAIN"] = self.var_domain.get().strip()
        env["CF_TOKEN"] = self.var_token.get().strip()
        env["CF_ZONE_ID"] = self.var_zone.get().strip()
        env["SECTION"] = sec_name
        env["WORKERS"] = str(sec_cfg.get("workers", 8))
        env["PROBE_TIMEOUT"] = str(sec_cfg.get("probe_timeout", 6))

        if sec_name not in self.log_queues:
            self.log_queues[sec_name] = queue.Queue()
        if sec_name not in self.session_finds:
            self.session_finds[sec_name] = 0

        try:
            p = subprocess.Popen(
                [sys.executable, "-u", ENGINE_SCANNER, "--section", sec_name],
                cwd=BASE, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW)
            self.scanner_procs[sec_name] = p
            t = threading.Thread(target=self._pipe_reader, args=(sec_name, p.stdout), daemon=True)
            self.scanner_threads[sec_name] = t
            t.start()
            self.set_status(f"Started scanner for section '{sec_name}' (workers={env['WORKERS']})")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scanner for {sec_name}:\n{e}")

    def stop_scanner(self, sec_name):
        proc = self.scanner_procs.get(sec_name)
        if proc and proc.poll() is None:
            proc.terminate()
            self.set_status(f"Stopped scanner for '{sec_name}'")

    def start_all_scanners(self):
        for s in self.cfg["sections"].keys():
            self.start_scanner(s)
        self.load_section_ui(self.active_sec)

    def stop_all_scanners(self):
        for s in self.cfg["sections"].keys():
            self.stop_scanner(s)
        self.load_section_ui(self.active_sec)

    def _pipe_reader(self, sec_name, pipe):
        for line in pipe:
            if sec_name in self.log_queues:
                self.log_queues[sec_name].put(line.rstrip())

    def _poll_all_logs(self):
        for sec_name, q in list(self.log_queues.items()):
            try:
                while True:
                    line = q.get_nowait()
                    if "FOUND " in line:
                        self.session_finds[sec_name] = self.session_finds.get(sec_name, 0) + 1
                    if sec_name == self.active_sec:
                        w = self.scan_log
                        w.config(state="normal")
                        w.insert("end", line + "\n")
                        w.see("end")
                        w.config(state="disabled")
                        self.lbl_found.config(text=f"Found: {self.session_finds[sec_name]} alive")
            except queue.Empty:
                pass
        self.after(200, self._poll_all_logs)

    # ------------------------------------------------------------- DNS KEEPER
    def toggle_active_keeper(self):
        self._save_current_section_ui()
        sec = self.active_sec
        enabled = self.chk_keeper.get()
        if enabled:
            if sec not in self.checker_stops or self.checker_stops[sec].is_set():
                stop_ev = threading.Event()
                self.checker_stops[sec] = stop_ev
                t = threading.Thread(target=self._keeper_loop, args=(sec, stop_ev), daemon=True)
                self.checker_threads[sec] = t
                t.start()
            self.set_status(f"DNS Keeper enabled for '{sec}' ✓")
        else:
            if sec in self.checker_stops:
                self.checker_stops[sec].set()
            self.set_status(f"DNS Keeper disabled for '{sec}'")

    def _keeper_loop(self, sec_name, stop_event):
        while not stop_event.is_set():
            self.run_checker(sec_name, dry=False)
            iv = self.cfg["sections"].get(sec_name, {}).get("check_interval_min", 30)
            for _ in range(iv * 60):
                if stop_event.is_set():
                    return
                time.sleep(1)

    def run_checker(self, sec_name, dry=False):
        sec_cfg = self.cfg["sections"].get(sec_name, {})
        env = dict(os.environ)
        env["CF_DOMAIN"] = self.var_domain.get().strip()
        env["CF_TOKEN"] = self.var_token.get().strip()
        env["CF_ZONE_ID"] = self.var_zone.get().strip()
        env["CF_RECORDS"] = sec_cfg.get("records", "")
        env["SECTION"] = sec_name
        env["WORKERS"] = "1"
        env["CHECK_ONLY"] = "1"
        env["PROBE_TIMEOUT"] = str(sec_cfg.get("probe_timeout", 6))
        env["MARGIN_MS"] = "-99999" if dry else str(sec_cfg.get("margin_ms", 30))

        cmd = [sys.executable, ENGINE_CHECKER, "--section", sec_name] + (["--dry"] if dry else [])

        def job():
            try:
                p = subprocess.run(cmd, cwd=BASE, env=env, timeout=300,
                                   capture_output=True, text=True, encoding="utf-8", errors="replace",
                                   creationflags=CREATE_NO_WINDOW)
                out = (p.stdout or "") + (p.stderr or "")
            except Exception as e:
                out = f"ERROR: {e}"
            self.after(0, lambda: self._on_checker_finished(sec_name, out))

        threading.Thread(target=job, daemon=True).start()
        if sec_name == self.active_sec:
            self.set_status(f"Running check for '{sec_name}' …")

    def _on_checker_finished(self, sec_name, text):
        if sec_name == self.active_sec:
            w = self.dns_log
            w.config(state="normal")
            w.delete("1.0", "end")
            w.insert("end", text.strip())
            w.see("end")
            w.config(state="disabled")
            self.refresh_active_dns_view()
        self.set_status(f"Check completed for '{sec_name}'")

    def refresh_active_dns_view(self):
        token = self.var_token.get().strip()
        zone = self.var_zone.get().strip()
        sec = self.cfg["sections"].get(self.active_sec, {})
        recs = [r.strip() for r in sec.get("records", "").split(",") if r.strip()]

        w = self.dns_view
        w.config(state="normal")
        w.delete("1.0", "end")
        if not (token and zone and recs):
            w.insert("end", "(Configure token, zone, and subdomains to view DNS status)\n")
        else:
            for name in recs:
                try:
                    d = cf_api(token, "GET", f"/zones/{zone}/dns_records?type=A&name={name}")
                    if d.get("success") and d["result"]:
                        r = d["result"][0]
                        cloud = "GREY" if not r["proxied"] else "ORANGE (WARNING: MUST BE GREY!)"
                        w.insert("end", f"{name:<55} -> {r['content']:<16} [{cloud}] ttl {r['ttl']}\n")
                    else:
                        w.insert("end", f"{name:<55} -> (record not created on Cloudflare yet)\n")
                except Exception as e:
                    w.insert("end", f"{name:<55} -> API Error: {e}\n")
        w.config(state="disabled")

    def refresh_all_table(self):
        token = self.var_token.get().strip()
        zone = self.var_zone.get().strip()
        for row in self.all_tree.get_children():
            self.all_tree.delete(row)

        for sec_name, sec_cfg in self.cfg["sections"].items():
            recs = [r.strip() for r in sec_cfg.get("records", "").split(",") if r.strip()]
            proc = self.scanner_procs.get(sec_name)
            scan_st = "RUNNING" if (proc and proc.poll() is None) else "idle"
            workers = sec_cfg.get("workers", 8)

            if not recs:
                self.all_tree.insert("", "end", values=(sec_name, "(none)", "-", "-", scan_st, workers))
                continue

            for rname in recs:
                target_ip, cloud = "(checking...)", "-"
                if token and zone:
                    try:
                        d = cf_api(token, "GET", f"/zones/{zone}/dns_records?type=A&name={rname}")
                        if d.get("success") and d["result"]:
                            rec = d["result"][0]
                            target_ip = rec["content"]
                            cloud = "GREY" if not rec["proxied"] else "ORANGE!"
                        else:
                            target_ip = "(not created)"
                    except Exception:
                        target_ip = "(err)"
                self.all_tree.insert("", "end", values=(sec_name, rname, target_ip, cloud, scan_st, workers))

    # ------------------------------------------------------------- MISC
    def _build_statusbar(self):
        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, relief="sunken", anchor="w", textvariable=self.status).pack(fill="x", side="bottom")

    def set_status(self, msg):
        self.status.set(msg)
        self.update_idletasks()

    def _on_close(self):
        running = [s for s, p in self.scanner_procs.items() if p.poll() is None]
        if running:
            if not messagebox.askyesno("Exit", f"Scanners running for: {', '.join(running)}\nStop all and exit?"):
                return
        for p in self.scanner_procs.values():
            if p.poll() is None: p.terminate()
        for ev in self.checker_stops.values():
            ev.set()
        self._save_current_section_ui()
        self.destroy()

if __name__ == "__main__":
    App().mainloop()
