#!/usr/bin/env python3
"""Reproduce the EXACT cn/cn2 duplicate with the OLD keeper logic, then prove
the NEW plan_records fixes it. Uses the box's real observed values."""
MARGIN_MS = 30

def old_logic(RECORDS, live, pool, fresh, dnsc):
    """Faithful transcription of the deployed box cf_ip_keeper.py lines 309-373."""
    used = {c.get("ip") for c in dnsc.values() if c.get("ip")}
    trace = []
    for name in RECORDS:
        cur = live.get(name)
        cand = {ip: ms for ip, ms in pool.items() if ip not in used or ip == cur}
        if not cand:
            trace.append(f"{name}: no free alive relay; untouched"); continue
        best = min(cand, key=cand.get)
        cur_ms = fresh.get(cur)
        cur_is_relay = cur in pool
        dup_cur = cur in used
        if not dup_cur and cur_is_relay and cur_ms is not None and not (fresh[best] + MARGIN_MS < cur_ms) and best == cur:
            trace.append(f"{name}: keeping {cur}")
        elif best != cur and (not cur_is_relay or cur_ms is None or dup_cur or fresh[best] + MARGIN_MS < cur_ms):
            trace.append(f"{name}: switched -> {best}")
        else:
            trace.append(f"{name}: keeping {cur} (best alt {best})")
        final_ip = best if (cur is None or not cur_is_relay or cur_ms is None
                            or dup_cur or fresh[best] + MARGIN_MS < cur_ms) else cur
        if final_ip:
            used.add(final_ip)
            dnsc[name] = {"ip": final_ip}
    return dnsc, trace

RECS = ["cn.x.ir", "cn2.x.ir"]
# REAL box values (2026-09-23 logs): both records ended on 2.188.243.132
pool = {"2.188.243.132": 336, "109.70.73.194": 424}   # both alive + in ir_gate
fresh = dict(pool)
dnsc = {  # dns_cache_Iran.json as it was -- BOTH already the same IP
    "cn.x.ir":  {"ip": "2.188.243.132", "ms": 336},
    "cn2.x.ir": {"ip": "2.188.243.132", "ms": 336},
}
live = {"cn.x.ir": "2.188.243.132", "cn2.x.ir": "2.188.243.132"}

out, trace = old_logic(RECS, live, pool, fresh, dict(dnsc))
print("OLD LOGIC trace:")
for t in trace:
    print("   ", t)
print("OLD RESULT:", {k: v["ip"] for k, v in out.items()})
dups = len({v["ip"] for v in out.values()}) != len(out)
print("OLD => DUPLICATE PRESENT:", dups)
print()
print("ROOT CAUSE: `cand` re-admits the contested IP via `or ip == cur`, so `best`")
print("is always the SAME fastest IP for both records; `dup_cur` then forces")
print("final_ip=best, i.e. it re-writes the very duplicate it detected.")
print("The `used` set also collapses to ONE element because the stale cache")
print("already holds the same IP twice, so it can never distinguish the two.")

# ---- NEW logic ----
import importlib.util, os
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cf_ip_keeper_real_lf.py")
spec = importlib.util.spec_from_file_location("k", SRC)
k = importlib.util.module_from_spec(spec); spec.loader.exec_module(k)
plan = k.plan_records(RECS, live, pool, MARGIN_MS)
print()
print("NEW plan_records:", plan)
final = dict(live); final.update(plan["assign"]); final.update(plan["keep"])
print("NEW RESULT:", final)
print("NEW => DUPLICATE PRESENT:", len(set(final.values())) != len(final))
assert len(set(final.values())) == len(final), "still duplicated!"
print("\nFIXED: cn and cn2 now hold DIFFERENT IPs (cn keeps 2.188.243.132, cn2 moves to 109.70.73.194)")
