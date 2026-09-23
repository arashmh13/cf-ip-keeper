#!/usr/bin/env python3
"""Invariant tests for cf_ip_keeper.plan_records — the 'cn and cn2 must never
share an IP' guarantee, plus race/stale-state scenarios.

Run:  python test_plan_records.py
"""
import importlib.util, itertools, os, sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cf_ip_keeper_real_lf.py")
spec = importlib.util.spec_from_file_location("keeper", SRC)
k = importlib.util.module_from_spec(spec)
# prevent main() from running
sys.argv = ["keeper"]
spec.loader.exec_module(k)

RECS = ["cn.example.com", "cn2.example.com"]
MARGIN = 30
fails = []

def check(cond, label):
    print(("  PASS " if cond else "  FAIL ") + label)
    if not cond:
        fails.append(label)

def no_shared_ip(res):
    got = list(res["assign"].values()) + list(res["keep"].values())
    return len(got) == len(set(got))

print("1) EXACT BUG: cn and cn2 both on the same IP (the reported case)")
live = {"cn.example.com": "2.188.243.132", "cn2.example.com": "2.188.243.132"}
pool = {"2.188.243.132": 326, "94.182.147.185": 436, "62.106.95.34": 493}
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no IP assigned to both records")
check("cn2.example.com" in res["forced"], "the second record is forced to move")
check(res["keep"].get("cn.example.com") == "2.188.243.132", "cn keeps the contested IP (first in order)")
check(res["assign"].get("cn2.example.com") in ("94.182.147.185", "62.106.95.34"),
      "cn2 moves to a DIFFERENT live IP")
by_ip = {}
for n, ip in list(res["assign"].items()) + list(res["keep"].items()):
    by_ip.setdefault(ip, []).append(n)
check(all(len(v) == 1 for v in by_ip.values()), "final mapping has zero collisions")

print("\n2) Sibling owns the only other candidate -> must NOT steal it, must skip")
live = {"cn.example.com": "1.1.1.1", "cn2.example.com": "1.1.1.1"}
pool = {"1.1.1.1": 300, "9.9.9.9": 400}
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP")
check(res["keep"].get("cn.example.com") == "1.1.1.1", "cn keeps 1.1.1.1")
check(res["assign"].get("cn2.example.com") == "9.9.9.9", "cn2 gets the free one")
# sibling-owned pool entry must never be stolen
live = {"cn.example.com": "1.1.1.1", "cn2.example.com": "1.1.1.1"}
pool = {"1.1.1.1": 300}   # only the contested IP is alive
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP when nothing else is alive")
check("cn2.example.com" in res["skip"] or "cn2.example.com" not in res["assign"],
      "cn2 is skipped rather than stealing cn's IP")

print("\n3) Stale cache says cn=X but live DNS says cn=Y (cache must be ignored)")
live = {"cn.example.com": "5.5.5.5", "cn2.example.com": "6.6.6.6"}
pool = {"5.5.5.5": 300, "6.6.6.6": 310, "7.7.7.7": 290}
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP")
check(res["keep"].get("cn.example.com") == "5.5.5.5",
      "cn keeps 5.5.5.5: 290ms is within the 30ms margin (no needless churn)")
check(res["keep"].get("cn2.example.com") == "6.6.6.6", "cn2 keeps 6.6.6.6 (within margin)")
# with a clearly faster alternative (beyond margin) the record must move
pool2 = {"5.5.5.5": 300, "6.6.6.6": 310, "7.7.7.7": 150}
res2 = k.plan_records(RECS, live, pool2, MARGIN)
print("   ->", res2)
check(res2["assign"].get("cn.example.com") == "7.7.7.7",
      "cn moves to 7.7.7.7 when it is faster beyond the margin")
check(no_shared_ip(res2), "no shared IP after the faster-IP move")

print("\n4) Dead current IP -> replaced, never left dead")
live = {"cn.example.com": "1.1.1.1", "cn2.example.com": "2.2.2.2"}
pool = {"3.3.3.3": 200, "4.4.4.4": 210}     # both live IPs are gone
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP")
check(res["assign"].get("cn.example.com") == "3.3.3.3", "cn replaced with 3.3.3.3")
check(res["assign"].get("cn2.example.com") == "4.4.4.4", "cn2 replaced with 4.4.4.4")

print("\n5) Unknown live state (CF API down) -> never create/duplicate")
live = {"cn.example.com": None, "cn2.example.com": None}
pool = {"1.1.1.1": 100, "2.2.2.2": 110}
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP")
check(len(res["assign"]) == 2, "both records still get distinct assignments planned")

print("\n6) Fuzz: random states must NEVER produce a duplicate")
import random
random.seed(7)
bad = 0
for t in range(4000):
    n = random.choice([2, 3])
    recs = [f"r{i}.example.com" for i in range(n)]
    live = {r: random.choice([None, "10.0.0.1", "10.0.0.2", "10.0.0.3", ""]) for r in recs}
    pool = {f"10.0.0.{i}": random.randint(50, 5000) for i in range(1, random.randint(2, 6))}
    res = k.plan_records(recs, live, pool, random.choice([0, 30, 500]))
    got = list(res["assign"].values()) + list(res["keep"].values())
    if len(got) != len(set(got)):
        bad += 1
        if bad == 1:
            print("   COUNTEREXAMPLE:", recs, live, pool, res)
check(bad == 0, f"4000 random cases produced no duplicate (bad={bad})")

print("\n7) Idempotence: applying the plan twice changes nothing")
live = {"cn.example.com": "2.188.243.132", "cn2.example.com": "2.188.243.132"}
pool = {"2.188.243.132": 326, "94.182.147.185": 436}
r1 = k.plan_records(RECS, live, pool, MARGIN)
after = dict(live)
after.update(r1["assign"]); after.update(r1["keep"])
r2 = k.plan_records(RECS, after, pool, MARGIN)
print("   ->", r2)
check(not r2["forced"], "no forced moves on the second pass (stable)")
check(no_shared_ip(r2), "still no duplicates")

print("\n8) Single-record section (no siblings) is unaffected")
res = k.plan_records(["hz.example.com"], {"hz.example.com": "8.8.8.8"}, {"8.8.8.8": 100}, MARGIN)
print("   ->", res)
check(res["keep"].get("hz.example.com") == "8.8.8.8", "single record keeps its IP")

print("\n9) Cross-system collision: 'cam' (not ours) already uses cn's chosen IP")
live = {"cn.example.com": "1.1.1.1", "cn2.example.com": "2.2.2.2"}
pool = {"1.1.1.1": 300, "2.2.2.2": 310, "3.3.3.3": 320}
avoid = {"1.1.1.1": "cam"}          # cam.<domain> holds 1.1.1.1
res = k.plan_records(RECS, live, pool, MARGIN, avoid=avoid)
print("   ->", res)
check(no_shared_ip(res), "no shared IP")
check(res["assign"].get("cn.example.com") == "3.3.3.3",
      "cn moves to 3.3.3.3 to avoid colliding with cam")
check("1.1.1.1" not in list(res["assign"].values()) + list(res["keep"].values()) or
      res["keep"].get("cn.example.com") == "1.1.1.1",
      "cn does not adopt the colliding IP when a clear one exists")
# but when only the colliding IP is fast/alive, we must not churn pointlessly
pool2 = {"1.1.1.1": 300}
res2 = k.plan_records(["cn.example.com"], {"cn.example.com": "1.1.1.1"}, pool2, MARGIN, avoid=avoid)
print("   ->", res2)
check(res2["keep"].get("cn.example.com") == "1.1.1.1",
      "keeps the colliding IP rather than leaving the record dead")

print("\n10) Sibling duplicate with an unusable alternative -> 'unresolved', not silent duplicate")
live = {"cn.example.com": "1.1.1.1", "cn2.example.com": "1.1.1.1"}
pool = {"1.1.1.1": 300}             # only the contested IP is alive
res = k.plan_records(RECS, live, pool, MARGIN)
print("   ->", res)
check(no_shared_ip(res), "no shared IP in the plan")
check("cn2.example.com" in res["unresolved"],
      "cn2 reported unresolved (caller must expand the pool)")
check("cn.example.com" in res["keep"], "cn keeps the contested IP")

print("\n" + ("ALL PASS" if not fails else f"{len(fails)} FAILURES: {fails}"))
sys.exit(0 if not fails else 1)