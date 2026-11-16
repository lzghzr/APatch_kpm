#!/usr/bin/env python3
"""
parse_point.py: Parses and summarizes NoMount point benchmark CSV data.
Role: Tester
"""

import sys
import os
import glob
import math
from collections import defaultdict

def parse_csv(csv_path: str):
    records = defaultdict(lambda: defaultdict(list))
    if not os.path.exists(csv_path):
        print(f"File not found: {csv_path}")
        return records

    with open(csv_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            metric = parts[0]
            tier = parts[1]
            idx = int(parts[2])
            duration_ns = int(parts[3])
            status = int(parts[4])
            records[metric][tier].append((idx, duration_ns, status))
    return records

def percentile(sorted_arr, p):
    if not sorted_arr:
        return 0.0
    n = len(sorted_arr)
    idx = (n * p) / 100.0
    i = int(idx)
    if i >= n:
        return float(sorted_arr[-1])
    return float(sorted_arr[i])

def calc_stats(samples_with_status):
    if not samples_with_status:
        return {}
    samples_ns = [s[1] for s in samples_with_status]
    statuses = [s[2] for s in samples_with_status]
    arr_us = sorted([ns / 1000.0 for ns in samples_ns])
    count = len(arr_us)
    ok_count = sum(1 for s in statuses if s == 0)

    mean_val = sum(arr_us) / count if count else 0.0
    var_val = sum((x - mean_val) ** 2 for x in arr_us) / count if count else 0.0

    return {
        "count": count,
        "ok_count": ok_count,
        "ok_pct": (ok_count / count * 100.0) if count else 0.0,
        "min": arr_us[0],
        "max": arr_us[-1],
        "p50": percentile(arr_us, 50),
        "p95": percentile(arr_us, 95),
        "p99": percentile(arr_us, 99),
        "mean": mean_val,
        "std": math.sqrt(var_val),
    }

def print_summary(label: str, csv_path: str):
    records = parse_csv(csv_path)
    print(f"\n========================================================")
    print(f"=== Point Benchmark Summary: {label} ({csv_path}) ===")
    print(f"========================================================")

    # 1. P1 ADD
    print("\n--- P1: Pure ADD (200 Rules) ---")
    for scale in ["47", "500"]:
        if scale in records.get("P1_ADD", {}):
            items = records["P1_ADD"][scale]
            s_all = calc_stats(items)
            s_first50 = calc_stats(items[:50])
            s_last50 = calc_stats(items[150:])
            print(f"Scale {scale} [All 200] : p50={s_all['p50']:.2f}us, p95={s_all['p95']:.2f}us, p99={s_all['p99']:.2f}us, mean={s_all['mean']:.2f}us, ok={s_all['ok_count']}/{s_all['count']}")
            print(f"Scale {scale} [First 50]: p50={s_first50['p50']:.2f}us, p95={s_first50['p95']:.2f}us, mean={s_first50['mean']:.2f}us")
            print(f"Scale {scale} [Last 50] : p50={s_last50['p50']:.2f}us, p95={s_last50['p95']:.2f}us, mean={s_last50['mean']:.2f}us")

    # 2. P2 DEL (Busy vs Idle)
    print("\n--- P2: Pure DEL (200 Rules, 500->300) ---")
    for cond in ["P2a_DEL_busy", "P2b_DEL_idle"]:
        pooled = []
        for r in ["round1", "round2", "round3"]:
            items = records.get(cond, {}).get(r, [])
            pooled.extend(items)
            s = calc_stats(items)
            print(f"{cond} [{r}]: p50={s.get('p50', 0):.2f}us, p95={s.get('p95', 0):.2f}us, mean={s.get('mean', 0):.2f}us, ok={s.get('ok_count', 0)}/{s.get('count', 0)}")
        s_pooled = calc_stats(pooled)
        print(f"{cond} [POOLED 600]: p50={s_pooled.get('p50', 0):.2f}us, p95={s_pooled.get('p95', 0):.2f}us, mean={s_pooled.get('mean', 0):.2f}us, ok={s_pooled.get('ok_count', 0)}/{s_pooled.get('count', 0)}")

    # 3. P3 Scale Tiers (47 / 200 / 500)
    print("\n--- P3: Scale Tiers (20 Samples each) ---")
    for scale in ["47", "200", "500"]:
        s_add = calc_stats(records.get("P3_ADD", {}).get(scale, []))
        s_del = calc_stats(records.get("P3_DEL", {}).get(scale, []))
        print(f"Scale {scale} ADD: p50={s_add.get('p50', 0):.2f}us, p95={s_add.get('p95', 0):.2f}us, mean={s_add.get('mean', 0):.2f}us, ok={s_add.get('ok_count', 0)}/{s_add.get('count', 0)}")
        print(f"Scale {scale} DEL: p50={s_del.get('p50', 0):.2f}us, p95={s_del.get('p95', 0):.2f}us, mean={s_del.get('mean', 0):.2f}us, ok={s_del.get('ok_count', 0)}/{s_del.get('count', 0)}")

    # 4. P4
    if "P4_vis_stat_enoent" in records:
        s_p4 = calc_stats(records["P4_vis_stat_enoent"].get("100iters", []))
        print("\n--- P4: Immediate Visibility & Interleaving ---")
        print(f"P4 100 iters stat ENOENT: count={s_p4.get('count', 0)}, ok={s_p4.get('ok_count', 0)}, p50={s_p4.get('p50', 0):.2f}us")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for p in sys.argv[1:]:
            print_summary(os.path.basename(p), p)
    else:
        for f in sorted(glob.glob("local/keep/evidence/tester-raw/nmbench/point/*.csv")):
            print_summary(os.path.basename(f), f)
