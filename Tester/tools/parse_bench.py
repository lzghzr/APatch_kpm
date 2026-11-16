#!/usr/bin/env python3
"""
parse_bench.py - Analyze raw benchmark results from bench.csv and meta.json using standard library.
Generates markdown summary tables matching the task request.
"""

import csv
import json
import math
from collections import defaultdict

def percentile(sorted_arr, p):
    if not sorted_arr:
        return 0.0
    k = (len(sorted_arr) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_arr[int(k)])
    d0 = sorted_arr[int(f)] * (c - k)
    d1 = sorted_arr[int(c)] * (k - f)
    return float(d0 + d1)

def calc_stats(arr):
    if not arr:
        return {"count": 0, "mean": 0.0, "min": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    s = sorted(arr)
    n = len(s)
    mean_val = sum(s) / n
    return {
        "count": n,
        "mean": mean_val,
        "min": float(s[0]),
        "p50": percentile(s, 50),
        "p95": percentile(s, 95),
        "p99": percentile(s, 99),
        "max": float(s[-1]),
    }

def main():
    csv_path = "local/keep/evidence/tester-raw/nmbench/bench.csv"
    meta_path = "local/keep/evidence/tester-raw/nmbench/meta.json"

    data = defaultdict(lambda: defaultdict(list))
    with open(csv_path) as f:
        r = csv.reader(f)
        for row in r:
            if not row:
                continue
            test, rnd, it, lat_ns = row[0], int(row[1]), int(row[2]), int(row[3])
            lat_us = lat_ns / 1000.0
            data[test][rnd].append(lat_us)

    with open(meta_path) as f:
        meta = json.load(f)

    def pooled_stats(test):
        all_samples = []
        for rnd in sorted(data[test].keys()):
            all_samples.extend(data[test][rnd])
        return calc_stats(all_samples)

    def round_stats(test, rnd):
        return calc_stats(data[test][rnd])

    print("================================================================================")
    print("TABLE 1: SECTION A - FILE MATERIALIZATION & OPEN COST (POOLED 3000 SAMPLES)")
    print("================================================================================")
    
    a_tests = [
        ("A1 Virtual open+read+close", "A1_virtual_open_read_close"),
        ("A2 Real open+read+close (backing)", "A2_real_open_read_close"),
        ("A1 Virtual stat", "A1_virtual_stat"),
        ("A2 Real stat (backing)", "A2_real_stat"),
        ("A3 Virtual open (accumulate 1000 fds)", "A3_accumulate_virtual_open"),
        ("A3 Virtual open (immediate close)", "A3_immediate_virtual_open"),
        ("A3 Real open (accumulate 1000 fds)", "A3_accumulate_real_open"),
        ("A3 Real open (immediate close)", "A3_immediate_real_open"),
    ]
    
    print(f"{'Metric':<38} | {'p50 (µs)':>9} | {'p95 (µs)':>9} | {'p99 (µs)':>9} | {'Mean (µs)':>9} | {'Min (µs)':>9} | {'Max (µs)':>9}")
    print("-" * 105)
    for label, key in a_tests:
        s = pooled_stats(key)
        print(f"{label:<38} | {s['p50']:9.2f} | {s['p95']:9.2f} | {s['p99']:9.2f} | {s['mean']:9.2f} | {s['min']:9.2f} | {s['max']:9.2f}")

    v_orc = pooled_stats("A1_virtual_open_read_close")
    r_orc = pooled_stats("A2_real_open_read_close")
    v_stat = pooled_stats("A1_virtual_stat")
    r_stat = pooled_stats("A2_real_stat")

    print("\n[Section A Comparison & Deltas]")
    print(f"open+read+close: Delta (Virtual - Real) = p50: {v_orc['p50'] - r_orc['p50']:+.2f} µs ({v_orc['p50']/r_orc['p50']:.2f}x), p95: {v_orc['p95'] - r_orc['p95']:+.2f} µs ({v_orc['p95']/r_orc['p95']:.2f}x), p99: {v_orc['p99'] - r_orc['p99']:+.2f} µs ({v_orc['p99']/r_orc['p99']:.2f}x)")
    print(f"stat:            Delta (Virtual - Real) = p50: {v_stat['p50'] - r_stat['p50']:+.2f} µs ({v_stat['p50']/r_stat['p50']:.2f}x), p95: {v_stat['p95'] - r_stat['p95']:+.2f} µs ({v_stat['p95']/r_stat['p95']:.2f}x), p99: {v_stat['p99'] - r_stat['p99']:+.2f} µs ({v_stat['p99']/r_stat['p99']:.2f}x)")

    # FD slope test
    for key, label in [("A3_accumulate_virtual_open", "Virtual Accumulate"), ("A3_accumulate_real_open", "Real Accumulate")]:
        rnds = sorted(data[key].keys())
        first_100_vals = []
        last_100_vals = []
        for r_idx in rnds:
            first_100_vals.extend(data[key][r_idx][:100])
            last_100_vals.extend(data[key][r_idx][-100:])
        first_100 = sum(first_100_vals) / len(first_100_vals)
        last_100 = sum(last_100_vals) / len(last_100_vals)
        print(f"{label} FD Trend: First 100 fds mean = {first_100:.2f} µs, Last 100 fds mean = {last_100:.2f} µs (drift: {last_100 - first_100:+.2f} µs)")

    print("\n================================================================================")
    print("TABLE 2: SECTION B - RULE & DENTRY LOOKUP SCALING (POOLED 3000 SAMPLES)")
    print("================================================================================")
    print(f"{'Target / Scenario':<32} | {'Tier':<10} | {'p50 (µs)':>9} | {'p95 (µs)':>9} | {'p99 (µs)':>9} | {'Mean (µs)':>9} | {'500 vs 50 Ratio':>16}")
    print("-" * 105)

    scenarios = [
        ("B1 Hit (existing virtual path)", "B1_hit_rules_"),
        ("B2 Miss (same prefix, absent)", "B2_miss_same_prefix_rules_"),
        ("B3 Miss (unrelated prefix)", "B3_miss_unrelated_rules_"),
    ]

    for sc_name, sc_prefix in scenarios:
        s50 = pooled_stats(f"{sc_prefix}50")
        s200 = pooled_stats(f"{sc_prefix}200")
        s500 = pooled_stats(f"{sc_prefix}500")
        ratio_p50 = s500['p50'] / s50['p50']
        print(f"{sc_name:<32} | {'50 rules':<10} | {s50['p50']:9.2f} | {s50['p95']:9.2f} | {s50['p99']:9.2f} | {s50['mean']:9.2f} | {'baseline (1.00x)':>16}")
        print(f"{'':<32} | {'200 rules':<10} | {s200['p50']:9.2f} | {s200['p95']:9.2f} | {s200['p99']:9.2f} | {s200['mean']:9.2f} | {s200['p50']/s50['p50']:15.2f}x")
        print(f"{'':<32} | {'500 rules':<10} | {s500['p50']:9.2f} | {s500['p95']:9.2f} | {s500['p99']:9.2f} | {s500['mean']:9.2f} | {ratio_p50:15.2f}x")
        print("-" * 105)

    d10 = pooled_stats("B_dir_lookup_10_entries")
    d1000 = pooled_stats("B_dir_lookup_1000_entries")
    print(f"{'Directory Lookup (10 entries)':<32} | {'10 entries':<10} | {d10['p50']:9.2f} | {d10['p95']:9.2f} | {d10['p99']:9.2f} | {d10['mean']:9.2f} | {'baseline (1.00x)':>16}")
    print(f"{'Directory Lookup (1000 entries)':<32} | {'1000 entries':<10} | {d1000['p50']:9.2f} | {d1000['p95']:9.2f} | {d1000['p99']:9.2f} | {d1000['mean']:9.2f} | {d1000['p50']/d10['p50']:15.2f}x")

    print("\n================================================================================")
    print("TABLE 3: SECTION C - MANAGEMENT OPERATION LATENCY (POOLED 3000 SAMPLES)")
    print("================================================================================")
    print(f"{'Operation':<24} | {'Tier':<10} | {'Condition':<9} | {'p50 (µs)':>10} | {'p95 (µs)':>10} | {'p99 (µs)':>10} | {'Mean (µs)':>10} | {'Load Delta (µs)':>16} | {'Load Ratio':>10}")
    print("-" * 115)

    c_ops = [
        ("CLI rule add (fork+exec)", "C_cli_add_r"),
        ("CLI rule del (fork+exec)", "C_cli_del_r"),
        ("Syscall add_key (add)", "C_sys_add_r"),
        ("Syscall add_key (del)", "C_sys_del_r"),
        ("Visibility delay", "C_visibility_lag_r"),
    ]

    for op_name, op_prefix in c_ops:
        for tier in [47, 200, 500]:
            idle = pooled_stats(f"{op_prefix}{tier}_idle")
            load = pooled_stats(f"{op_prefix}{tier}_load")
            delta_p50 = load['p50'] - idle['p50']
            ratio_p50 = load['p50'] / idle['p50'] if idle['p50'] > 0 else 0
            
            print(f"{op_name:<24} | {tier:<10} | {'Idle':<9} | {idle['p50']:10.2f} | {idle['p95']:10.2f} | {idle['p99']:10.2f} | {idle['mean']:10.2f} | {'-':>16} | {'1.00x':>10}")
            print(f"{'':<24} | {tier:<10} | {'Read Load':<9} | {load['p50']:10.2f} | {load['p95']:10.2f} | {load['p99']:10.2f} | {load['mean']:10.2f} | {delta_p50:+16.2f} | {ratio_p50:9.2f}x")
            print("-" * 115)

    print("\n================================================================================")
    print("ROUND-BY-ROUND STABILITY (p50 across 3 rounds)")
    print("================================================================================")
    for test in sorted(data.keys()):
        p50s = [round_stats(test, r)['p50'] for r in sorted(data[test].keys())]
        p50_str = ", ".join(f"r{r}:{v:.2f}µs" for r, v in zip(sorted(data[test].keys()), p50s))
        print(f"{test:<35} : {p50_str}")

if __name__ == "__main__":
    main()
