#!/usr/bin/env python3
"""
parse_comparison.py - Side-by-side comparative analysis of Baseline vs Candidate
for NoMount 3 performance paths.
Role: Tester
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

def load_data(csv_path):
    data = defaultdict(lambda: defaultdict(list))
    with open(csv_path) as f:
        r = csv.reader(f)
        for row in r:
            if not row:
                continue
            test, rnd, it, lat_ns = row[0], int(row[1]), int(row[2]), int(row[3])
            lat_us = lat_ns / 1000.0
            data[test][rnd].append(lat_us)
    return data

def main():
    base_data = load_data("local/keep/evidence/tester-raw/nmbench/bench_baseline.csv")
    cand_data = load_data("local/keep/evidence/tester-raw/nmbench/bench_candidate.csv")

    def pooled_stats(data, test):
        all_samples = []
        for rnd in sorted(data[test].keys()):
            all_samples.extend(data[test][rnd])
        return calc_stats(all_samples)

    def round_stats(data, test, rnd):
        return calc_stats(data[test][rnd])

    print("==========================================================================================================================")
    print("TABLE 1: SECTION A - FILE MATERIALIZATION & OPEN COST (POOLED 3000 SAMPLES)")
    print("==========================================================================================================================")
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

    fmt_head = "{:<36} | {:<24} | {:<24} | {:<24} | {:<10}"
    print(fmt_head.format("Metric", "Baseline (p50/p95/p99)", "Candidate (p50/p95/p99)", "Delta (p50/p95/p99)", "p50 Ratio"))
    print("-" * 130)

    for label, key in a_tests:
        b = pooled_stats(base_data, key)
        c = pooled_stats(cand_data, key)
        b_str = f"{b['p50']:.2f} / {b['p95']:.2f} / {b['p99']:.2f}"
        c_str = f"{c['p50']:.2f} / {c['p95']:.2f} / {c['p99']:.2f}"
        d_p50 = c['p50'] - b['p50']
        d_p95 = c['p95'] - b['p95']
        d_p99 = c['p99'] - b['p99']
        d_str = f"{d_p50:+.2f} / {d_p95:+.2f} / {d_p99:+.2f}"
        r_p50 = c['p50'] / b['p50'] if b['p50'] > 0 else 0
        print(fmt_head.format(label, b_str, c_str, d_str, f"{r_p50:.2f}x"))

    print("\n==========================================================================================================================")
    print("TABLE 2: SECTION B - RULE & DENTRY LOOKUP SCALING (POOLED 3000 SAMPLES)")
    print("==========================================================================================================================")
    scenarios = [
        ("B1 Hit (existing vpath)", "B1_hit_rules_"),
        ("B2 Miss (same prefix)", "B2_miss_same_prefix_rules_"),
        ("B3 Miss (unrelated prefix)", "B3_miss_unrelated_rules_"),
    ]

    fmt_b = "{:<28} | {:<10} | {:<24} | {:<24} | {:<24} | {:<10}"
    print(fmt_b.format("Scenario", "Tier", "Baseline (p50/p95/p99)", "Candidate (p50/p95/p99)", "Delta (p50/p95/p99)", "p50 Ratio"))
    print("-" * 130)

    for sc_name, sc_prefix in scenarios:
        for tier in [50, 200, 500]:
            key = f"{sc_prefix}{tier}"
            b = pooled_stats(base_data, key)
            c = pooled_stats(cand_data, key)
            b_str = f"{b['p50']:.2f} / {b['p95']:.2f} / {b['p99']:.2f}"
            c_str = f"{c['p50']:.2f} / {c['p95']:.2f} / {c['p99']:.2f}"
            d_p50 = c['p50'] - b['p50']
            d_p95 = c['p95'] - b['p95']
            d_p99 = c['p99'] - b['p99']
            d_str = f"{d_p50:+.2f} / {d_p95:+.2f} / {d_p99:+.2f}"
            r_p50 = c['p50'] / b['p50'] if b['p50'] > 0 else 0
            tier_str = f"{tier} rules"
            print(fmt_b.format(sc_name, tier_str, b_str, c_str, d_str, f"{r_p50:.2f}x"))
            sc_name = ""
        print("-" * 130)

    for d_cnt in [10, 1000]:
        key = f"B_dir_lookup_{d_cnt}_entries"
        b = pooled_stats(base_data, key)
        c = pooled_stats(cand_data, key)
        b_str = f"{b['p50']:.2f} / {b['p95']:.2f} / {b['p99']:.2f}"
        c_str = f"{c['p50']:.2f} / {c['p95']:.2f} / {c['p99']:.2f}"
        d_p50 = c['p50'] - b['p50']
        d_p95 = c['p95'] - b['p95']
        d_p99 = c['p99'] - b['p99']
        d_str = f"{d_p50:+.2f} / {d_p95:+.2f} / {d_p99:+.2f}"
        r_p50 = c['p50'] / b['p50'] if b['p50'] > 0 else 0
        print(fmt_b.format("Dir Lookup", f"{d_cnt} entries", b_str, c_str, d_str, f"{r_p50:.2f}x"))

    print("\n==========================================================================================================================")
    print("TABLE 3: SECTION C - MANAGEMENT OPERATION LATENCY (POOLED 3000 SAMPLES)")
    print("==========================================================================================================================")
    c_ops = [
        ("CLI rule add", "C_cli_add_r"),
        ("CLI rule del", "C_cli_del_r"),
        ("Syscall add", "C_sys_add_r"),
        ("Syscall del", "C_sys_del_r"),
        ("Visibility delay", "C_visibility_lag_r"),
    ]

    fmt_c = "{:<20} | {:<6} | {:<7} | {:<24} | {:<24} | {:<24} | {:<10}"
    print(fmt_c.format("Operation", "Tier", "Load", "Baseline (p50/p95/p99)", "Candidate (p50/p95/p99)", "Delta (p50/p95/p99)", "p50 Ratio"))
    print("-" * 130)

    for op_name, op_prefix in c_ops:
        for tier in [47, 200, 500]:
            for load_cond in ["idle", "load"]:
                key = f"{op_prefix}{tier}_{load_cond}"
                b = pooled_stats(base_data, key)
                c = pooled_stats(cand_data, key)
                b_str = f"{b['p50']:.2f} / {b['p95']:.2f} / {b['p99']:.2f}"
                c_str = f"{c['p50']:.2f} / {c['p95']:.2f} / {c['p99']:.2f}"
                d_p50 = c['p50'] - b['p50']
                d_p95 = c['p95'] - b['p95']
                d_p99 = c['p99'] - b['p99']
                d_str = f"{d_p50:+.2f} / {d_p95:+.2f} / {d_p99:+.2f}"
                r_p50 = c['p50'] / b['p50'] if b['p50'] > 0 else 0
                load_lbl = "Idle" if load_cond == "idle" else "Load"
                print(fmt_c.format(op_name, str(tier), load_lbl, b_str, c_str, d_str, f"{r_p50:.2f}x"))
                op_name = ""
        print("-" * 130)

if __name__ == "__main__":
    main()
