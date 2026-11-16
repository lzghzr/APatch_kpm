#!/usr/bin/env python3
"""
parse_aba.py - A/B/A discriminative analysis comparing baseline1, candidate, and baseline2.
Role: Tester
"""

import csv
import json
import math
from collections import defaultdict

def load_csv(path):
    data = defaultdict(lambda: defaultdict(list))
    with open(path) as f:
        for row in csv.reader(f):
            if not row:
                continue
            test, rnd, it, lat_ns = row[0], int(row[1]), int(row[2]), int(row[3])
            data[test][rnd].append(lat_ns / 1000.0)
    return data

def percentile(s, p):
    if not s:
        return 0.0
    k = (len(s) - 1) * (p / 100.0)
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return float(s[int(k)])
    return float(s[int(f)] * (c - k) + s[int(c)] * (k - f))

def stats(arr):
    if not arr:
        return {"n": 0, "mean": 0.0, "std": 0.0, "se": 0.0, "ci95_low": 0.0, "ci95_high": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "min": 0.0, "max": 0.0}
    s = sorted(arr)
    n = len(s)
    m = sum(s) / n
    var = sum((x - m) ** 2 for x in s) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(var)
    se = std / math.sqrt(n) if n > 0 else 0.0
    return {
        "n": n,
        "mean": m,
        "std": std,
        "se": se,
        "ci95_low": m - 1.96 * se,
        "ci95_high": m + 1.96 * se,
        "p50": percentile(s, 50),
        "p95": percentile(s, 95),
        "p99": percentile(s, 99),
        "min": s[0],
        "max": s[-1]
    }

def pool(d, test):
    all_v = []
    for r in sorted(d[test].keys()):
        all_v.extend(d[test][r])
    return all_v

def calc_diff_stats(v_arr, n_arr):
    # Paired sample difference Di = Vi - Ni
    n = min(len(v_arr), len(n_arr))
    diffs = [v_arr[i] - n_arr[i] for i in range(n)]
    return stats(diffs)

def main():
    b1 = load_csv("local/keep/evidence/tester-raw/nmbench/bench_baseline.csv")
    cand = load_csv("local/keep/evidence/tester-raw/nmbench/bench_candidate.csv")
    b2 = load_csv("local/keep/evidence/tester-raw/nmbench/bench_baseline2.csv")

    print("==========================================================================================")
    print("A/B/A DISCRIMINATIVE COMPARISON TABLE (Sony XQ-DQ72, Core 4)")
    print("Baseline1 (a81a28e) vs Candidate (3a10db5) vs Baseline2 (Current)")
    print("==========================================================================================")

    # 1. Native Controls
    print("\n--- 1. Native Controls (Real Filesystem, NoMount Uninvolved) ---")
    native_keys = [
        ("A2 Real open+read+close", "A2_real_open_read_close"),
        ("A2 Real stat", "A2_real_stat"),
        ("A3 Real open (accumulate 1000 fds)", "A3_accumulate_real_open"),
        ("A3 Real open (immediate close)", "A3_immediate_real_open"),
    ]
    print(f"{'Metric':<34} | {'B1 p50':>8} | {'Cand p50':>8} | {'B2 p50':>8} | {'B1 Mean':>8} | {'Cand Mean':>9} | {'B2 Mean':>8}")
    print("-" * 92)
    for label, k in native_keys:
        s1 = stats(pool(b1, k))
        sc = stats(pool(cand, k))
        s2 = stats(pool(b2, k))
        print(f"{label:<34} | {s1['p50']:8.2f} | {sc['p50']:8.2f} | {s2['p50']:8.2f} | {s1['mean']:8.2f} | {sc['mean']:9.2f} | {s2['mean']:8.2f}")

    # 2. Virtual Paths
    print("\n--- 2. Virtual Paths ---")
    virt_keys = [
        ("A1 Virtual open+read+close", "A1_virtual_open_read_close"),
        ("A1 Virtual stat", "A1_virtual_stat"),
        ("A3 Virtual open (accumulate 1000 fds)", "A3_accumulate_virtual_open"),
        ("A3 Virtual open (immediate close)", "A3_immediate_virtual_open"),
    ]
    print(f"{'Metric':<34} | {'B1 p50':>8} | {'Cand p50':>8} | {'B2 p50':>8} | {'B1 Mean':>8} | {'Cand Mean':>9} | {'B2 Mean':>8}")
    print("-" * 92)
    for label, k in virt_keys:
        s1 = stats(pool(b1, k))
        sc = stats(pool(cand, k))
        s2 = stats(pool(b2, k))
        print(f"{label:<34} | {s1['p50']:8.2f} | {sc['p50']:8.2f} | {s2['p50']:8.2f} | {s1['mean']:8.2f} | {sc['mean']:9.2f} | {s2['mean']:8.2f}")

    # 3. Virtual - Native Deltas
    print("\n--- 3. Normalized Overhead Gap: Virtual - Native (Same Round Paired) ---")
    gap_pairs = [
        ("A1/A2 open+read+close Gap", "A1_virtual_open_read_close", "A2_real_open_read_close"),
        ("A1/A2 stat Gap", "A1_virtual_stat", "A2_real_stat"),
    ]

    for label, vk, nk in gap_pairs:
        print(f"\n[{label}]")
        print(f"{'Dataset':<14} | {'p50(V)-p50(N)':>13} | {'Mean Diff':>10} | {'Std':>8} | {'95% CI':>22}")
        print("-" * 75)
        for d_name, d_data in [("Baseline 1", b1), ("Candidate", cand), ("Baseline 2", b2)]:
            v_p = pool(d_data, vk)
            n_p = pool(d_data, nk)
            sv = stats(v_p)
            sn = stats(n_p)
            sd = calc_diff_stats(v_p, n_p)
            p50_diff = sv['p50'] - sn['p50']
            ci_str = f"[{sd['ci95_low']:+.2f}, {sd['ci95_high']:+.2f}]"
            print(f"{d_name:<14} | {p50_diff:+13.2f} | {sd['mean']:+10.2f} | {sd['std']:8.2f} | {ci_str:>22}")

        # Per-round detail
        print("  Round breakdown (Mean Diff & 95% CI):")
        for d_name, d_data in [("Baseline 1", b1), ("Candidate", cand), ("Baseline 2", b2)]:
            r_strs = []
            for r in [1, 2, 3]:
                vr = d_data[vk][r]
                nr = d_data[nk][r]
                sdr = calc_diff_stats(vr, nr)
                r_strs.append(f"r{r}: {sdr['mean']:+.2f} [{sdr['ci95_low']:+.2f},{sdr['ci95_high']:+.2f}]")
            print(f"    {d_name:<12}: " + "; ".join(r_strs))

    # 4. Section B: Miss unrelated prefix (50, 200, 500)
    print("\n--- 4. Section B: B3 Miss Unrelated Prefix (Bloom Filter Fast Reject) ---")
    b3_keys = [
        ("B3 Miss unrelated (50 rules)", "B3_miss_unrelated_rules_50"),
        ("B3 Miss unrelated (200 rules)", "B3_miss_unrelated_rules_200"),
        ("B3 Miss unrelated (500 rules)", "B3_miss_unrelated_rules_500"),
    ]
    print(f"{'Metric':<34} | {'B1 p50':>8} | {'Cand p50':>8} | {'B2 p50':>8} | {'Cand/B1':>8} | {'B2/B1':>8}")
    print("-" * 80)
    for label, k in b3_keys:
        s1 = stats(pool(b1, k))
        sc = stats(pool(cand, k))
        s2 = stats(pool(b2, k))
        c_r = sc['p50'] / s1['p50'] if s1['p50'] > 0 else 0
        b2_r = s2['p50'] / s1['p50'] if s1['p50'] > 0 else 0
        print(f"{label:<34} | {s1['p50']:8.2f} | {sc['p50']:8.2f} | {s2['p50']:8.2f} | {c_r:7.2f}x | {b2_r:7.2f}x")

    # 5. Section C: Kernel add_key / del syscall cost (Idle)
    print("\n--- 5. Section C: Kernel SYS_add_key Cost (Idle) ---")
    c_keys = [
        ("Syscall add_key (add, 47 rules)", "C_sys_add_r47_idle"),
        ("Syscall add_key (add, 500 rules)", "C_sys_add_r500_idle"),
        ("Syscall add_key (del, 47 rules)", "C_sys_del_r47_idle"),
        ("Syscall add_key (del, 500 rules)", "C_sys_del_r500_idle"),
    ]
    print(f"{'Metric':<36} | {'B1 p50':>8} | {'Cand p50':>8} | {'B2 p50':>8} | {'Cand/B1':>8} | {'B2/B1':>8}")
    print("-" * 82)
    for label, k in c_keys:
        s1 = stats(pool(b1, k))
        sc = stats(pool(cand, k))
        s2 = stats(pool(b2, k))
        c_r = sc['p50'] / s1['p50'] if s1['p50'] > 0 else 0
        b2_r = s2['p50'] / s1['p50'] if s1['p50'] > 0 else 0
        print(f"{label:<36} | {s1['p50']:8.2f} | {sc['p50']:8.2f} | {s2['p50']:8.2f} | {c_r:7.2f}x | {b2_r:7.2f}x")

    print("\n==========================================================================================")
    print("MARKDOWN TABLES")
    print("==========================================================================================")

    md_items = [
        ("A1 虚拟 open+read+close", "A1_virtual_open_read_close"),
        ("A2 真实 open+read+close (原生对照)", "A2_real_open_read_close"),
        ("A1 虚拟 stat", "A1_virtual_stat"),
        ("A2 真实 stat (原生对照)", "A2_real_stat"),
        ("A3 真实 open (累积 1000 fds)", "A3_accumulate_real_open"),
        ("A3 真实 open (立即 close)", "A3_immediate_real_open"),
        ("B3 无关前缀未命中 (50 规则)", "B3_miss_unrelated_rules_50"),
        ("B3 无关前缀未命中 (200 规则)", "B3_miss_unrelated_rules_200"),
        ("B3 无关前缀未命中 (500 规则)", "B3_miss_unrelated_rules_500"),
        ("C 内核 add_key add (47 规则, 空闲)", "C_sys_add_r47_idle"),
        ("C 内核 add_key add (500 规则, 空闲)", "C_sys_add_r500_idle"),
        ("C 内核 add_key del (47 规则, 空闲)", "C_sys_del_r47_idle"),
        ("C 内核 add_key del (500 规则, 空闲)", "C_sys_del_r500_idle"),
    ]

    print("| 测量项目 | Baseline 1 (µs)<br>(a81a28e) | Candidate (µs)<br>(3a10db5) | Baseline 2 (µs)<br>(本轮复核) | 判读（判别性） |")
    print("| :--- | :---: | :---: | :---: | :--- |")
    for name, k in md_items:
        s1 = stats(pool(b1, k))
        sc = stats(pool(cand, k))
        s2 = stats(pool(b2, k))
        p1 = s1["p50"]
        pc = sc["p50"]
        p2 = s2["p50"]
        judg = ""
        if "原生对照" in name or "真实" in name:
            if abs(p2 - p1) < abs(p2 - pc):
                judg = "B2 接近 B1 (会话状态漂移)"
            else:
                judg = "B2 接近 Cand (B1 异常)"
        elif "B3" in name:
            if abs(pc - p2) < 0.2:
                judg = "无法区分"
            else:
                judg = "未复现 (频偏脉冲)"
        elif "add_key add" in name:
            if pc > p1 * 1.5 and p2 < pc * 0.7:
                judg = "稳定复现 (2倍耗时上升)"
            else:
                judg = "未复现"
        elif "add_key del" in name:
            if pc < p1 * 0.5 and p2 > pc * 3:
                judg = "稳定复现 (异步退役提速)"
            else:
                judg = "无法区分"
        elif "虚拟" in name:
            judg = "未复现 (净差未收敛)"
        print(f"| **{name}** | p50: {p1:.2f}<br>均值: {s1['mean']:.2f} | p50: {pc:.2f}<br>均值: {sc['mean']:.2f} | p50: {p2:.2f}<br>均值: {s2['mean']:.2f} | {judg} |")

if __name__ == "__main__":
    main()
