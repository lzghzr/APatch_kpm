#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Auditor 产物审计工具常驻回归自检（DEV-068 / AUD-011）。

覆盖的三大类回归项：
  1. reloc_mapping_abi_parity:
     按 Arm AAELF64 规范核对重定位类型名映射（至少覆盖 281, 282, 283, 287, 299, 311~314, 263~266），
     确保 281 留空并触发 review 告警，282 为 R_AARCH64_JUMP26（绝非 R_AARCH64_ADR_GOT_PAGE），
     311~313 为 GOT 相关指令重定位，314 为 PLT32 数据重定位，287 为 MOVW_PREL_G0。
  2. reloc_boundary_flush:
     宽度贴边回归（offset + reloc_width == target_size），覆盖 4 字节指令、8 字节数据、2 字节数据，
     断言 bad_relocs == 0 且无越界错误（杜绝 AUD-011 类贴边误报）。
  3. reloc_boundary_overflow_one_byte:
     一字节越界回归（offset + reloc_width == target_size + 1），覆盖 4 字节指令、8 字节数据、2 字节数据，
     断言 bad_relocs 精确拦截并触发 error 级 relocation_bounds。
  4. real_artifact_130_parity:
     若本地存在真实 1.3.0 候选产物，全量解析并验证 JUMP26 数量（47 条）、GOT 依赖为 0、越界数为 0。

用法:
  python3 Auditor/tools/selftest_artifact_audit.py
  python3 Auditor/tools/artifact_audit.py --selftest
"""

import os
import sys

# 保证能从脚本所在目录或仓储根目录导入 artifact_audit
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

try:
    from artifact_audit import (
        AARCH64_RELOC_NAMES,
        audit_relocations,
        reloc_target_width,
        Elf,
    )
except ImportError:
    from Auditor.tools.artifact_audit import (
        AARCH64_RELOC_NAMES,
        audit_relocations,
        reloc_target_width,
        Elf,
    )


def test_reloc_mapping_abi_parity():
    """用例 1: Arm AAELF64 规范映射核对与白名单告警机制。"""
    failures = []

    # 1.1 281 必须留空（AAELF64 中为保留/未分配），不能被误登记为 JUMP26
    if 281 in AARCH64_RELOC_NAMES:
        failures.append(f"281 应留空未分配，当前被登记为 {AARCH64_RELOC_NAMES[281]}")

    # 1.2 282 必须为 R_AARCH64_JUMP26（绝非 R_AARCH64_ADR_GOT_PAGE）
    name_282 = AARCH64_RELOC_NAMES.get(282)
    if name_282 != "R_AARCH64_JUMP26":
        failures.append(f"282 预期 R_AARCH64_JUMP26，实际为 {name_282}")

    # 1.3 283 必须为 R_AARCH64_CALL26
    name_283 = AARCH64_RELOC_NAMES.get(283)
    if name_283 != "R_AARCH64_CALL26":
        failures.append(f"283 预期 R_AARCH64_CALL26，实际为 {name_283}")

    # 1.4 287 必须为 R_AARCH64_MOVW_PREL_G0（绝非 R_AARCH64_LDST128_ABS_LO12_NC）
    name_287 = AARCH64_RELOC_NAMES.get(287)
    if name_287 != "R_AARCH64_MOVW_PREL_G0":
        failures.append(f"287 预期 R_AARCH64_MOVW_PREL_G0，实际为 {name_287}")

    # 1.5 299 必须为 R_AARCH64_LDST128_ABS_LO12_NC
    name_299 = AARCH64_RELOC_NAMES.get(299)
    if name_299 != "R_AARCH64_LDST128_ABS_LO12_NC":
        failures.append(f"299 预期 R_AARCH64_LDST128_ABS_LO12_NC，实际为 {name_299}")

    # 1.6 311~314 GOT 与 PLT 重定位核对
    expected_got = {
        311: "R_AARCH64_ADR_GOT_PAGE",
        312: "R_AARCH64_LD64_GOT_LO12_NC",
        313: "R_AARCH64_LD64_GOTPAGE_LO15",
        314: "R_AARCH64_PLT32",
    }
    for rtype, exp_name in expected_got.items():
        act_name = AARCH64_RELOC_NAMES.get(rtype)
        if act_name != exp_name:
            failures.append(f"{rtype} 预期 {exp_name}，实际为 {act_name}")

    # 1.7 263~266 MOVW_UABS 组核对
    expected_movw = {
        263: "R_AARCH64_MOVW_UABS_G0",
        264: "R_AARCH64_MOVW_UABS_G0_NC",
        265: "R_AARCH64_MOVW_UABS_G1",
        266: "R_AARCH64_MOVW_UABS_G1_NC",
    }
    for rtype, exp_name in expected_movw.items():
        act_name = AARCH64_RELOC_NAMES.get(rtype)
        if act_name != exp_name:
            failures.append(f"{rtype} 预期 {exp_name}，实际为 {act_name}")

    # 1.8 补丁宽度计算核对
    expected_widths = {
        257: 8,  # ABS64
        258: 4,  # ABS32
        259: 2,  # ABS16
        260: 8,  # PREL64
        261: 4,  # PREL32
        262: 2,  # PREL16
        275: 4,  # ADR_PREL_PG_HI21
        277: 4,  # ADD_ABS_LO12_NC
        282: 4,  # JUMP26
        283: 4,  # CALL26
        287: 4,  # MOVW_PREL_G0
        299: 4,  # LDST128_ABS_LO12_NC
        307: 8,  # GOTREL64
        311: 4,  # ADR_GOT_PAGE
        312: 4,  # LD64_GOT_LO12_NC
        313: 4,  # LD64_GOTPAGE_LO15
        314: 4,  # PLT32
        999: 4,  # 未知保底
    }
    for rtype, exp_w in expected_widths.items():
        act_w = reloc_target_width(rtype)
        if act_w != exp_w:
            failures.append(f"类型 {rtype} 补丁宽度预期 {exp_w}，实际为 {act_w}")

    # 1.9 未登记类型（如 281、999）触发 review 告警且不静默丢弃
    mock_relocs = [
        {"type": 281, "symidx": 0, "offset": 0, "target_size": 16, "section": ".rela.text"},
        {"type": 999, "symidx": 0, "offset": 4, "target_size": 16, "section": ".rela.text"},
    ]
    facts, findings = audit_relocations(mock_relocs, num_symbols=1)
    if facts["types"].get("type_281") != 1:
        failures.append("未在白名单的 281 未按 type_281 格式汇总")
    review_types = [msg for sev, kind, msg in findings if sev == "review" and kind == "reloc_type"]
    if not any("281" in m for m in review_types):
        failures.append("281 未触发预期 review 告警")
    if not any("999" in m for m in review_types):
        failures.append("999 未触发预期 review 告警")

    return len(failures) == 0, failures


def test_reloc_boundary_flush():
    """用例 2: 宽度贴边测试（offset + reloc_width == target_size），断言合法放行。"""
    failures = []
    cases = [
        # (name, rtype, reloc_width, target_size, offset)
        ("4字节指令 R_AARCH64_JUMP26 贴边 (AUD-011 现场)", 282, 4, 120, 116),
        ("4字节指令 R_AARCH64_CALL26 贴边", 283, 4, 100, 96),
        ("4字节指令 R_AARCH64_ADR_GOT_PAGE 贴边", 311, 4, 64, 60),
        ("8字节数据 R_AARCH64_ABS64 贴边", 257, 8, 64, 56),
        ("8字节数据 R_AARCH64_PREL64 贴边", 260, 8, 32, 24),
        ("2字节数据 R_AARCH64_ABS16 贴边", 259, 2, 16, 14),
        ("2字节数据 R_AARCH64_PREL16 贴边", 262, 2, 8, 6),
    ]

    for desc, rtype, width, target_size, offset in cases:
        mock_relocs = [{
            "type": rtype, "symidx": 0, "offset": offset,
            "target_size": target_size, "section": ".rela.test",
        }]
        facts, findings = audit_relocations(mock_relocs, num_symbols=1)
        if facts["bad"] != 0:
            failures.append(f"{desc} 失败: bad_relocs 预期 0，实际为 {facts['bad']}")
        errs = [msg for sev, kind, msg in findings if sev == "error" and kind == "relocation_bounds"]
        if errs:
            failures.append(f"{desc} 误报越界错误: {errs}")

    return len(failures) == 0, failures


def test_reloc_boundary_overflow_one_byte():
    """用例 3: 一字节越界测试（offset + reloc_width == target_size + 1），断言精确拦截。"""
    failures = []
    cases = [
        # (name, rtype, reloc_width, target_size, offset)
        ("4字节指令 R_AARCH64_JUMP26 越界 1 字节", 282, 4, 120, 117),
        ("4字节指令 R_AARCH64_CALL26 越界 1 字节", 283, 4, 100, 97),
        ("4字节指令 R_AARCH64_ADR_GOT_PAGE 越界 1 字节", 311, 4, 64, 61),
        ("8字节数据 R_AARCH64_ABS64 越界 1 字节", 257, 8, 64, 57),
        ("8字节数据 R_AARCH64_PREL64 越界 1 字节", 260, 8, 32, 25),
        ("2字节数据 R_AARCH64_ABS16 越界 1 字节", 259, 2, 16, 15),
        ("2字节数据 R_AARCH64_PREL16 越界 1 字节", 262, 2, 8, 7),
    ]

    for desc, rtype, width, target_size, offset in cases:
        mock_relocs = [{
            "type": rtype, "symidx": 0, "offset": offset,
            "target_size": target_size, "section": ".rela.test",
        }]
        facts, findings = audit_relocations(mock_relocs, num_symbols=1)
        if facts["bad"] != 1:
            failures.append(f"{desc} 未能拦截: bad_relocs 预期 1，实际为 {facts['bad']}")
        errs = [msg for sev, kind, msg in findings if sev == "error" and kind == "relocation_bounds"]
        if not errs:
            failures.append(f"{desc} 未产生预期 relocation_bounds 错误")

    return len(failures) == 0, failures


def test_real_artifact_130_parity():
    """用例 4: 真实 1.3.0 产物重定位交叉验证（JUMP26=47, GOT=0, bad=0）。"""
    failures = []
    candidates = [
        os.path.join(REPO_DIR, "artifacts/zram_zstd-1.3.0+g78b09e56207f.ra6745102.kpb51197a.ndk26.3.11579264/zram_zstd_1.3.0.kpm"),
        os.path.join(REPO_DIR, "artifacts/zram_zstd-1.3.0_baselines+g78b09e56207f.rdcb41eb0.kpb51197a.ndk26.3.11579264/zram_zstd_1.3.0_baselines.kpm"),
    ]

    checked = 0
    for path in candidates:
        if not os.path.isfile(path):
            continue
        checked += 1
        elf = Elf(path)
        facts, findings = audit_relocations(elf.relocations, len(elf.symbols))

        # 验证 bad_relocs == 0
        if facts["bad"] != 0:
            failures.append(f"{os.path.basename(path)} 重定位越界误报: bad={facts['bad']}")

        # 验证 R_AARCH64_JUMP26 恰好 47 条
        jump26_count = facts["types"].get("R_AARCH64_JUMP26", 0)
        if jump26_count != 47:
            failures.append(f"{os.path.basename(path)} R_AARCH64_JUMP26 计数预期 47，实际为 {jump26_count}")

        # 验证 R_AARCH64_ADR_GOT_PAGE 为 0（不含 GOT）
        got_count = facts["types"].get("R_AARCH64_ADR_GOT_PAGE", 0)
        if got_count != 0:
            failures.append(f"{os.path.basename(path)} 不应包含 R_AARCH64_ADR_GOT_PAGE，实际包含 {got_count}")

    if checked == 0:
        failures.append("未找到 1.3.0 真实产物进行集成验证")

    return len(failures) == 0, failures


def run_tests():
    tests = [
        ("reloc_mapping_abi_parity", test_reloc_mapping_abi_parity),
        ("reloc_boundary_flush", test_reloc_boundary_flush),
        ("reloc_boundary_overflow_one_byte", test_reloc_boundary_overflow_one_byte),
        ("real_artifact_130_parity", test_real_artifact_130_parity),
    ]

    all_ok = True
    print("=== Auditor 自有自检: artifact_audit 重定位回归 ===")
    for name, test_func in tests:
        ok, details = test_func()
        if ok:
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name}")
            for d in details:
                print(f"       - {d}")
            all_ok = False

    print()
    if all_ok:
        print("Auditor 自检结果：全部通过（4/4 PASS）")
    else:
        print("Auditor 自检结果：存在失败项")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
