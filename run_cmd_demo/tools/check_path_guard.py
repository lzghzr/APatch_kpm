#!/usr/bin/env python3
"""产物级断言：`run_cmd_work` 里 path 的写后回读必须真的决定「是否 exec」。

背景：`*p = X; if (*p != X)` 在 GCC 12.2.1 会被折叠成 `str` + `csel`，不产生任何 `ldr`，
失配分支变成不可达死代码（`aud050b` 即此坑）。但只查「存在/顺序」不够——Auditor 用同外形反例证明
`cmp` 操作数、分支目标/极性、失配路终止三者任一被改都能骗过纯顺序检查。因此这里做四条静态检查：

  A. `cmp` 的两个操作数必须分别是**回读 `ldr` 的目的寄存器**与**写 `sh` 的那条 `str` 的源寄存器**，
     且两者不同（拒绝 `cmp x10,x10` 恒等、`cmp x10,x5` 比错对象）。
  B. `cmp` 之后的条件分支必须是 `b.eq`，目标落在 **exec 窗口**（exec 槽 `ldr` … `blr`）内，
     且 `target != branch+4`（拒绝空分支、极性反转、跳到别处）。
  C. 失配路（`b.eq` 之后到 exec 窗口之前）必须由 `b`/`ret` 终止，且跳转目标越过 exec 窗口——
     不能顺着落进 exec（拒绝「结果被丢弃、照样 exec」）。
  D. exec 点必须是 `ldr <槽>` → `mov w1,#2`（`UMH_WAIT_PROC`）→ `blr`，两段都在 3 条指令内；
     `blr` 的目的必须就是槽 `ldr` 的目的寄存器（AUD-056 d-2b）。
  E. 硬化项（AUD-056）：① `.data` 地址寄存器与「把 sh 写进内存的 str」都必须唯一（d-3）；
     ② `b.eq` 目标必须正好是槽 `ldr`，不能落在窗口中间（d-2a）；
     ③ 回读值与写源在回读→cmp 之间不得被重写（d-4）；④ 失配块内不许有条件分支跳进 exec 窗口（d-1）。

判据顺序即控制流，任一不满足即判失败，并打印失败原因。

输出三态与退出码（AUD-056 关闭后的口径）：
  PASS=0   守卫在这份字节里成立；
  FAIL=1   能定位 exec 窗口，但守卫不成立（写法坏了/被折叠）；
  UNKNOWN=2 无法判断（函数或 exec 窗口不可识别，例如实现换了写法）—— **不判失败**，交维护者裁定。
  本工具是**产物级证据**：结论只对这一份字节（instance_id + SHA-256）成立，不构成对后续构建的外形政策，
  也不得接入发布门禁。

用法：
  python3 run_cmd_demo/tools/check_path_guard.py <kpm> [<kpm> ...]      # 正向：两个变体都要 PASS
  python3 run_cmd_demo/tools/check_path_guard.py --negative <kpm>       # 断言该产物必须 FAIL（旧死代码件）
  python3 run_cmd_demo/tools/check_path_guard.py --negative-control <kpm>  # gap0–gap5 六件回归

`--negative-control` 不再另编最小件（旧版编出来的 `guarded_volatile` 根本没有 `b.cond`，
覆盖不到 B/C/D 三条判据）：改为**从给定产物取真身 `run_cmd_work` 反汇编**，逐条改一处造出
gap1–gap10 十个同外形反例，要求 `gap0 PASS / gap1–gap10 全 FAIL`。gap6–gap10 对应
AUD-056 的四项硬化（d-2a 窗口中间目标、d-2b blr 目的寄存器、d-3 诱饵三元组、d-4 回读值被重写、d-1 块内跳 exec）。
"""

import argparse
import copy
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PREFIX = "aarch64-none-elf-"
INSN = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$")
RELOC = re.compile(r"R_AARCH64_\S+\s+(\S+)")
SYMBOL = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
MEM_OP = re.compile(r"^(x\d+),\s*\[(.+?)\]$")
BR_TARGET = re.compile(r"^([0-9a-f]+)\b")


def tool(name):
    root = os.environ.get("AARCH64_NONE_ELF_DIR")
    if root:
        candidate = Path(root) / "bin" / (PREFIX + name)
        if candidate.exists():
            return str(candidate)
    found = shutil.which(PREFIX + name)
    if not found:
        sys.exit(f"找不到 {PREFIX}{name}（设 AARCH64_NONE_ELF_DIR 或加入 PATH）")
    return found


def dump_of(path):
    proc = subprocess.run([tool("objdump"), "-dr", str(path)], text=True, capture_output=True)
    if proc.returncode != 0:
        sys.exit(f"objdump 失败：{proc.stderr.strip()}")
    return proc.stdout


def parse(dump):
    """按函数名切块 → {symbol: [ {addr, mnemonic, operands, relocs} ]}。"""
    funcs, current, last = {}, None, None
    for line in dump.splitlines():
        m = SYMBOL.match(line)
        if m:
            current, last = m.group(1), None
            funcs[current] = []
            continue
        if current is None:
            continue
        m = INSN.match(line)
        if m:
            ops = re.sub(r"\s*//.*$", "", m.group(4)).strip()
            last = {"addr": int(m.group(1), 16), "mn": m.group(3), "ops": ops, "relocs": []}
            funcs[current].append(last)
            continue
        r = RELOC.search(line)
        if r and last is not None:
            last["relocs"].append(r.group(1))
    return funcs


def first(seq, pred):
    return next((x for x in seq if pred(x)), None)


def regs(operands):
    return [x.strip() for x in operands.split(",")]


def mem_expr(insn):
    m = MEM_OP.match(insn["ops"])
    return (m.group(1), m.group(2)) if m else (None, None)


def br_target(insn):
    m = BR_TARGET.match(insn["ops"].split(",")[-1].strip())
    return int(m.group(1), 16) if m else None


def find_store_load(body):
    """返回 (store, load, cmp_insn, 失败原因)。

    守卫按**语义三元组**定位（store 的源 ∈ `.data` 地址寄存器 → 同址 ldr → cmp{回读目的, 写入源}），
    而不是「第一处 .data store」。段名必须**精确等于 `.data`**：`.data.re_offsets`、`.data+0x8` 这类
    同前缀符号是诱饵（AUD-056 复验指出 `\b` 会把它们一起吞进来），一律不算 sh。这样既不会把别处的 `.data` 寄存器误当写源（d-3 的误报面），
    也能识别**两个都像守卫的三元组**——那正是诱饵守卫外形，判失败而不是挑第一个。
    """
    sh_regs = {
        insn["ops"].split(",")[0].strip()
        for insn in body
        if insn["mn"] in ("adrp", "add") and any(re.fullmatch(r"\.data", r) for r in insn["relocs"])
    }
    stores = [x for x in body if x["mn"] == "str" and mem_expr(x)[0] in sh_regs]
    if not stores:
        return None, None, None, "找不到把 sh（.data 地址寄存器）写进内存的 str —— 连写入都不在"

    triples, unguarded = [], []
    for candidate in stores:
        src, expr = mem_expr(candidate)
        load = first([x for x in body if x["addr"] > candidate["addr"]],
                     lambda x: x["mn"] == "ldr" and mem_expr(x)[1] == expr)
        if load is None:
            unguarded.append((candidate, "写入之后没有同址回读"))
            continue
        dst = mem_expr(load)[0]
        cmp_insn = first([x for x in body if x["addr"] > load["addr"]][:4],
                         lambda x: x["mn"] in ("cmp", "subs") and {ops0 for ops0 in regs(x["ops"])} == {dst, src})
        if cmp_insn is None:
            unguarded.append((candidate, f"回读 {load['addr']:#x} 之后没有 cmp{{{dst}, {src}}}"))
            continue
        triples.append((candidate, load, cmp_insn))

    # d-3（AUD-056 复核补充）：**任何** .data 写入都必须构成守卫三元组。
    # 有诱饵三元组时更要 fail-closed —— 诱饵 + 真实写入未回读（或回读后没比）正是审计给的反例外形。
    if unguarded:
        detail = "；".join(f"{hex(st['addr'])} {why}" for st, why in unguarded)
        return None, None, None, f"存在未构成守卫的 .data 写入（{detail}）——诱饵/旁路外形"
    if not triples:
        return None, None, None, "没有可识别的守卫三元组（store→同址回读→cmp{回读,写入源}）"
    if len(triples) > 1:
        addrs = ", ".join(hex(t[0]["addr"]) for t in triples)
        return None, None, None, f"候选守卫三元组有 {len(triples)} 组（写入点 {addrs}）——诱饵守卫外形"
    return triples[0][0], triples[0][1], triples[0][2], None


def find_exec_window(body):
    """返回 (exec_lo, exec_hi, 失败原因, ldr_dst, blr_reg)：exec 槽 ldr → mov w1,#2 → blr。"""
    wait = first(body, lambda x: x["mn"] == "mov" and re.fullmatch(r"w1,\s*#0x2", x["ops"].replace(" ", "")))
    if wait is None:
        return None, None, "找不到 UMH_WAIT_PROC（mov w1,#2）—— exec 调用点不可定位", None, None
    pos = next(i for i, x in enumerate(body) if x["addr"] == wait["addr"])
    ldr = first(list(reversed(body[max(0, pos - 3) : pos])), lambda x: x["mn"] == "ldr")
    blr = first(body[pos + 1 : pos + 4], lambda x: x["mn"] == "blr")
    if ldr is None or blr is None:
        return None, None, f"{wait['addr']:#x} 附近不是 exec 点（缺 exec 槽 ldr 或 blr）", None, None
    ldr_dst = ldr["ops"].split(",")[0].strip()
    blr_reg = blr["ops"].split(",")[0].strip() or None
    return ldr["addr"], blr["addr"], None, ldr_dst, blr_reg


PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"


def analyse(body, symbol=""):
    """四条检查；返回 (verdict, 说明)。

    verdict 三态（AUD-056 关闭后的口径）：
      PASS    —— 守卫在**这份字节**里成立；
      FAIL    —— 体外能定位 exec 窗口，但守卫不成立（写法坏了/被折叠）；
      UNKNOWN —— 无法判断（函数或 exec 窗口根本不可识别，例如实现换到了别的函数/写法）。
    UNKNOWN **不**等于失败：它只表示工具在这一份字节上给不出结论，交维护者裁定。
    """
    if not body:
        return UNKNOWN, f"反汇编里找不到函数 {symbol or '(指定函数)'} —— 无法判断"

    store, load, cmp_insn, err = find_store_load(body)
    if err:
        return FAIL, err
    sh_reg = mem_expr(store)[0]
    slot_reg = mem_expr(store)[1].split(",")[0].strip()

    # A) cmp 的操作数必须是 {回读目的, 写入源}，且互不相同。
    if cmp_insn is None:
        return FAIL, f"回读 {load['addr']:#x} 之后没有 cmp"
    ops = regs(cmp_insn["ops"])
    loaded = mem_expr(load)[0]
    if len(ops) < 2:
        return FAIL, f"{cmp_insn['addr']:#x} 的 cmp 操作数不完整：{cmp_insn['ops']}"
    if ops[0] == ops[1]:
        return FAIL, f"{cmp_insn['addr']:#x} 是 cmp {ops[0]},{ops[1]}（恒等比较，失配块不可达）"
    if {ops[0], ops[1]} != {loaded, sh_reg}:
        return FAIL, (
            f"{cmp_insn['addr']:#x} 的 cmp {ops[0]},{ops[1]} 比错了对象："
            f"应是回读目的 {loaded} 与写入源（sh）{sh_reg}"
        )

    # D) exec 窗口：ldr <槽> … mov w1,#2 … blr
    exec_lo, exec_hi, err, ldr_dst, blr_reg = find_exec_window(body)
    if err:
        return UNKNOWN, f"{err} —— 不是本判据的判读对象，无法判断"

    store, load, cmp_insn, err = find_store_load(body)
    if err:
        return FAIL, err
    if not load["addr"] < exec_lo:
        return FAIL, f"回读 {load['addr']:#x} 不在 exec 之前"

    # D2) `blr` 的目的必须就是 exec 槽 `ldr` 的目的寄存器（换寄存器等于调别的指针）。
    if blr_reg is not None and ldr_dst is not None and blr_reg != ldr_dst:
        return FAIL, f"exec 点的 blr {blr_reg} 与槽 ldr {ldr_dst} 不是同一个寄存器"

    # D3) 回读值在 cmp 之前不许被重写（无数据流追踪时，重写 xN 即可骗过操作数检查）。
    for x in [y for y in body if load["addr"] < y["addr"] < cmp_insn["addr"]]:
        dest = x["ops"].split(",")[0].strip()
        if x["mn"] in ("str", "cmp", "subs", "cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne", "b") :
            continue
        if dest in (loaded, sh_reg):
            return FAIL, f"{x['addr']:#x} 在回读 {load['addr']:#x} 与 cmp {cmp_insn['addr']:#x} 之间重写了 {dest}"

    # B) 分支必须是 b.eq、目标落在 exec 窗口、不是空分支。
    branch = first([x for x in body if x["addr"] > cmp_insn["addr"]][:3], lambda x: x["mn"] in ("b.eq", "b.ne"))
    if branch is None:
        return FAIL, f"cmp {cmp_insn['addr']:#x} 之后没有条件分支"
    if branch["mn"] != "b.eq":
        return FAIL, f"{branch['addr']:#x} 是 {branch['mn']}（极性反转：相等时必须去 exec）"
    target = br_target(branch)
    if target is None:
        return FAIL, f"{branch['addr']:#x} 的分支目标无法解析：{branch['ops']}"
    if target == branch["addr"] + 4:
        return FAIL, f"{branch['addr']:#x} 的分支目标就是下一条（空分支：两路同路）"
    if not exec_lo <= target <= exec_hi:
        return FAIL, f"{branch['addr']:#x} 的分支目标 {target:#x} 不在 exec 窗口 [{exec_lo:#x},{exec_hi:#x}]"
    if target != exec_lo:
        return FAIL, (
            f"{branch['addr']:#x} 的分支目标 {target:#x} 落在窗口中间（应为槽 ldr {exec_lo:#x}）："
            "跳到 ldr 之后会跳过槽值与 UMH_WAIT_PROC"
        )

    # C) 失配路必须越出 exec 窗口终止，不能顺着落进 exec。
    block = [x for x in body if branch["addr"] < x["addr"] < exec_lo]
    if not block:
        return FAIL, f"{branch['addr']:#x} 与 exec {exec_lo:#x} 之间没有失配块"
    COND = ("b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge", "b.hi", "b.ls", "b.cs", "b.cc",
            "b.mi", "b.pl", "b.vs", "b.vc", "cbz", "cbnz", "tbz", "tbnz")
    for x in block:
        if x["mn"] in COND:
            t = br_target(x)
            if t is not None and exec_lo <= t <= exec_hi:
                return FAIL, (
                    f"失配块 {x['addr']:#x} 的条件分支 {x['mn']} 跳进 exec 窗口 "
                    f"[{exec_lo:#x},{exec_hi:#x}]（块尾终止管不到这条路径）"
                )
    terminator = block[-1]
    if terminator["mn"] not in ("b", "ret"):
        return FAIL, f"失配块最后一条是 {terminator['mn']} {terminator['ops']} —— 会顺着落进 exec"
    if terminator["mn"] == "b":
        t = br_target(terminator)
        if t is None or t <= exec_hi:
            return FAIL, f"失配路的 b 目标 {t if t is None else hex(t)} 没有越过 exec 窗口（结果被丢弃）"
    if not any("printk" in r for x in block for r in x["relocs"]):
        return FAIL, f"失配块（{branch['addr']:#x}–{exec_lo:#x}）里没有 printk 调用"
    eio = first(block, lambda x: x["mn"] == "mov" and re.fullmatch(r"w[01],\s*#0xfffffffb", x["ops"].replace(" ", "")))
    if eio is None:
        return FAIL, "失配块里没有 -EIO（mov w0|w1,#0xfffffffb）"

    return PASS, (
        f"store@{store['addr']:#x} → load@{load['addr']:#x} → cmp({ops[0]},{ops[1]})@{cmp_insn['addr']:#x} "
        f"→ b.eq@{branch['addr']:#x}→{target:#x}(exec 窗口 [{exec_lo:#x},{exec_hi:#x}])；"
        f"失配块 {branch['addr']:#x}–{exec_lo:#x} 含 printk+(-EIO)@{eio['addr']:#x}，以 {terminator['mn']} 越出 exec"
    )


# ---------------------------------------------------------------- 同外形反例

def derive_gaps(body):
    """从真身函数造 gap0–gap5；每个 gap 只改一处，其余完全同形。"""
    ok, why = analyse(body, "run_cmd_work")
    if not ok:
        sys.exit(f"模板件本身不通过（无法用它派生反例）：{why}")

    store, load, _cmp, _err = find_store_load(body)
    exec_lo, exec_hi, _, exec_dst, _ = find_exec_window(body)
    cmp_insn = first([x for x in body if x["addr"] > load["addr"]][:4], lambda x: x["mn"] in ("cmp", "subs"))
    branch = first([x for x in body if x["addr"] > cmp_insn["addr"]][:3], lambda x: x["mn"] in ("b.eq", "b.ne"))
    block = [x for x in body if branch["addr"] < x["addr"] < exec_lo]
    terminator = block[-1]
    sh_reg = mem_expr(store)[0]
    loaded = mem_expr(load)[0]
    blr = first([x for x in body if x["addr"] > exec_lo], lambda x: x["mn"] == "blr")

    def duplicate_guard_triple(src, store_insn, load_insn, cmp_insn):
        """再造一组**完整**三元组（store→同址回读→cmp{回读,写入源}）——这才是 d-3 的诱饵守卫。"""
        clone = copy.deepcopy(src)
        base = max(x["addr"] for x in clone) + 4
        s2 = copy.deepcopy(store_insn); s2["addr"] = base;       s2["ops"] = f"{mem_expr(store_insn)[0]}, [x21]"
        l2 = copy.deepcopy(load_insn);  l2["addr"] = base + 4;   l2["ops"] = f"{mem_expr(load_insn)[0]}, [x21]"
        c2 = copy.deepcopy(cmp_insn);   c2["addr"] = base + 8
        clone.extend([s2, l2, c2])
        return clone

    def decoy_triple_and_unguarded(src, store_insn, load_insn, cmp_insn):
        """造审计给的外形：一组诱饵完整三元组 + 真实 `str` 没有回读。"""
        clone = duplicate_guard_triple(src, store_insn, load_insn, cmp_insn)
        real = next(x for x in clone if x["addr"] == store_insn["addr"])
        real["ops"] = f"{mem_expr(store_insn)[0]}, [x22]"   # 改址后无同址回读
        return clone

    def insert_between(src, after, reg, mn, ops):
        clone = copy.deepcopy(src)
        idx = clone.index(next(x for x in clone if x["addr"] == after["addr"]))
        clone.insert(idx + 1, {"addr": after["addr"] + 2, "mn": mn, "ops": ops, "relocs": []})
        return clone

    def mutate(addr, new_ops=None, new_mn=None, new_target=None):
        clone = copy.deepcopy(body)
        insn = next(x for x in clone if x["addr"] == addr)
        if new_mn:
            insn["mn"] = new_mn
        if new_target is not None:
            insn["ops"] = f"{new_target:x} " + " ".join(insn["ops"].split()[1:])
        if new_ops is not None:
            insn["ops"] = new_ops
        return clone

    gaps = [
        ("gap0 真身（正确）", copy.deepcopy(body), True),
        ("gap1 失配路 b 仍跳 exec（结果被丢弃）", mutate(terminator["addr"], new_target=exec_lo), False),
        ("gap2 b.eq 指向下一条（空分支）", mutate(branch["addr"], new_target=branch["addr"] + 4), False),
        ("gap3 cmp 恒等（失去比较对象）", mutate(cmp_insn["addr"], new_ops="x10, x10"), False),
        ("gap4 cmp 与 slot 地址比（不是 sh）", mutate(cmp_insn["addr"], new_ops=f"{mem_expr(load)[0]}, {mem_expr(store)[1].split(chr(44))[0].strip()}"), False),
        ("gap5 b.eq → b.ne（极性反转）", mutate(branch["addr"], new_mn="b.ne"), False),
        # ---- AUD-056 硬化项的对应反例（d-2a / d-2b / d-3 / d-4 / d-1）----
        ("gap6 分支目标落在窗口中间（跳过槽 ldr）", mutate(branch["addr"], new_target=exec_hi), False),
        ("gap7 blr 换了目的寄存器", mutate(blr["addr"], new_ops="x9"), False),
        ("gap8 第二组完整守卫三元组（诱饵守卫）", duplicate_guard_triple(body, store, load, _cmp), False),
        ("gap9 回读与 cmp 之间重写回读目的", insert_between(body, load, loaded, "mov", f"{loaded}, x0"), False),
        ("gap10 失配块内条件分支跳进 exec", mutate(block[0]["addr"], new_mn="cbnz",
                                                   new_ops=f"x0, {exec_lo:x}"), False),
        ("gap11 诱饵三元组 + 真实写入未回读", decoy_triple_and_unguarded(body, store, load, _cmp), False),
    ]
    return gaps


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*", type=Path)
    parser.add_argument("--negative", action="append", type=Path, default=[])
    parser.add_argument("--negative-control", type=Path, metavar="KPM",
                        help="从该产物取真身反汇编，派生 gap0–gap5 做回归")
    parser.add_argument("--symbol", default="run_cmd_work")
    args = parser.parse_args()

    failures, unknowns = [], []
    for path in args.artifacts:
        body = parse(dump_of(path)).get(args.symbol, [])
        verdict, why = analyse(body, args.symbol)
        print(f"[{verdict}] {path.name}: {why}")
        if verdict == FAIL:
            failures.append(f"{path.name}: {why}")
        elif verdict == UNKNOWN:
            unknowns.append(f"{path.name}: {why}")

    for path in args.negative:
        body = parse(dump_of(path)).get(args.symbol, [])
        verdict, why = analyse(body, args.symbol)
        ok = verdict == FAIL
        print(f"[{'OK' if ok else 'BAD'}] 负向 {path.name}: 期望 FAIL，实际 {verdict}（{why}）")
        if not ok:
            failures.append(f"负向件 {path.name} 判成 {verdict}：判据失效")

    if args.negative_control:
        body = parse(dump_of(args.negative_control)).get(args.symbol, [])
        print(f"负向对照（模板 {args.negative_control.name} / 符号 {args.symbol}）")
        for name, variant, expect_pass in derive_gaps(body):
            verdict, why = analyse(variant, args.symbol)
            good = (verdict == PASS) == expect_pass and verdict != UNKNOWN
            print(f"  [{'OK' if good else 'BAD'}] {name}: 期望{'PASS' if expect_pass else 'FAIL'}，"
                  f"实际 {verdict} —— {why}")
            if not good:
                failures.append(f"{name}: 期望{'PASS' if expect_pass else 'FAIL'}，实际 {verdict}（{why}）")

    for item in failures:
        print(f"  失败：{item}")
    for item in unknowns:
        print(f"  无法判断（交维护者裁定，不判失败）：{item}")
    if failures:
        return 1
    return 2 if unknowns else 0


if __name__ == "__main__":
    sys.exit(main())
