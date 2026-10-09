#!/usr/bin/env python3
"""用选定镜像的指令证据运行生产 C 推导；这是 Developer 离线自检。"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


class Code(ctypes.Structure):
    _fields_ = [("words", ctypes.POINTER(ctypes.c_uint32)), ("count", ctypes.c_uint), ("addr", ctypes.c_uint64)]


class Layout(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int16) for name in
                ("id", "config", "mcgrps", "n_mcgrps", "n_mcgrps_size", "mcgrp_offset", "net_sock")]


def instruction_source(root):
    source = (root / "kpm_utils.h").read_text()
    return source.split("// instruction\n", 1)[1].rsplit("#endif", 1)[0]


def offset_source(module):
    header = (module / "re_kernel.h").read_text()
    namesize = re.search(r"^#define GENL_NAMSIZ .*?$", header, re.M)[0]
    family = header[header.index("struct genl_family_config {"):header.index("struct nlattr {")]
    # 独立偏移夹具也使用生产 family 定义，保证 sizeof 与实际构建一致。
    types = "#ifndef __RE_KERNEL_H\n" + namesize + "\n#ifndef __aligned\n" + \
            "#define __aligned(n) __attribute__((aligned(n)))\n#endif\n" + family + "#endif\n"
    offsets = re.search(r"struct struct_offset\s*\{.*?\};", (module / "re_utils.h").read_text(), re.S)[0]
    return types + offsets + "\nstruct struct_offset struct_offset;\nstatic long calculate_offsets(void) {\n" + (module / "re_offsets.c").read_text().split(
        "// Generic Netlink 偏移推导\n", 1)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--image", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    module = Path(__file__).resolve().parents[1]
    source = module / "re_offsets.c"
    root = module.parent
    # 仅模拟锚点地址；提取 calculate_offsets 的生产 Genl 段，以相同的固定窗口读取指令。
    wrapper = r"""
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define CONFIG_DEBUG 1
static char trace_buffer[32768];
static unsigned int trace_used;
static void probe_log(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void probe_log(const char* format, ...) {
  va_list args;
  va_start(args, format);
  int n = vsnprintf(trace_buffer + trace_used, sizeof(trace_buffer) - trace_used, format, args);
  va_end(args);
  assert(n >= 0 && (unsigned int)n < sizeof(trace_buffer) - trace_used);
  trace_used += n;
}
#define logkm probe_log
#define lookup_name(func) \
  func = (typeof(func))kallsyms_lookup_name(#func); \
  if (!func) return -21;
struct probe_code { const uint32_t* words; unsigned int count; uint64_t addr; };
static struct probe_code* probe_codes;
static unsigned long kallsyms_lookup_name(const char* name) {
  probe_log("lookup %s\n", name);
  const char* names[] = {"genlmsg_multicast_allns", "genlmsg_put", "genl_unregister_family", "genl_pernet_exit"};
  for (unsigned int i = 0; i < 4; i++) {
    if (!strcmp(name, names[i])) return (unsigned long)probe_codes[i].words;
  }
  return 0;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
""" + instruction_source(root) + "\n#pragma clang diagnostic pop\n" + offset_source(module) + r"""
struct probe_layout { int16_t id, config, mcgrps, n_mcgrps, n_mcgrps_size, mcgrp_offset, net_sock; };
const char* probe_trace(void) { return trace_buffer; }
int probe(struct probe_code* codes, struct probe_layout* out) {
  trace_used = 0;
  trace_buffer[0] = 0;
  probe_codes = codes;
  struct_offset.binder_alloc_buffer_size = 0x123;
  struct_offset.genl_family_id = out->id;
  struct_offset.genl_family_config = out->config;
  struct_offset.genl_family_mcgrps = out->mcgrps;
  struct_offset.genl_family_n_mcgrps = out->n_mcgrps;
  struct_offset.genl_family_n_mcgrps_size = out->n_mcgrps_size;
  struct_offset.genl_family_mcgrp_offset = out->mcgrp_offset;
  struct_offset.net_genl_sock = out->net_sock;
  int rc = calculate_offsets();
  // 加载时即算即存；失败中止加载，仍须保护已有的 Binder 字段。
  assert(struct_offset.binder_alloc_buffer_size == 0x123);
  out->id = struct_offset.genl_family_id;
  out->config = struct_offset.genl_family_config;
  out->mcgrps = struct_offset.genl_family_mcgrps;
  out->n_mcgrps = struct_offset.genl_family_n_mcgrps;
  out->n_mcgrps_size = struct_offset.genl_family_n_mcgrps_size;
  out->mcgrp_offset = struct_offset.genl_family_mcgrp_offset;
  out->net_sock = struct_offset.net_genl_sock;
  return rc;
}
"""
    results = []
    with tempfile.TemporaryDirectory(prefix="rekernel-genl-") as tmp:
        temp = Path(tmp)
        cfile = temp / "probe.c"
        cfile.write_text(wrapper)
        library = temp / "probe.so"
        subprocess.run(["clang", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        lib.probe.argtypes = [ctypes.POINTER(Code), ctypes.POINTER(Layout)]
        lib.probe_trace.restype = ctypes.c_char_p
        for name in args.image:
            buffers, views, evidence_hashes = [], [], {}
            image_path = args.evidence / "inputs" / name / "Image"
            symbol_path = args.evidence / "legacy" / name / "kallsyms_extracted.txt"
            image_bytes = image_path.read_bytes()
            symbols = [(int(addr, 16), symbol) for addr, symbol in re.findall(
                r"^([0-9a-f]+) [a-zA-Z] (\S+)$", symbol_path.read_text(), re.M)]
            for fn, window in (("genlmsg_multicast_allns", 32), ("genlmsg_put", 0x14),
                               ("genl_unregister_family", 0x55), ("genl_pernet_exit", 8)):
                addr = next(addr for addr, symbol in symbols if symbol == fn)
                end = addr + window * 4
                raw = image_bytes[addr:end]
                assert len(raw) == end - addr, fn
                words = [int.from_bytes(raw[pos:pos + 4], "little") for pos in range(0, len(raw), 4)]
                buffer = (ctypes.c_uint32 * len(words))(*words)
                buffers.append(buffer)
                views.append(Code(buffer, len(words), addr))
                evidence_hashes[fn] = {"file_offset": addr, "size": len(raw),
                                       "sha256": hashlib.sha256(raw).hexdigest()}
            evidence_hashes["Image"] = hashlib.sha256(image_bytes).hexdigest()
            evidence_hashes["symbols"] = hashlib.sha256(symbol_path.read_bytes()).hexdigest()
            codes = (Code * 4)(*views)
            layout = Layout()
            rc = lib.probe(codes, ctypes.byref(layout))
            assert rc == 0, (name, rc)
            got = {field: getattr(layout, field) for field, _ in Layout._fields_}
            values = json.loads((args.evidence / "profiles" / name / "offsets.json").read_text())["offsets"]
            mapping = {field: "genl_family_" + field for field in got}
            mapping["net_sock"] = "net_genl_sock"
            expected = {field: int(values[key], 0) if isinstance(values[key], str) else values[key]
                        for field, key in mapping.items()}
            assert got == expected, (name, got, expected)
            trace = lib.probe_trace().decode()
            labels = ("lookup genlmsg_put", "genl_family_id=", "genl_family_config=",
                      "lookup genlmsg_multicast_allns", "genl_family_n_mcgrps=",
                      "genl_family_n_mcgrps_size=", "genl_family_mcgrp_offset=",
                      "genl_family_mcgrps=", "lookup genl_pernet_exit", "net_genl_sock=")
            locations = [trace.index(label) for label in labels]
            assert locations == sorted(locations), (name, trace)
            assert all(trace.count(label) == 1 for label in labels), (name, trace)
            debug_cases = ["successful_group_logs_precede_next_lookup"]
            negative = []
            baseline_layout = Layout.from_buffer_copy(layout)
            # 原始 u32 布局从连续字段推导 mcgrps；不依赖注销函数符号或指令。
            original_release_view = Code(codes[2].words, codes[2].count, codes[2].addr)
            codes[2] = Code(None, 0, original_release_view.addr)
            derived_layout = Layout()
            assert lib.probe(codes, ctypes.byref(derived_layout)) == 0
            assert bytes(derived_layout) == bytes(baseline_layout)
            codes[2] = original_release_view
            # 连续布局路径仍必须取得每个直接锚定的字段，缺少时不能猜默认值。
            for index, offsets in ((0, [got["n_mcgrps"], got["mcgrp_offset"]]),
                                   (1, [got["id"], got["config"]]), (3, [got["net_sock"]])):
                width = 8 if index == 3 else 4
                for off in offsets:
                    pos = next(pos for pos, word in enumerate(buffers[index])
                               if word & 0xffc00000 == (0xf9400000 if width == 8 else 0xb9400000)
                               and ((word >> 10) & 0xfff) * width == off)
                    saved = buffers[index][pos]
                    buffers[index][pos] = 0xd503201f
                    sentinel = Layout(*([-123] * 7))
                    assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                    if index == 0:
                        assert sentinel.id == got["id"] and sentinel.config == got["config"]
                    elif index == 3:
                        assert sentinel.id == got["id"] and sentinel.n_mcgrps == got["n_mcgrps"]
                        assert sentinel.mcgrps == got["mcgrps"] and sentinel.net_sock == -1
                    trace = lib.probe_trace().decode()
                    fields = {0: ("genl_family_n_mcgrps=", "genl_family_mcgrp_offset="),
                              1: ("genl_family_id=", "genl_family_config="),
                              3: ("net_genl_sock=",)}
                    assert all(field in trace for field in fields[index]), (name, trace)
                    if index == 1:
                        assert "lookup genlmsg_multicast_allns" not in trace
                    if index == 0:
                        assert "lookup genl_pernet_exit" not in trace
                    debug_cases.append(f"anchor{index}_field_{off:x}:failure_logged_before_later_lookup")
                    negative.append(f"u32_layout:missing_anchor{index}_field_{off:x}")
                    buffers[index][pos] = saved
            # u32 宽度本身不选择连续布局，组号字段不相邻时必须进入旧扫描。
            group_pos = next(pos for pos, word in enumerate(buffers[0])
                             if word & 0xffc003e0 == 0xb9400000
                             and ((word >> 10) & 0xfff) * 4 == got["mcgrp_offset"])
            group_word = buffers[0][group_pos]
            buffers[0][group_pos] += 1 << 10
            nonadjacent_layout = Layout()
            assert lib.probe(codes, ctypes.byref(nonadjacent_layout)) == 0
            assert nonadjacent_layout.mcgrps == baseline_layout.mcgrps
            assert nonadjacent_layout.mcgrp_offset == baseline_layout.mcgrp_offset + 4
            codes[2] = Code(None, 0, original_release_view.addr)
            sentinel = Layout(*([-123] * 7))
            assert lib.probe(codes, ctypes.byref(sentinel)) < 0
            negative.append("nonadjacent_u32_requires_unregister_anchor")
            codes[2] = original_release_view
            buffers[0][group_pos] = group_word
            baseline_negative = list(negative)
            # 以下旧注销扫描用例改用合成 u8 计数，确实进入生产 fallback 路径。
            count_pos = next(pos for pos, word in enumerate(buffers[0])
                             if word & 0xffc003e0 == 0xb9400000
                             and ((word >> 10) & 0xfff) * 4 == got["n_mcgrps"])
            count_word = buffers[0][count_pos]
            buffers[0][count_pos] = 0x39400000 | (got["n_mcgrps"] << 10) | (count_word & 0x3ff)
            layout = Layout()
            assert lib.probe(codes, ctypes.byref(layout)) == 0
            assert layout.n_mcgrps_size == 1
            assert all(getattr(layout, field) == value for field, value in got.items() if field != "n_mcgrps_size")
            for index in range(4):
                original = codes[index].count
                original_words = list(buffers[index])
                # 只保留第一条指令，其余窗口为 NOP；不传递或依赖符号长度。
                for pos in range(1, original):
                    buffers[index][pos] = 0xd503201f
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                negative.append(f"anchor{index}:truncated_to_one_instruction")
                for pos, word in enumerate(original_words):
                    buffers[index][pos] = word
                for pos in range(original):
                    buffers[index][pos] = 0xd503201f  # NOP：范围合法，但缺少字段或调用证据。
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                negative.append(f"anchor{index}:missing_instruction_evidence")
                for pos, word in enumerate(original_words):
                    buffers[index][pos] = word
            # 首次所需字段读取缺失时，实际后续指令不能使推导误成功。
            first_positions = []
            for index, offsets in ((0, [got["n_mcgrps"], got["mcgrp_offset"]]),
                                   (1, [got["id"], got["config"]]),
                                   (2, [got["mcgrps"]]), (3, [got["net_sock"]])):
                for off in offsets:
                    width = 1 if index == 0 and off == got["n_mcgrps"] else 8 if index in (2, 3) else 4
                    opcode = 0x39400000 if width == 1 else 0xf9400000 if width == 8 else 0xb9400000
                    pos = next(pos for pos, word in enumerate(buffers[index])
                               if word & 0xffc00000 == opcode and ((word >> 10) & 0xfff) * width == off)
                    original_word = buffers[index][pos]
                    buffers[index][pos] = 0xd503201f
                    sentinel = Layout(*([-123] * 7))
                    assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                    negative.append(f"anchor{index}:first_field_read_missing_{off:x}")
                    if index == 2:
                        trace = lib.probe_trace().decode()
                        assert "genl_family_mcgrps=0xffffffff" in trace
                        assert "lookup genl_pernet_exit" not in trace
                        debug_cases.append("fallback_pointer_failure_logged_before_socket_lookup")
                    first_positions.append({"anchor": index, "offset": off, "instruction": pos})
                    buffers[index][pos] = original_word

            # 首次指针读取缺失，窗口之外的同类访存不应被扫描。
            pos = next(item["instruction"] for item in first_positions if item["anchor"] == 2)
            original_word = buffers[2][pos]
            decoy = (original_word & ~(0xfff << 10)) | (((got["mcgrps"] - 16) // 8) << 10)
            extended_words = [*buffers[2], decoy]
            extended_words[pos] = 0xd503201f
            extended_buffer = (ctypes.c_uint32 * len(extended_words))(*extended_words)
            original_release = Code(codes[2].words, codes[2].count, codes[2].addr)
            codes[2] = Code(extended_buffer, len(extended_words), original_release.addr)
            sentinel = Layout(*([-123] * 7))
            assert lib.probe(codes, ctypes.byref(sentinel)) < 0
            negative.append("unrelated_pointer_beyond_fixed_window")
            codes[2] = original_release

            # 原 DEV-010 的索引 91 诱饵，以及新窗口内的同类读取，都必须拒绝。
            for late_pos in (0x30, 0x3c, 0x54, 91):
                words = [*buffers[2], *([0xd503201f] * 7)]
                words[pos] = 0xd503201f
                words[late_pos] = decoy
                decoy_buffer = (ctypes.c_uint32 * len(words))(*words)
                codes[2] = Code(decoy_buffer, len(words), original_release.addr)
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                negative.append(f"missing_first_pointer_with_decoy_at_{late_pos}")
            codes[2] = original_release

            # 实际指针读取之前插入同结果寄存器的另一字段，不能把被覆盖的旧读取当来源。
            saved_before = buffers[2][pos - 1]
            buffers[2][pos - 1] = decoy
            preceding_layout = Layout()
            assert lib.probe(codes, ctypes.byref(preceding_layout)) == 0
            assert bytes(preceding_layout) == bytes(layout)
            buffers[2][pos - 1] = saved_before

            # 新规则按局部用途识别指针，不再用注销函数的组号读取作交叉核对。
            # 用实际相邻指令变异验证寄存器关联、事件参数、扩展类型和步长。
            add_pos = next(i for i in range(pos + 1, min(pos + 5, 0x55))
                           if buffers[2][i] & 0xffe0fc1f == 0x8b20d002
                           and ((buffers[2][i] >> 5) & 31) == (buffers[2][pos] & 31))
            event_pos = next(i for i in range(max(0x30, pos - 2), add_pos)
                             if buffers[2][i] == 0x321d03e0
                             or buffers[2][i] & 0xffe0001f == 0x52800000
                             and (buffers[2][i] >> 5) & 0xffff == 8)
            mutations = [(add_pos, buffers[2][add_pos] ^ (1 << 5), "add_source_mismatch"),
                         (add_pos, buffers[2][add_pos] ^ 1, "add_destination_mismatch"),
                         (add_pos, buffers[2][add_pos] ^ (1 << 31), "add_width_mismatch"),
                         (add_pos, buffers[2][add_pos] ^ (1 << 13), "add_extension_mismatch"),
                         (add_pos, buffers[2][add_pos] ^ (1 << 10), "add_stride_mismatch"),
                         (event_pos, 0x528000e0, "event_value_mismatch"),
                         (event_pos, 0xd503201f, "event_missing"),
                         (event_pos, 0x52800100 | 1, "event_destination_mismatch")]
            for where, replacement, label in mutations:
                saved = buffers[2][where]
                buffers[2][where] = replacement
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0, (name, label)
                negative.append(label)
                buffers[2][where] = saved

            # 合成完整模式放在窗口边界；从窗口外借用标记或 ADD 也必须拒绝。
            for start, event_index, add_index, label in (
                    (0x2f, 0x30, 0x31, "pointer_before_window"),
                    (0x55, 0x56, 0x57, "pointer_after_window"),
                    (0x54, 0x52, 0x55, "add_after_window"),
                    (0x30, 0x2f, 0x31, "event_before_window"),
                    (0x30, 0x31, 0x35, "add_beyond_neighbor_window")):
                words = [0xd503201f] * 0x60
                words[start] = buffers[2][pos]
                words[event_index] = 0x52800100
                words[add_index] = buffers[2][add_pos]
                edge_buffer = (ctypes.c_uint32 * len(words))(*words)
                codes[2] = Code(edge_buffer, len(words), original_release.addr)
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0, (name, label)
                negative.append(label)
            codes[2] = original_release

            # 调用/返回切断局部模式；不能借用调用前的事件常量。
            for branch, label in ((0x94000000, "bl"), (0xd63f0100, "blr"), (0xd65f03c0, "ret")):
                for where in (0x31, 0x33):
                    words = [0xd503201f] * 0x55
                    words[0x30] = 0x52800100
                    words[0x32] = buffers[2][pos]
                    words[0x34] = buffers[2][add_pos]
                    words[where] = branch
                    barrier_buffer = (ctypes.c_uint32 * len(words))(*words)
                    codes[2] = Code(barrier_buffer, len(words), original_release.addr)
                    sentinel = Layout(*([-123] * 7))
                    assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                    negative.append(f"event_or_address_across_{label}_{where}")
            codes[2] = original_release
            # 相邻 MOV/读取覆盖指针结果，也不能延用之前的候选。
            rt = buffers[2][pos] & 31
            for replacement, label in ((0xaa0103e0 | rt, "mov_reg"),
                                       (0xd2800020 | rt, "movz"),
                                       (0xb21d03e0 | rt, "orr")):
                words = [0xd503201f] * 0x55
                words[0x30] = 0x52800100
                words[0x32] = buffers[2][pos]
                words[0x33] = replacement
                words[0x34] = buffers[2][add_pos]
                overwrite_buffer = (ctypes.c_uint32 * len(words))(*words)
                codes[2] = Code(overwrite_buffer, len(words), original_release.addr)
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0, (name, label)
                negative.append("pointer_overwritten_by_" + label)
            codes[2] = original_release
            pattern = {"load": pos, "add": add_pos, "event": event_pos}
            # 合成等价局部形态，验证任意 x0～x30 基址，以及多种加载结果寄存器。
            register_cases = 0
            for base, result in [*((base, 9) for base in range(31)), *((19, result) for result in (2, 8, 16, 20, 30))]:
                words = [0xd503201f] * 0x55
                words[0x30] = (buffers[2][pos] & ~0x3ff) | (base << 5) | result
                words[0x31] = 0x52800100
                words[0x32] = (buffers[2][add_pos] & ~(31 << 5)) | (result << 5)
                register_buffer = (ctypes.c_uint32 * len(words))(*words)
                codes[2] = Code(register_buffer, len(words), original_release.addr)
                register_layout = Layout()
                assert lib.probe(codes, ctypes.byref(register_layout)) == 0, (name, base, result)
                assert bytes(register_layout) == bytes(layout)
                register_cases += 1
            codes[2] = original_release

            # 从直接读取之前离开函数，不能把后续机器码当成入口字段。
            for word, label in ((0xd65f03c0, "return"), (0x94000000, "call")):
                original_word = buffers[3][0]
                buffers[3][0] = word
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                negative.append("socket_" + label + "_before_load")
                buffers[3][0] = original_word

            # genlmsg_put 的额外读取不应影响两个所需头部字段的匹配。
            extra = 0xb9400000 | (0xff << 10) | (3 << 5) | 8  # ldr w8, [x3, #0x3fc]
            words = [extra, *buffers[1]]
            extra_buffer = (ctypes.c_uint32 * len(words))(*words)
            original_put = Code(codes[1].words, codes[1].count, codes[1].addr)
            codes[1] = Code(extra_buffer, len(words), original_put.addr)
            extra_layout = Layout()
            assert lib.probe(codes, ctypes.byref(extra_layout)) == 0
            assert bytes(extra_layout) == bytes(layout)
            positive = ["u32_layout_without_unregister_symbol", "nonadjacent_u32_with_pointer_scan",
                        "synthetic_u8_group_count",
                        "genlmsg_put_extra_field_read", "synthetic_any_xn_mcgrps_pattern",
                        "preceding_pointer_load_overwritten"]
            # 多了无关字段也不能弥补必需字段缺失。
            required = [got["id"], got["config"]]
            for missing in range(2):
                partial = [0xb9400000 | ((off // 4) << 10) | (3 << 5)
                           for i, off in enumerate(required) if i != missing]
                partial.append(extra)
                partial.extend([0xd503201f] * (0x14 - len(partial)))
                partial_buffer = (ctypes.c_uint32 * len(partial))(*partial)
                codes[1] = Code(partial_buffer, len(partial), original_put.addr)
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0
                negative.append(f"genlmsg_put:missing_required_header_field{missing}")
            codes[1] = original_put
            # 只提供 id/hdrsize 即可取得配置段，version 不再是独立查找条件。
            header_words = [0xb9400000 | ((off // 4) << 10) | (3 << 5) | (8 + index)
                            for index, off in enumerate(required)]
            header_words.extend([0xd503201f] * (0x14 - len(header_words)))
            header_buffer = (ctypes.c_uint32 * len(header_words))(*header_words)
            codes[1] = Code(header_buffer, len(header_words), original_put.addr)
            header_layout = Layout()
            assert lib.probe(codes, ctypes.byref(header_layout)) == 0
            assert bytes(header_layout) == bytes(layout)
            positive.append("header_pair_without_version_read")
            codes[1] = original_put
            # 同一保存寄存器上的两次读取也有效，不需要跨调用的根寄存器传播。
            saved_words = [0xaa0303f3,  # mov x19, x3
                           (header_words[0] & ~(31 << 5)) | (19 << 5),
                           (header_words[1] & ~(31 << 5)) | (19 << 5)]
            saved_words.extend([0xd503201f] * (0x14 - len(saved_words)))
            saved_buffer = (ctypes.c_uint32 * len(saved_words))(*saved_words)
            codes[1] = Code(saved_buffer, len(saved_words), original_put.addr)
            saved_layout = Layout()
            assert lib.probe(codes, ctypes.byref(saved_layout)) == 0
            assert bytes(saved_layout) == bytes(layout)
            positive.append("header_pair_on_saved_family_register")
            codes[1] = original_put
            header_mutations = []
            for branch, label in ((0x94000000, "bl"), (0xd63f0100, "blr"), (0xd65f03c0, "ret")):
                header_mutations.append(([branch, *header_words], "header_pair_after_" + label))
            header_mutations.append(([header_words[0], *([0xd503201f] * 19), header_words[1]],
                                     "hdrsize_outside_prefix"))
            words = list(header_words)
            words[1] += 1 << 10
            header_mutations.append((words, "nonadjacent_header_pair"))
            words = [word if word == 0xd503201f else (word & ~(31 << 5)) for word in header_words]
            header_mutations.append((words, "header_pair_from_other_object"))
            words = list(saved_words)
            words[0] = 0xd503201f
            header_mutations.append((words, "saved_family_copy_missing"))
            for words, label in header_mutations:
                mutation_buffer = (ctypes.c_uint32 * len(words))(*words)
                codes[1] = Code(mutation_buffer, len(words), original_put.addr)
                sentinel = Layout(*([-123] * 7))
                assert lib.probe(codes, ctypes.byref(sentinel)) < 0, (name, label)
                negative.append(label)
            codes[1] = original_put
            # 恢复真实 u32 指令，再核对连续布局路径与原参考输出。
            buffers[0][count_pos] = count_word
            restored_layout = Layout()
            assert lib.probe(codes, ctypes.byref(restored_layout)) == 0
            assert bytes(restored_layout) == bytes(baseline_layout)
            positive.append("restored_u32_adjacent_layout")
            results.append({"image": name, "offsets": got, "positive_cases": positive,
                            "negative_cases": negative, "baseline_u32_negative_cases": baseline_negative,
                            "remaining_negative_scope": "synthetic u8 count exercises production pointer-scan fallback",
                            "evidence_sha256": evidence_hashes,
                            "first_read_positions": first_positions,
                            "mcgrps_pattern": pattern, "synthetic_register_cases": register_cases,
                            "debug_cases": debug_cases})
            print(name, "7 fields match;", len(negative), "negative cases passed")
    output = {"scope": "Developer offline selfcheck; no device conclusion", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "kpm_utils_sha256": hashlib.sha256((root / "kpm_utils.h").read_bytes()).hexdigest(),
              "re_utils_sha256": hashlib.sha256((module / "re_utils.h").read_bytes()).hexdigest(), "results": results}
    with args.output.open("x") as stream:
        json.dump(output, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
