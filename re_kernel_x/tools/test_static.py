#!/usr/bin/env python3
"""实现方自检：真实基准 KPM 的补丁边界，以及生产消息函数的主机测试。"""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import struct
import tempfile


def call(*args, ok=True):
    result = subprocess.run(args, capture_output=True, text=True)
    assert (result.returncode == 0) == ok, result.stdout + result.stderr
    return result.stdout


def undefined_imports(data):
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    entries = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * header[11])
               for i in range(header[12])]
    imports = set()
    for section in entries:
        if section[1] != 2:
            continue
        assert section[9] == 24 and section[5] % 24 == 0 and section[6] < len(entries)
        strings = entries[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, index, _, _ = struct.unpack_from("<IBBHQQ", data, offset)
            if index or not name or info >> 4 not in (1, 2):
                continue
            end = names.find(b"\0", name)
            assert 0 <= name < end
            imports.add(names[name:end].decode("ascii"))
    return imports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baselines", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    module = Path(__file__).resolve().parents[1]
    tool = module / "tools/patch_offsets.py"
    spec = importlib.util.spec_from_file_location("patch_offsets", tool)
    patcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patcher)
    kpms = sorted(args.baselines.glob("*.kpm"))
    assert len(kpms) == 8, "expected four ABI baselines, release + debug"
    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        for index, kpm in enumerate(kpms):
            layout = json.loads(Path(str(kpm) + ".json").read_text())
            data = kpm.read_bytes()
            offset, size, abi = patcher.sections(data)
            imports = undefined_imports(data)
            assert {"kallsyms_lookup_name", "kallsyms_lookup_name_by_suffix"} <= imports
            assert not imports & {"kf_get_task_ext", "get_task_ext"}, imports
            assert not imports & {"memcpy", "memset", "memcmp", "strlen", "strcmp", "strnlen"}, imports
            assert size == len(layout["fields"]) * 2 and abi == layout["binder_abi"]
            values = {field: hex(0x100 + i * 8) for i, field in enumerate(layout["fields"])}
            values["genl_family_n_mcgrps_size"] = "0x1"
            if "work_offq_pool_shift" in values:
                values["work_offq_pool_shift"] = "0x5"
                values["work_cpu_unbound"] = "0x40"
            profile = scratch / f"values-{index}.json"
            profile.write_text(json.dumps(values))
            output = scratch / f"patched-{index}.kpm"
            call("python3", str(tool), "patch", str(kpm), "--offsets", str(profile), "--output", str(output))
            patched = output.read_bytes()
            assert patched[:offset] == data[:offset] and patched[offset + size:] == data[offset + size:]
            assert patched[offset:offset + size] == patcher.encode_offsets(profile, layout["fields"])
            blob = scratch / f"values-{index}.bin"
            call("python3", str(tool), "dump", str(output), "--output", str(blob))
            raw_output = scratch / f"raw-{index}.kpm"
            call("python3", str(tool), "patch", str(kpm), "--blob", str(blob), "--output", str(raw_output))
            assert raw_output.read_bytes() == patched
            call("python3", str(tool), "patch", str(kpm), "--blob", str(blob), "--output", str(output), ok=False)

        kpm = kpms[0]
        offset, size, abi = patcher.sections(kpm.read_bytes())
        layout = json.loads(Path(str(kpm) + ".json").read_text())
        invalid = scratch / "invalid.json"
        invalid.write_text(json.dumps({layout["fields"][0]: 32768}))
        destination = scratch / "must-not-exist.kpm"
        call("python3", str(tool), "patch", str(kpm), "--offsets", str(invalid), "--output", str(destination), ok=False)
        for bad in (32768, True, "invalid"):
            invalid.write_text(json.dumps(dict(values, binder_alloc_buffer_size=bad)))
            call("python3", str(tool), "patch", str(kpm), "--offsets", str(invalid), "--output", str(destination), ok=False)
        invalid.write_text(json.dumps(dict(values, genl_family_n_mcgrps_size=3)))
        call("python3", str(tool), "patch", str(kpm), "--offsets", str(invalid), "--output", str(destination), ok=False)
        for field, value in (("work_offq_pool_shift", -1), ("work_offq_pool_shift", 64),
                             ("work_cpu_unbound", 0), ("work_cpu_unbound", -1)):
            if field not in layout["fields"]:
                continue
            invalid.write_text(json.dumps(dict(values, **{field: value})))
            call("python3", str(tool), "patch", str(kpm), "--offsets", str(invalid), "--output", str(destination), ok=False)
        original_blob = kpm.read_bytes()[offset:offset + size]
        for field, value in (("work_offq_pool_shift", 64), ("work_cpu_unbound", 0)):
            if field not in layout["fields"]:
                continue
            malformed = bytearray(original_blob)
            struct.pack_into("<h", malformed, layout["fields"].index(field) * 2, value)
            blob.write_bytes(malformed)
            call("python3", str(tool), "patch", str(kpm), "--blob", str(blob), "--output", str(destination), ok=False)
        blob.write_bytes(b"\0" * (size - 1))
        call("python3", str(tool), "patch", str(kpm), "--blob", str(blob), "--output", str(destination), ok=False)
        wrong_layout = scratch / "wrong.json"
        wrong_layout.write_text(Path(str(kpms[-1]) + ".json").read_text())
        call("python3", str(tool), "patch", str(kpm), "--layout", str(wrong_layout), "--blob", str(blob),
             "--output", str(destination), ok=False)
        broken = scratch / "broken.kpm"
        broken.write_bytes(kpm.read_bytes()[:64])
        call("python3", str(tool), "baseline", str(broken), "--output", str(wrong_layout), ok=False)
        assert not destination.exists()
        print("eight real KPMs: JSON/blob roundtrip, only table bytes change, invalid inputs refused: PASS")
        print("actual ELF imports: SDK plain/suffix lookup, no task_ext dependency: PASS")

        header = (module / "re_kernel.h").read_text().replace("#include <ktypes.h>", "")
        header = header.replace('#include "re_structs.h"', "")
        (scratch / "re_kernel_host.h").write_text(header)
        source = (module / "re_kernel.c").read_text()
        functions = []
        for name in ("static struct binder_transaction_data* binder_current_transaction(",
                     "static void rekernel_report(", "static void binder_transaction_before(",
                     "static void binder_transaction_after("):
            start = source.index(name)
            end = source.index("\n}\n", start) + 3
            functions.append(source[start:end])
        harness = (module / "tools/tests/protocol.c").read_text()
        harness = harness.replace("/* PRODUCTION_FUNCTIONS */", "\n".join(functions))
        host_source = scratch / "protocol-test.c"
        host_source.write_text(harness)
        binary = scratch / "protocol-test"
        call(args.cc, "-g", "-O1", "-pthread", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(host_source),
             "-o", str(binary))
        print(call(str(binary)).strip())

        utils = (module / "re_utils.h").read_text()
        offsets = (module / "re_offsets.c").read_text()
        genl_functions = []
        for text, names in (
            (offsets, ("genl_family_id", "genl_family_config", "genl_family_n_mcgrps", "genl_family_mcgrp_offset",
                       "net_genl_sock", "sock_net", "sk_buff_len", "sk_buff_tail", "sk_buff_head", "sk_buff_data")),
            (utils, ("skb_tail_pointer", "nlmsg_data", "nla_data", "nla_len", "nla_total_size", "nla_put_s32",
                     "nla_put_string", "nla_nest_start", "nla_nest_end", "nlmsg_end", "nlmsg_trim", "nlmsg_cancel",
                     "nlmsg_msg_size", "nlmsg_total_size", "genlmsg_msg_size", "genlmsg_total_size", "genlmsg_new",
                     "genlmsg_end", "genlmsg_cancel", "nlmsg_multicast", "genlmsg_multicast_netns", "genlmsg_multicast",
                     "genl_register_family", "genl_unregister_family")),
            (source, ("free_async_update", "free_async_lookup", "free_async_has_rules",
                      "net_uid_monitored", "net_uid_update", "rekernel_genl_rcv_msg", "genl_rcv_msg_before",
                      "start_rekernel_genl_server", "stop_rekernel_genl_server", "send_netlink_message")),
        ):
            import re
            for name in names:
                pattern = re.compile(r"^static (?:inline )?[^\n]*?\b" + name + r"\(", re.M)
                start = pattern.search(text).start()
                brace = text.index("{", start)
                depth, end = 1, brace + 1
                while depth:
                    depth += (text[end] == "{") - (text[end] == "}")
                    end += 1
                genl_functions.append(text[start:end])
        fixture = (module / "tools/tests/genl.c").read_text().replace("/* PRODUCTION_FUNCTIONS */",
                                                                           "\n".join(genl_functions))
        structs = (module / "re_structs.h").read_text()
        start = structs.index("// include/net/scm.h")
        end = structs.index("// uapi/linux/tcp.h", start)
        fixture = fixture.replace("/* PRODUCTION_NETLINK_TYPES */", structs[start:end])
        genl_source = scratch / "genl-test.c"
        genl_source.write_text(fixture)
        genl_binary = scratch / "genl-test"
        call(args.cc, "-g", "-O1", "-pthread", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             str(genl_source), "-o", str(genl_binary))
        print(call(str(genl_binary)).strip())

        cleanup_functions = []
        for text, names in (
            (offsets, ("binder_transaction_buffer", "binder_transaction_to_proc", "binder_transaction_code",
                       "binder_transaction_flags", "binder_node_ptr", "binder_node_cookie", "binder_proc_is_frozen",
                       "binder_proc_is_dead", "binder_proc_outstanding_txns")),
            (source, ("binder_buffer_read", "binder_buffer_data_equal", "binder_can_update_transaction", "binder_find_outdated_transaction_ilocked",
                      "outstanding_txns_dec", "binder_release_entire_buffer", "binder_stats_deleted",
                      "binder_is_frozen", "free_async_update", "free_async_lookup", "free_async_has_rules",
                      "binder_free_async_strategy", "binder_proc_transaction_before")),
        ):
            for name in names:
                pattern = re.compile(r"^static (?:inline )?[^\n]*?\b" + name + r"\(", re.M)
                start = pattern.search(text).start()
                brace = text.index("{", start)
                depth, end = 1, brace + 1
                while depth:
                    depth += (text[end] == "{") - (text[end] == "}")
                    end += 1
                cleanup_functions.append(text[start:end])
        fixture = (module / "tools/tests/cleanup.c").read_text().replace("/* PRODUCTION_FUNCTIONS */",
                                                                       "\n".join(cleanup_functions))
        for abi in (3, 4, 5, 6):
            cleanup_source = scratch / f"cleanup-test-{abi}.c"
            cleanup_source.write_text(fixture.replace("#define REKERNEL_BINDER_ABI 6", f"#define REKERNEL_BINDER_ABI {abi}"))
            cleanup_binary = scratch / f"cleanup-test-{abi}"
            call(args.cc, "-g", "-O1", "-pthread", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 str(cleanup_source), "-o", str(cleanup_binary))
            print(call(str(cleanup_binary)).strip())


if __name__ == "__main__":
    main()
