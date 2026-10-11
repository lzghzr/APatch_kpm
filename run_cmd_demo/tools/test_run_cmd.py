#!/usr/bin/env python3
"""Developer 自检：生产 UMH 控制逻辑、固定窗口偏移及选定镜像入口。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='新的空输出目录')
    parser.add_argument('--image', type=Path)
    parser.add_argument('--symbols', type=Path)
    parser.add_argument('--expect-path', type=lambda s: int(s, 0))
    parser.add_argument('--expect-sid', type=lambda s: int(s, 0))
    parser.add_argument('--expect-security', type=lambda s: int(s, 0))
    parser.add_argument('--expect-blob', type=lambda s: int(s, 0))
    args = parser.parse_args()
    if any(x is not None for x in (args.expect_sid, args.expect_security, args.expect_blob)) and (
            not args.image or not all(x is not None for x in (args.expect_sid, args.expect_security, args.expect_blob))):
        parser.error('SID 入口验证需要镜像及 --expect-sid、--expect-security、--expect-blob')
    if any(x is not None for x in (args.image, args.symbols, args.expect_path)) and not all(
            x is not None for x in (args.image, args.symbols, args.expect_path)):
        parser.error('镜像核对同时需要 --image、--symbols、--expect-path；参考值需另行取得')
    args.output.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1]
    root = module.parent
    code = (module / 'run_cmd.c').read_text()
    code = code.replace('#include "rc_offsets.c"', (module / 'rc_offsets.c').read_text())
    code = '#define KPM_INFO(...)\n' + re.sub(r'^#include .*\n', '', code, flags=re.M)
    # 宿主使用 Mach-O，不携带 KPM 的 ELF 数据段属性。
    code = code.replace('__attribute__((section(".data.re_offsets"), used))', '')
    # 仅在主机 init 夹具替换准备阶段，生产 prepare 的算法另行用实际指令验证。
    code = code.replace('static long run_cmd_init(', '#define prepare_run_cmd fake_prepare_run_cmd\nstatic long run_cmd_init(')
    code = code.replace('static long run_cmd_control0(', '#undef prepare_run_cmd\nstatic long run_cmd_control0(')
    utilities = 'typedef uint8_t u8;\ntypedef uint64_t u64;\n' + (root / 'kpm_utils.h').read_text().split('// BTF\n', 1)[1].rsplit('#endif', 1)[0]
    fixture = (module / 'tools/test_run_cmd.c').read_text().replace(
        '/* PRODUCTION_FUNCTIONS */', re.sub(r'^#include .*\n', '', (module / 'run_cmd.h').read_text(), flags=re.M) + '\n' + utilities + '\n' + code)
    evidence = {}
    if args.image:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        symbols = {name: int(addr, 16) for addr, name in re.findall(
            r'^([0-9a-fA-F]+) [a-zA-Z] (\S+)$', args.symbols.read_text(), re.M)}
        data = args.image.read_bytes()
        base = symbols.get('_text', 0)
        required = ('call_usermodehelper_exec', 'call_usermodehelper_setup', 'security_transfer_creds', 'prepare_kernel_cred', 'abort_creds', 'kthread_create_worker', 'kthread_queue_work', 'filp_open', 'replace_fd', 'filp_close', 'override_creds', 'revert_creds', 'security_secctx_to_secid', 'selinux_cred_getsecid')
        for name in required:
            offset = symbols[name] - base
            raw = data[offset:offset + (32 if name == required[0] else 64) * 4]
            assert len(raw) == (32 if name == required[0] else 64) * 4
            asm = '\n'.join(f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in
                            Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN).disasm(raw, symbols[name]))
            (args.output / (name + '.asm')).write_text(asm + '\n')
            evidence[name] = {'address': symbols[name], 'entry_sha256': hashlib.sha256(raw).hexdigest()}
            if name == required[0]:
                words = [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]
                declarations = 'static const uint32_t image_entry[] = {' + ','.join(hex(w) for w in words) + '};\n'
                fixture = fixture.replace('/* PRODUCTION_FUNCTIONS */', '')
                fixture = fixture.replace('int main(void) {', declarations + '\nint main(void) {')
                fixture = fixture.replace('  puts("run_cmd production',
                    '  memcpy(entry, image_entry, sizeof(image_entry));\n'
                    '  subprocess_info_path_offset = -1;\n'
                    '  kfunc(call_usermodehelper_exec) = (typeof(kfunc(call_usermodehelper_exec)))entry;\n'
                    f'  assert(calculate_offsets() == 0 && subprocess_info_path_offset == {args.expect_path});\n'
                    '  puts("run_cmd production')
        if args.expect_sid is not None:
            # 整页对齐的连续镜像副本保留原 ADRP 相对位置；blob 值采用启动后的参考值。
            getter = symbols['selinux_cred_getsecid'] - base
            blob = symbols['selinux_blob_sizes'] - base
            raw = data[getter:getter + 0x10 * 4]
            declaration = 'static const uint32_t sid_image_entry[] = {' + ','.join(
                hex(int.from_bytes(raw[i:i+4], 'little')) for i in range(0, len(raw), 4)) + '};\n'
            fixture = fixture.replace('int main(void) {', declaration + '\nint main(void) {')
            verification = f'''  void* image_map;
  assert(posix_memalign(&image_map, 0x1000, {max(getter + len(raw), blob + 4) + 0x1000}) == 0);
  memcpy((char*)image_map + {getter}, sid_image_entry, sizeof(sid_image_entry));
  kvar(selinux_blob_sizes) = (int*)((char*)image_map + {blob});
  *kvar(selinux_blob_sizes) = {args.expect_blob};
  kfunc(selinux_cred_getsecid) = (typeof(kfunc(selinux_cred_getsecid)))((char*)image_map + {getter});
  cred_offset.security_offset = {args.expect_security};
  cred_sid_offset = -1;
  assert(calculate_offsets() == 0 && cred_sid_offset == {args.expect_sid});
  cred_offset.security_offset = -1;
  cred_security_offset = cred_sid_offset = -1;
  assert(calculate_offsets() == 0 && cred_sid_offset == {args.expect_sid});
  assert(cred_security_offset == {args.expect_security} && cred_offset.security_offset == -1);
  free(image_map);
'''
            fixture = fixture.replace('  puts("run_cmd production', verification + '  puts("run_cmd production')
            evidence.update(expected_sid=args.expect_sid, expected_security=args.expect_security,
                            expected_runtime_blob=args.expect_blob,
                            sid_pc_mapping='page-aligned image-relative placement, unchanged getter words')
        evidence.update(image_sha256=sha(args.image), symbols_sha256=sha(args.symbols), expected_path=args.expect_path)
    source = args.output / 'test.c'
    source.write_text(fixture)
    binary = args.output / 'test'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(source), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], check=True, text=True, capture_output=True)
    print(result.stdout, end='')
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer host selfcheck; not SELinux, CFI or device proof',
        'stdout': result.stdout, 'evidence': evidence,
        'sources': {str(p.relative_to(root)): sha(p) for p in
                    (module / 'run_cmd.c', module / 'run_cmd.h', module / 'rc_offsets.c', module / 'rc_utils.h', root / 'kpm_utils.h',
                     module / 'tools/test_run_cmd.c', Path(__file__))}}, indent=2) + '\n')


if __name__ == '__main__':
    main()
