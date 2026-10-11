#!/usr/bin/env python3
"""Developer 自检：实际双模式 KPM、JSON/blob 替换边界与静态 SID 初始化。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builds', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('patcher', root / 'patch_offsets.py')
    patcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patcher)
    artifacts = []
    kpms = sorted(args.builds.glob('*.kpm'))
    assert len(kpms) == 4
    for path in kpms:
        data = path.read_bytes()
        static = '_baselines' in path.name
        assert b'name=run_cmd_demo\0' in data
        assert b'offset_mode=' + (b'static' if static else b'dynamic') + b'\0' in data
        assert (b'bpf_get_btf_vmlinux\0' in data) == (not static)
        assert (b'btf_find_by_name_kind\0' in data) == (not static)
        sidecar = Path(str(path) + '.json')
        assert sidecar.exists() == static
        item = {'file': path.name, 'sha256': sha(data), 'mode': 'static' if static else 'dynamic'}
        if static:
            layout = json.loads(sidecar.read_text())
            assert layout['schema'] == 3 and 'binder_abi' not in layout
            offset, size, abi = patcher.sections(data)
            assert size == 8 and abi is None and layout['sha256'] == sha(data)
            assert layout['fields'] == patcher.source_fields(root / 'run_cmd_demo/rc_offsets.c')
            assert list(layout['offsets'].values()) == [-1] * 4
            values = dict(subprocess_info_path_offset='0x38', cred_security_offset='0x78',
                          cred_sid_offset=4, legacy_worker_size=-1)
            profile = args.output / (path.stem + '.offsets.json')
            profile.write_text(json.dumps({'offsets': values}) + '\n')
            patched = args.output / path.name
            patcher.run(argparse.Namespace(command='patch', kpm=path, layout=None, offsets=profile,
                                          blob=None, output=patched))
            updated = patched.read_bytes()
            assert updated[:offset] == data[:offset] and updated[offset + size:] == data[offset + size:]
            assert updated[offset:offset + size] == patcher.encode_offsets(profile, layout['fields'])
            updated_layout = json.loads(Path(str(patched) + '.json').read_text())
            assert updated_layout['schema'] == 3 and 'binder_abi' not in updated_layout
            assert updated_layout['sha256'] == sha(updated)
            blob = args.output / (path.stem + '.bin')
            patcher.run(argparse.Namespace(command='dump', kpm=patched, layout=None, output=blob))
            roundtrip = args.output / (path.stem + '-roundtrip.kpm')
            patcher.run(argparse.Namespace(command='patch', kpm=path, layout=None, offsets=None,
                                          blob=blob, output=roundtrip))
            assert roundtrip.read_bytes() == updated
            item['layout_sha256'] = sha(sidecar.read_bytes())
            item['patched_sha256'] = sha(updated)
        artifacts.append(item)

    # 只编译静态生产初始化。实际加载仍依赖内核线程和 SELinux 环境。
    offsets = (root / 'run_cmd_demo/rc_offsets.c').read_text()
    offsets = offsets.replace('__attribute__((section(".data.re_offsets"), used))', '')
    source = args.output / 'static-init.c'
    source.write_text('''#include <assert.h>
#include <stdint.h>
#include <errno.h>
#define CONFIG_KPM_BASELINES
static void* creator;
static int* runtime_blob_ptr;
#define kfunc(name) creator
#define kvar(name) runtime_blob_ptr
#define kvar_val(name) (*runtime_blob_ptr)
''' + offsets + '''
int main(void) {
  creator = (void*)1;
  assert(calculate_offsets() == -EINVAL);  // 未移植模板不能加载。
  subprocess_info_path_offset = 0x38;
  cred_security_offset = 0x78;
  cred_sid_offset = 4;
  assert(calculate_offsets() == 0 && cred_sid_offset == 4);
  int runtime_blob = 16;
  runtime_blob_ptr = &runtime_blob;
  assert(calculate_offsets() == 0 && cred_sid_offset == 20);
  cred_sid_offset = 4;
  runtime_blob = 32;
  assert(calculate_offsets() == 0 && cred_sid_offset == 36);
  creator = 0;
  runtime_blob_ptr = 0;
  cred_sid_offset = 4;
  assert(calculate_offsets() == -EINVAL);  // 旧 worker 尚未填写大小。
  subprocess_info_path_offset = 0x28;
  legacy_worker_size = 40;
  assert(calculate_offsets() == 0 && cred_sid_offset == 4);
  return 0;
}
''')
    binary = args.output / 'static-init'
    subprocess.run(['clang', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    (args.output / 'receipt.json').write_text(json.dumps({
        'scope': 'Developer artifact/host selfcheck; not device or native SELinux proof',
        'artifacts': artifacts, 'static_sid_runtime_adjustment': 'passed',
        'source_hashes': {str(p.relative_to(root)): sha(p.read_bytes()) for p in
                          [root / 'run_cmd_demo/run_cmd.c', root / 'run_cmd_demo/rc_offsets.c',
                           root / 'patch_offsets.py', Path(__file__)]}}, indent=2) + '\n')
    print('four KPM modes, schema 3 JSON/blob byte boundaries, static SID init: PASS')


if __name__ == '__main__':
    main()
