#!/usr/bin/env python3
"""DEV-106: execute production CLI against strict DEL state derived from emitted ADD paths."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import test_nomount_module_cli as oracle

DELETE = r'''
static int fixture_delete(struct nm_payload *p) {
    const char *path = getenv("DEL_STATE");
    FILE *f = fopen(path, "rb"); if (!f) abort();
    if (fseek(f, 0, SEEK_END)) abort();
    long length = ftell(f); if (length < 0) abort(); rewind(f);
    char *state = malloc((size_t)length + 1); if (!state) abort();
    size_t used = fread(state, 1, length, f); fclose(f);
    if (used != (size_t)length) abort();
    int status = 0;
    for (size_t pos = 0; pos < p->data_size;) {
        struct nm_del_hdr h; memcpy(&h, p->buffer + pos, sizeof(h));
        size_t size = sizeof(h) + h.v_len, at = 0;
        if (pos + size > p->data_size) abort();
        const char *fail = getenv("FAIL_PATH");
        if (fail && strlen(fail) == h.v_len && !memcmp(fail, p->buffer + pos + sizeof(h), h.v_len)) {
            if (!status) status = -5;
            pos += size; continue;
        }
        while (at < used) {
            struct nm_del_hdr old; memcpy(&old, state + at, sizeof(old));
            size_t n = sizeof(old) + old.v_len;
            if (at + n > used) abort();
            if (n == size && !memcmp(state + at, p->buffer + pos, n)) break;
            at += n;
        }
        if (at == used) { if (!status) status = -2; }
        else { memmove(state + at, state + at + size, used - at - size); used -= size; }
        pos += size;
    }
    f = fopen(path, "wb"); if (!f) abort();
    if (fwrite(state, 1, used, f) != used || fclose(f)) abort();
    free(state); p->arg1 = p->data_size;
    return status;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline-header', type=Path, help='Run the frozen pre-fix header and require DEV-106 reproduction')
    args = p.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    if args.baseline_header:
        baseline = args.baseline_header.read_text()
        oracle.build_zip.adapt_cli_header = lambda _: baseline
    marker = '  batches++;p->arg1=p->data_size;'
    assert marker in oracle.POST
    oracle.POST = DELETE + oracle.POST.replace(marker, '  if(p->cmd==NM_CMD_DEL_RULE&&getenv("DEL_STATE"))return fixture_delete(p);\n' + marker, 1)
    oracle.build(out)
    module = out / 'module'; cases = []

    def file(relative):
        path = module / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture'); return path

    def run(label, command, expected, **env):
        cap = out / (label + '.bin')
        result = subprocess.run([str(out/'cli'), 'module', command, str(module), '--uid-excluded', '100-200'],
                                env=dict(os.environ, CAPTURE=str(cap), **env), capture_output=True, text=True, timeout=30)
        (out/(label+'.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == expected, (label, result.returncode, result.stderr)
        rows = oracle.records(cap)
        cases.append({'case':label, 'exit':result.returncode, 'attempted':len(rows)})
        return rows

    def key(row):
        name = row['v'].encode()
        return struct.pack('<IIIIH', row['uid'], row['uid_end'], row['deny'], row['deny_end'], len(name)) + name

    def seed(rows):
        state = out/'state.bin'; state.write_bytes(b''.join(dict.fromkeys(key(row) for row in rows))); return state

    file('system/etc/deep/one'); file('system/bin/two'); (module/'system/empty').mkdir()
    loaded = run('nested-load', 'load', 0); state = seed(loaded)
    if args.baseline_header:
        deleted = run('baseline-unload', 'unload', 1, DEL_STATE=str(state))
        assert {r['v'] for r in deleted} > {r['v'] for r in loaded}
        assert state.read_bytes() == b''
        (out/'receipt.json').write_text(json.dumps({'reproduced':'DEV-106: all rules removed, surplus DEL returns 1','cases':cases},indent=2)+'\n')
        print('PASS: frozen pre-fix DEV-106 reproduced'); return
    deleted = run('nested-unload', 'unload', 0, DEL_STATE=str(state))
    assert {key(r) for r in deleted} == {key(r) for r in loaded} and not state.read_bytes()
    assert len(deleted) == len({key(r) for r in deleted})
    run('missing-rules', 'unload', 1, DEL_STATE=str(state))

    for i in range(140): file(f'system/vendor/etc/{i:03}')
    (module/'vendor').symlink_to('system/vendor', target_is_directory=True)
    file('system/whiteout/.remove'); file('system/replaced/.replace'); file('system/replaced/value')
    file('system/both/.remove'); file('system/both/.replace'); file('system/both/value')
    file('system/xempty/.replace'); file('system/xopaque/value'); file('system/xopaque/.replace')
    for name in ('xempty', 'xopaque'):
        subprocess.run(['xattr','-w','user.nomount-fixture-opaque','y',str(module/'system'/name)],check=True)
    file('system/char-whiteout')
    (module/'system/alias').symlink_to('etc', target_is_directory=True)
    loaded = run('markers-aliases-load', 'load', 0); keys = {key(r) for r in loaded}
    assert len(loaded) > len(keys), 'fixture must include overlapping markers and partition aliases'
    state = seed(loaded)
    # Unrelated path and a different UID scope at the same path survive unload.
    extra = key(dict(v='/system/unrelated',uid=0,uid_end=0,deny=0,deny_end=0)) + key(dict(loaded[0],uid=300,uid_end=300,deny=0,deny_end=0))
    with state.open('ab') as f: f.write(extra)
    deleted = run('markers-aliases-unload', 'unload', 0, DEL_STATE=str(state))
    assert len(deleted) == len(keys) and {key(r) for r in deleted} == keys
    assert state.read_bytes() == extra
    failed = next(r for r in loaded if r['v']=='/vendor/etc/070')
    state = seed(loaded)
    deleted = run('real-delete-failure', 'unload', 1, DEL_STATE=str(state), FAIL_PATH=failed['v'])
    assert len(deleted) == len(keys) and state.read_bytes() == key(failed)
    # A missing legitimate rule must not be mistaken for successful skeleton cleanup.
    state = seed([r for r in loaded if key(r)!=key(failed)])
    deleted = run('missing-legitimate-rule', 'unload', 1, DEL_STATE=str(state))
    assert len(deleted) == len(keys) and state.read_bytes() == b''
    (out/'receipt.json').write_text(json.dumps({'scope':'Developer host production CLI, strict keyring rule-state model; not native VFS/device evidence','cases':cases},indent=2)+'\n')
    print('PASS', len(cases), 'DEV-106 cases; exact DEL set, one attempt per path, real failures retained')

if __name__ == '__main__': main()
