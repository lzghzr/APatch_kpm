#!/usr/bin/env python3
"""核对 keyring 连续片段、目标 mutex 尺寸与控制层 BTF 拒绝边界。"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def declaration(text, marker):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:text.index(';', end) + 1] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'config', 'spin-header', 'qspin-header', 'osq-header', 'oracle-output', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    oracle = json.loads((args.oracle_output / 'receipt.json').read_text())
    assert oracle['tool_sha256'] == sha(root / 'nomount/tools/test_backing_inode_layout.py')
    assert oracle['sources']['nomount/nm_btf.c'] == sha(root / 'nomount/nm_btf.c')
    args.output.mkdir(parents=True, exist_ok=False)
    config = args.config.read_text()
    for name in ('CONFIG_DEBUG_SPINLOCK', 'CONFIG_DEBUG_MUTEXES', 'CONFIG_DEBUG_LOCK_ALLOC', 'CONFIG_LOCKDEP'):
        assert f'{name}=y' not in config
    assert 'CONFIG_MUTEX_SPIN_ON_OWNER=y' in config and 'CONFIG_SMP=y' in config
    prelude = '''#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;typedef int64_t time64_t;typedef long time_t;
typedef struct {int counter;} atomic_t;typedef struct {long counter;} atomic_long_t;
struct list_head {struct list_head* next;struct list_head* prev;};struct lock_class_key {};
struct seq_file;struct key;struct key_restriction;struct key_preparsed_payload;struct key_match_data;struct kernel_pkey_params;struct kernel_pkey_query;
typedef int (*request_key_actor_t)(struct key*,void*);
#define __randomize_layout
#define __rcu
#define __user
#define __LITTLE_ENDIAN 1
'''
    fragments = []
    reference = None
    for tag in ('target', 'v4.4', 'v5.15', 'v6.6'):
        key_header = args.native / tag / 'include/linux/key-type.h'
        payload_header = args.native / tag / 'include/linux/key.h'
        text = key_header.read_text()
        source = prelude + declaration(payload_header.read_text(), 'union key_payload {')
        source += declaration(text, 'struct key_preparsed_payload {') + declaration(text, 'struct key_type {')
        source += (root / 'nomount/nm_structs.h').read_text()
        source += '''
_Static_assert(offsetof(struct key_type,name)==offsetof(struct nm_key_type_head,name),"key name");
_Static_assert(offsetof(struct key_type,def_datalen)==offsetof(struct nm_key_type_head,def_datalen),"key default length");
_Static_assert(offsetof(struct key_type,def_datalen)+8==sizeof(struct nm_key_type_head),"key head");
_Static_assert(offsetof(struct key_type,free_preparse)-offsetof(struct key_type,preparse)==offsetof(struct nm_key_callbacks,free_preparse),"key callbacks");
_Static_assert(offsetof(struct key_type,instantiate)-offsetof(struct key_type,preparse)==offsetof(struct nm_key_callbacks,instantiate),"key instantiate");
_Static_assert(offsetof(struct key_type,instantiate)+8- offsetof(struct key_type,preparse)==sizeof(struct nm_key_callbacks),"key callback span");
_Static_assert(offsetof(struct key_preparsed_payload,datalen)-offsetof(struct key_preparsed_payload,data)==offsetof(struct nm_key_data,datalen),"preparse data");
_Static_assert(sizeof(((struct key_preparsed_payload*)0)->data)+sizeof(((struct key_preparsed_payload*)0)->datalen)==sizeof(struct nm_key_data),"preparse span");
_Static_assert(__builtin_types_compatible_p(typeof(((struct key_type*)0)->preparse),int (*)(struct key_preparsed_payload*)),"preparse ABI");
_Static_assert(__builtin_types_compatible_p(typeof(((struct key_type*)0)->free_preparse),void (*)(struct key_preparsed_payload*)),"free-preparse ABI");
_Static_assert(__builtin_types_compatible_p(typeof(((struct key_type*)0)->instantiate),int (*)(struct key*,struct key_preparsed_payload*)),"instantiate ABI");
'''
        if tag == 'target':
            source += '#define CONFIG_MUTEX_SPIN_ON_OWNER 1\n'
            source += declaration(args.qspin_header.read_text(), 'typedef struct qspinlock {')
            source += declaration(args.spin_header.read_text(), 'typedef struct raw_spinlock {')
            source += declaration(args.spin_header.read_text(), 'typedef struct spinlock {')
            source += declaration(args.osq_header.read_text(), 'struct optimistic_spin_queue {')
            mutex_header = (args.native / 'target/include/linux/mutex.h').read_text()
            source += declaration(mutex_header, 'struct mutex {')
            names = ('__mutex_init', 'mutex_lock', 'mutex_unlock')
            # DEBUG_LOCK_ALLOC未启用，选择对应分支里的实际公开声明。
            clean = mutex_header.split('#else /* CONFIG_DEBUG_LOCK_ALLOC */')[-1] if '#else /* CONFIG_DEBUG_LOCK_ALLOC */' in mutex_header else mutex_header
            for name in names:
                if name == 'mutex_lock':
                    match = re.search(r'extern\s+void\s+mutex_lock\([^;]+;', clean)
                else:
                    match = re.search(r'extern\s+void\s+' + name + r'\([^;]+;', mutex_header)
                assert match, name
                source += match[0] + '\n'
            source += re.search(r'extern\s+int\s+register_key_type\([^;]+;', text)[0] + '\n'
            source += '''
_Static_assert(__builtin_types_compatible_p(typeof(&__mutex_init),void (*)(struct mutex*,const char*,struct lock_class_key*)),"mutex init ABI");
_Static_assert(__builtin_types_compatible_p(typeof(&mutex_lock),void (*)(struct mutex*)),"mutex lock ABI");
_Static_assert(__builtin_types_compatible_p(typeof(&mutex_unlock),void (*)(struct mutex*)),"mutex unlock ABI");
_Static_assert(__builtin_types_compatible_p(typeof(&register_key_type),int (*)(struct key_type*)),"register key ABI");
'''
        source += 'int main(void){printf("%zu %zu %zu",sizeof(struct key_type),offsetof(struct key_type,preparse),offsetof(struct key_preparsed_payload,data));'
        if tag == 'target':
            source += 'printf(" %zu %zu %zu",sizeof(struct mutex),offsetof(struct mutex,wait_list),sizeof(struct lock_class_key));'
        source += 'puts("");return 0;}\n'
        c = args.output / (tag + '.c')
        c.write_text(source)
        command = ['/usr/bin/clang', '-Wall', '-Werror', str(c), '-o', str(args.output / tag)]
        compiled = subprocess.run(command, text=True, capture_output=True)
        (args.output / (tag + '.log')).write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        values = list(map(int, subprocess.check_output([str(args.output / tag)], text=True).split()))
        # 宿主stdio只用于打印；ARM64声明检查移除宿主打印依赖。
        arm_source = source.replace('#include <stdio.h>\n', '').split('int main(void)')[0]
        arm_source += f'_Static_assert(sizeof(struct key_type)=={values[0]},"ARM64 key size");\n'
        arm_source += f'_Static_assert(offsetof(struct key_type,preparse)=={values[1]},"ARM64 callbacks");\n'
        arm_source += f'_Static_assert(offsetof(struct key_preparsed_payload,data)=={values[2]},"ARM64 preparse input");\n'
        if tag == 'target':
            arm_source += f'_Static_assert(sizeof(struct mutex)=={values[3]},"ARM64 mutex size");\n'
            arm_source += f'_Static_assert(offsetof(struct mutex,wait_list)=={values[4]},"ARM64 mutex wait list");\n'
            arm_source += f'_Static_assert(sizeof(struct lock_class_key)=={values[5]},"ARM64 class key");\n'
        arm_c = args.output / (tag + '-arm.c'); arm_c.write_text(arm_source)
        arm = subprocess.run(['/usr/bin/clang', '--target=aarch64-none-elf', '-Wall', '-Werror', '-c', str(arm_c), '-o', str(args.output / (tag + '.o'))], text=True, capture_output=True)
        (args.output / (tag + '-arm.log')).write_text(arm.stdout + arm.stderr); arm.check_returncode()
        fragments.append({'profile': tag, 'key_header_sha256': sha(key_header), 'payload_header_sha256': sha(payload_header),
                          'key_size': values[0], 'key_callbacks': values[1], 'key_preparse_data': values[2]})
        if tag == 'target':
            assert values == [136, 24, 40, 32, 16, 0], values
            reference = {'mutex_size': values[3], 'mutex_no_lockdep': 1, 'key_callbacks': values[1], 'key_preparse_data': values[2], 'key_type_size': values[0]}
    (args.output / 'reference.json').write_text(json.dumps(reference, indent=2) + '\n')
    spec = importlib.util.spec_from_file_location('btf_host', root / 're_kernel/tools/test_btf.py')
    host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
    b = host.Btf(); pointer = b.add('', 2, 0); integer = b.add('u32', 1, 4, struct.pack('<I', 32)); long_int = b.add('u64', 1, 8, struct.pack('<I', 64))
    def prototype(args, result):
        return b.add('', 13, result, b''.join(struct.pack('<II', b.name('arg'+str(i)), t) for i, t in enumerate(args)), len(args))
    callbacks = [b.add('', 2, prototype([pointer], integer)), b.add('', 2, prototype([pointer], 0)), b.add('', 2, prototype([pointer, pointer], integer))]
    b.aggregate('mutex', 32, [('unused_field', long_int, 0)])
    b.aggregate('key_type', 136, [('name', pointer, 0), ('def_datalen', long_int, 8), ('preparse', callbacks[0], 24), ('free_preparse', callbacks[1], 32), ('instantiate', callbacks[2], 40)])
    b.aggregate('key_preparsed_payload', 72, [('data', pointer, 40), ('datalen', long_int, 48)])
    for name, count, result in [('__mutex_init',3,0),('mutex_lock',1,0),('mutex_unlock',1,0),('register_key_type',1,integer)]:
        b.add(name, 12, prototype([pointer] * count, result))
    blob = b.data(); records, strings = host.index_btf(blob)
    source = (args.oracle_output / 'btf.c').read_text().split('int main(int argc,char** argv)', 1)[0]
    source = re.sub(r'static const u32 records\[\] = \{[^}]*\};', 'static const u32 records[] = {' + ','.join(map(str,records)) + '};', source)
    source = re.sub(r'static const u32 string_start=\d+,string_length=\d+;', f'static const u32 string_start={strings},string_length={len(blob)-strings};', source)
    source += r'''
int main(int argc,char** argv){
 assert(argc==2);FILE* f=fopen(argv[1],"rb");assert(f);fseek(f,0,SEEK_END);long size=ftell(f);rewind(f);blob=malloc(size);assert(blob);assert(fread(blob,1,size,f)==(size_t)size);fclose(f);
 struct_offset.key_type_size=136;assert(!calculate_btf_control_layout());assert(struct_offset.mutex_size==32&&struct_offset.mutex_no_lockdep==1&&struct_offset.key_callbacks==24&&struct_offset.key_preparse_data==40);
 struct kpm_btf btf={&object,host_find,host_type,host_name,host_size};
 struct btf_type* key=(void*)kpm_btf_type(&btf,"key_type",4);struct btf_member* fields=(void*)(key+1);
 struct btf_type* prep=(void*)kpm_btf_type(&btf,"key_preparsed_payload",4);struct btf_member* input=(void*)(prep+1);
 u32 offset=fields[3].offset;fields[3].offset+=8;assert(calculate_btf_control_layout()==-EINVAL);fields[3].offset=offset;
 struct btf_type* callback=(void*)host_type(&object,fields[2].type);struct btf_type* proto=(void*)host_type(&object,callback->size);
 u32 info=proto->info;proto->info=(13U<<24)|2;assert(calculate_btf_control_layout()==-EOPNOTSUPP);proto->info=info;
 u32 type=input[0].type;input[0].type=input[1].type;assert(calculate_btf_control_layout()==-EINVAL);input[0].type=type;
 u32 prep_size=prep->size;prep->size=48;assert(calculate_btf_control_layout()==-EINVAL);prep->size=prep_size;
 struct btf_type* mutex=(void*)kpm_btf_type(&btf,"mutex",4);u32 mutex_size=mutex->size;mutex->size=0;assert(calculate_btf_control_layout()==-EINVAL);mutex->size=mutex_size;
 struct btf_member* owner=(void*)(mutex+1);u32 name=owner->name_off;
'''
    source += 'char* owner_name=(void*)(blob+string_start+name);char saved[13];memcpy(saved,owner_name,sizeof(saved));memcpy(owner_name,"dep_map",8);assert(calculate_btf_control_layout()==-EOPNOTSUPP);memcpy(owner_name,saved,sizeof(saved));\n'
    source += r'''
 // 同一算法接受已核对的另一组真实连续片段位置，按字段而非版本号选择。
 key->size=144;struct_offset.key_type_size=144;for(int i=2;i<5;i++)fields[i].offset+=64;
 prep->size=80;input[0].offset+=64;input[1].offset+=64;
 assert(!calculate_btf_control_layout()&&struct_offset.key_callbacks==32&&struct_offset.key_preparse_data==48);
 struct btf_type* function=(void*)kpm_btf_type(&btf,"mutex_lock",12);struct btf_type* fn=(void*)host_type(&object,function->size);
 u32 count=fn->info;fn->info=(13U<<24)|2;assert(calculate_btf_control_layout()==-EOPNOTSUPP);fn->info=count;
 u32 fn_name=function->name_off;function->name_off=0;assert(calculate_btf_control_layout()==-ENOENT);function->name_off=fn_name;
 assert(!calculate_btf_control_layout());free(blob);puts("control BTF offsets, continuous fragments, ABI and lockdep boundaries: PASS");return 0;}
'''
    c=args.output/'control-btf.c';c.write_text(source);(args.output/'synthetic.btf').write_bytes(blob)
    compiled=subprocess.run(['/usr/bin/clang','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-g',str(c),'-o',str(args.output/'control-btf')],text=True,capture_output=True)
    (args.output/'compile.log').write_text(compiled.stdout+compiled.stderr);compiled.check_returncode()
    run=subprocess.run([str(args.output/'control-btf'),str(args.output/'synthetic.btf')],text=True,capture_output=True)
    (args.output/'run.log').write_text(run.stdout+run.stderr);run.check_returncode()
    receipt={'scope':'Developer native declaration fragments and synthetic BTF; not native lock or keyring execution',
             'sources':{p:sha(root/p) for p in ('nomount/nm_structs.h','nomount/nm_offsets.c','nomount/nm_btf.c','kpm_utils.h')},
             'tool_sha256':sha(Path(__file__)),'config_sha256':sha(args.config),'profiles':fragments,'target_values':reference,
             'native_inputs':{str(p.relative_to(args.native)):sha(p) for p in args.native.rglob('*') if p.is_file()},
             'spin_header_sha256':sha(args.spin_header),'qspin_header_sha256':sha(args.qspin_header),'osq_header_sha256':sha(args.osq_header),
             'native_objects':{tag:sha(args.output/(tag+'.o')) for tag in ('target','v4.4','v5.15','v6.6')},
             'oracle_receipt_sha256':sha(args.oracle_output/'receipt.json'),'result':run.stdout.strip()}
    (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(run.stdout.strip())


if __name__ == '__main__':
    main()
