#!/usr/bin/env python3
"""Developer: use selected Sony BTF field values with the unchanged run_cmd C Oracle."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--image',type=Path,required=True)
ap.add_argument('--output',type=Path,required=True)
a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
r=Path(__file__).resolve().parents[1]
d=a.image.read_bytes();at=d.find(b'\x9f\xeb\x01\x00\x18\x00\x00\x00')
assert at>=0
_,_,_,h,start,length,ss,sl=struct.unpack_from('<HBBIIIII',d,at)
b=d[at:at+h+ss+sl];strings=b[h+ss:h+ss+sl]
def name(i):return strings[i:strings.index(0,i)].decode()
pos=h+start;end=pos+length;records={}
while pos<end:
    n,info,size=struct.unpack_from('<III',b,pos);kind=(info>>24)&31;count=info&65535
    if kind==4 and name(n) in ['subprocess_info','cred','task_security_struct','kthread_work','kthread_worker']:
        records[name(n)]={'size':size,'fields':{name(mn):off//8 for mn,mt,off in
          (struct.unpack_from('<III',b,pos+12+i*12) for i in range(count))}}
    extra={1:4,2:0,3:12,4:count*12,5:count*12,6:count*8,7:0,8:0,9:0,10:0,11:0,12:0,13:count*8,
           14:4,15:count*12,16:0,17:4,18:0,19:count*12}[kind];pos+=12+extra
assert pos==end and len(records)==5
subprocess.run(['python3',str(r/'tools/test_run_cmd.py'),'--output',str(a.output/'oracle')],check=True)
source=(a.output/'oracle/test.c').read_text()
addition='  reset(); use_btf=1; btf_fixture();\n'
for idx,n,fields in [(1,'subprocess_info',['path']),(2,'cred',['security']),(3,'task_security_struct',['sid']),
                     (4,'kthread_work',['node','func','worker','canceling']),(5,'kthread_worker',[])]:
    addition+=f'  btf_records[{idx}].type.size={records[n]["size"]};\n'
    for j,f in enumerate(fields):addition+=f'  btf_records[{idx}].members[{j}].offset={records[n]["fields"][f]*8};\n'
addition+='  cred_offset.security_offset=120;\n  assert(prepare_run_cmd()==0);\n'
addition+='  assert(subprocess_info_path_offset==56 && cred_security_offset==120 && cred_sid_offset==4);\n'
addition+='  assert(kfunc(kthread_create_worker) && legacy_worker_size==-1);\n'
addition+='  puts("selected Sony BTF values: modern creator does not require legacy worker size: PASS");\n'
source=source.replace('  puts("run_cmd production',addition+'  puts("run_cmd production')
p=a.output/'sony.c';p.write_text(source);out=a.output/'sony'
subprocess.run(['clang','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',
                '-fsanitize=address,undefined',str(p),'-o',str(out)],check=True)
subprocess.run([str(out)],check=True)
(a.output/'result.json').write_text(json.dumps({'target':'boot_67.2.A.3.178.img / 5.15.189-android13-8-00016',
 'btf_file_offset':at,'records':records,'result':'modern creator layout preparation succeeds; runtime context/SID/worker result needs Tester logs',
 'scope':'Developer host fixture using real BTF field values; unchanged original C Oracle'},indent=2)+'\n')
