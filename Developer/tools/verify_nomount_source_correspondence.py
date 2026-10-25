#!/usr/bin/env python3
import argparse,gzip,hashlib,json,re,struct,subprocess
from pathlib import Path
parser=argparse.ArgumentParser(description="Compile unmodified operation-table declarations using target IKCONFIG; offline only")
parser.add_argument('--sources',type=Path,required=True)
parser.add_argument('--images',type=Path,required=True)
parser.add_argument('--toolchain',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
CC=args.toolchain/'aarch64-linux-android31-clang'
IMAGES=args.images
TARGETS={'mi10-sony':'kernel_mi10-4.19','mi11-odin':'kernel_mi11-5.4','a12-mirror':'kernel_android12-5.10','a12-exact':'kernel_android12-5.10'}
TABLES=[('inode_operations','set_acl'),('super_operations','nr_cached_objects'),('dentry_operations','d_real')]

def block(text,name):
 m=re.search(r'struct\s+'+name+r'\s*\{',text);start=m.start();i=m.end();depth=1
 while depth:
  depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:text.index(';',i)+1]

def section(path,wanted):
 data=path.read_bytes();assert data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',data,18)[0]==183
 off=struct.unpack_from('<Q',data,40)[0];size,n,stridx=struct.unpack_from('<HHH',data,58)
 ss=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*size) for i in range(n)]
 s=ss[stridx];names=data[s[4]:s[4]+s[5]]
 for s in ss:
  name=names[s[0]:names.index(b'\0',s[0])].decode()
  if name==wanted:return data[s[4]:s[4]+s[5]]
 raise ValueError(wanted)

out=args.output;out.mkdir(exist_ok=False)
results=[]
for src,target in TARGETS.items():
 folder=out/src;folder.mkdir();source=args.sources/src
 binary=(IMAGES/target).read_bytes();start=binary.index(b'IKCFG_ST')+8;end=binary.index(b'IKCFG_ED',start)
 config=gzip.decompress(binary[start:end]).decode();(folder/'target.config').write_text(config)
 kv=dict(re.findall(r'^(CONFIG_\w+)=(.+)$',config,re.M))
 names=['CONFIG_QUOTA','CONFIG_ARM64_L1_CACHE_SHIFT','CONFIG_LOCKDEP','CONFIG_DEBUG_LOCK_ALLOC','CONFIG_ANDROID_KABI_RESERVE','CONFIG_SMP','CONFIG_GCC_PLUGIN_RANDSTRUCT']
 states={k:kv.get(k,'not-set' if '# '+k+' is not set' in config else 'absent') for k in names}
 defines='\n'.join('#define '+k+' '+('1' if v=='y' else v) for k,v in kv.items() if v!='m')+'\n'
 (folder/'target_config.h').write_text(defines)
 stubs=folder/'stub/linux';stubs.mkdir(parents=True)
 (stubs/'compiler.h').write_text('#define __user\n#define __stringify_1(x) #x\n#define __stringify(x) __stringify_1(x)\n#define CONCAT1(a,b) a##b\n#define CONCAT(a,b) CONCAT1(a,b)\n#define __UNIQUE_ID(x) CONCAT(x,__COUNTER__)\n')
 (stubs/'stringify.h').write_text('#include <linux/compiler.h>\n')
 cache=(source/'arch/arm64/include/asm/cache.h').read_text()+'\n'+(source/'include/linux/cache.h').read_text()
 macro_names=['L1_CACHE_SHIFT','L1_CACHE_BYTES','SMP_CACHE_BYTES','____cacheline_aligned']
 macros='\n'.join(re.search(r'^#define\s+'+k+r'\b[^\n]*',cache,re.M)[0] for k in macro_names)+'\n'
 decls=[block((source/('include/linux/dcache.h' if t=='dentry_operations' else 'include/linux/fs.h')).read_text(),t) for t,a in TABLES]
 prologue='''#include "target_config.h"
#include <linux/compiler.h>
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short umode_t;
typedef unsigned int dev_t;
typedef unsigned int gfp_t;
typedef long ssize_t;
typedef unsigned long size_t;
typedef long long loff_t;
typedef _Bool bool;
_Static_assert(sizeof(void *)==8 && sizeof(u64)==8,"AArch64 widths");
#include <linux/android_kabi.h>
'''+macros
 variants={}
 for variant in ['original','tail-counterexample']:
  # Counterexample deliberately erases only trailing reserve declarations, not any Oracle.
  override='' if variant=='original' else '#undef ANDROID_KABI_RESERVE\n#define ANDROID_KABI_RESERVE(n)\n'
  body=prologue+override+'\n'.join(decls)+'\nconst unsigned long values[] __attribute__((section(".layout")))={\n'
  for t,a in TABLES:
   exprs=['sizeof(struct '+t+')','_Alignof(struct '+t+')','__builtin_offsetof(struct '+t+','+a+')']
   if variant=='original':exprs+=['__builtin_offsetof(struct '+t+',android_kabi_reserved4)+sizeof(((struct '+t+'*)0)->android_kabi_reserved4)']
   body+=','.join(exprs)+',\n'
  body+='};\n';c=folder/(variant+'.c');o=folder/(variant+'.o');c.write_text(body)
  argv=[str(CC),'-std=gnu11','-ffreestanding','-Wno-visibility','-I'+str(folder/'stub'),'-I'+str(source/'include'),'-c',str(c),'-o',str(o)]
  p=subprocess.run(argv,capture_output=True,text=True);(folder/(variant+'.stderr')).write_text(p.stderr)
  if p.returncode:raise RuntimeError(p.stderr)
  vals=struct.unpack('<'+'Q'*(len(section(o,'.layout'))//8),section(o,'.layout'));width=4 if variant=='original' else 3
  variants[variant]={t:dict(zip(['size','alignment','anchor','member_end'][:width],vals[i*width:(i+1)*width])) for i,(t,a) in enumerate(TABLES)}
 results.append(dict(source=src,target=target,kernel_sha256=hashlib.sha256(binary).hexdigest(),ikconfig_sha256=hashlib.sha256(config.encode()).hexdigest(),config=states,cache_macros=macros,declarations=dict(zip([t for t,a in TABLES],decls)),layouts=variants))
 print(src,states,variants)
(out/'receipt.json').write_text(json.dumps(results,indent=2)+'\n')
