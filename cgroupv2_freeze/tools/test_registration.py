#!/usr/bin/env python3
"""Developer: core-only cftype registration, benign duplicates, error propagation, pair-only hook removal."""
import argparse
from pathlib import Path
import subprocess
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output',type=Path,required=True)
a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
s=(Path(__file__).resolve().parents[1]/'cgroupv2_freeze.c').read_text()
body=s[s.index('static void cgroup_addrm_files_after'):s.index('static const char uid_[]')]
fixture=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define unlikely(x) (x)

#include <string.h>
#define logkm(...) ((void)0)
struct cgroup_subsys_state; struct cgroup;
struct cftype { char bytes[200]; };
static struct cftype cgroup_freeze_files[2];
static int cftype_stride=192;
static bool cgroup_files_live;
typedef struct { long ret; uintptr_t arg0,arg1,arg2,arg3; } hook_fargs4_t;
static int calls, result;
static int fake(struct cgroup_subsys_state*a,struct cgroup*b,struct cftype*c,bool add) {
 assert(c==cgroup_freeze_files);calls++;return result;
}
static int (*cgroup_addrm_files)(struct cgroup_subsys_state*,struct cgroup*,struct cftype*,bool)=fake;
#define wrap_get_origin_func(a) cgroup_addrm_files
/* PRODUCTION */
int main(void) {
 struct cftype files[3]={0};
 strcpy(files[0].bytes,"tasks");strcpy((char*)files+cftype_stride,"cgroup.procs");
 hook_fargs4_t a={.arg2=(uintptr_t)files,.arg3=1};
 // 1. 核心表添加一次：登记成功并标记常驻
 cgroup_addrm_files_after(&a,NULL);assert(calls==1&&cgroup_files_live&&a.ret==0);
 // 2. 自有表跳过（递归隔离）
 a.arg2=(uintptr_t)cgroup_freeze_files;cgroup_addrm_files_after(&a,NULL);assert(calls==1);
 // 3. 非核心/控制器表跳过
 memset(files,0,sizeof(files));strcpy(files[0].bytes,"cpuacct.usage");
 a.arg2=(uintptr_t)files;cgroup_addrm_files_after(&a,NULL);assert(calls==1);
 // 4. 原函数已经失败时不再追加一次
 strcpy(files[0].bytes,"cgroup.procs");a.ret=-12;cgroup_addrm_files_after(&a,NULL);assert(calls==1);
 // 5. -EEXIST 是自家重复添加：不升级成调用方的建组失败，但仍按常驻处理
 a.ret=0;result=-17;cgroup_files_live=false;cgroup_addrm_files_after(&a,NULL);
 assert(calls==2&&a.ret==0&&cgroup_files_live);
 // 6. 其它错误仍然透传给调用者
 a.ret=0;result=-12;cgroup_files_live=false;cgroup_addrm_files_after(&a,NULL);
 assert(calls==3&&a.ret==-12&&!cgroup_files_live);
 // 7. 删除路径正常
 a.ret=0;result=0;a.arg3=0;cgroup_addrm_files_after(&a,NULL);
 assert(calls==4&&a.ret==0&&!cgroup_files_live);
 // 8. 删除路径遇到 -EEXIST 同样良性，且不因删除标记常驻
 a.ret=0;result=-17;cgroup_files_live=false;cgroup_addrm_files_after(&a,NULL);
 assert(calls==5&&a.ret==0&&!cgroup_files_live);
 puts("core-only add/remove, recursion guard, benign -EEXIST and other error propagation: PASS");
}
'''
p=a.output/'test.c';p.write_text(fixture.replace('/* PRODUCTION */',body));b=a.output/'test'
subprocess.run(['clang','-O1','-g','-Wall','-Werror','-fsanitize=address,undefined',str(p),'-o',str(b)],check=True)
subprocess.run([str(b)],check=True)
