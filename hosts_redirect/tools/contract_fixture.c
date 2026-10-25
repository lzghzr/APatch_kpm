
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#undef NULL
#define NULL 0
#define __user
#define unlikely(x) __builtin_expect(!!(x),0)
#define likely(x) __builtin_expect(!!(x),1)
#define logkm(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define HOOK_LOCAL_DATA_NUM 8

typedef struct
{
    union
    {
        struct
        {
            uint64_t data0;
            uint64_t data1;
            uint64_t data2;
            uint64_t data3;
            uint64_t data4;
            uint64_t data5;
            uint64_t data6;
            uint64_t data7;
        };
        uint64_t data[HOOK_LOCAL_DATA_NUM];
    };
} hook_local_t;

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
        };
        uint64_t args[0];
    };
} hook_fargs0_t __attribute__((aligned(8)));

typedef struct
{
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union
    {
        struct
        {
            uint64_t arg0;
            uint64_t arg1;
            uint64_t arg2;
            uint64_t arg3;
        };
        uint64_t args[4];
    };
} hook_fargs4_t __attribute__((aligned(8)));

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;
struct filename
{
    const char *name; /* pointer to actual string */
    const __user char *uptr; /* original userland pointer */
    struct audit_names *aname;
    int refcnt;
    const char iname[];
};
struct file;
struct open_flags { int flags; };
typedef int hook_err_t;
static unsigned int uid;
static int missing, hook_error, lookups, hooks, unhooks;
static unsigned int current_uid(void) { return uid; }
static struct file* fake_open(int dfd, struct filename* name, const struct open_flags* op) { return NULL; }
static uintptr_t kallsyms_lookup_name(const char* name) { assert(!strcmp(name,"do_filp_open"));lookups++;return missing?0:(uintptr_t)fake_open; }
static int hook_wrap(void* fn,int argc,void* before,void* after,void* data) {assert(fn==(void*)fake_open && argc==3 && before && after);hooks++;return hook_error;}
static void unhook(void* fn) {assert(fn==(void*)fake_open);unhooks++;}
static int is_bad_address(void* fn) { return !fn; }
static int copy_calls, copy_len, copy_result = -1;
static int compat_copy_to_user(void* dst,const void* src,int n) {copy_calls++;copy_len=n;if(dst && copy_result < 0)memcpy(dst,src,n);return copy_result < 0 ? n : copy_result;}
#define lookup_name(func)                                  \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
    return -21;

#define lookup_name_continue(func)                  \
  func = (typeof(func))kallsyms_lookup_name(#func); \
  pr_info("kernel function %s addr: %llx\n", #func, func);

#define hook_func(func, argv, before, after, udata)                         \
  if (!func)                                                                \
    return -22;                                                             \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func) {                                                    \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  } else {                                                                  \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)            \
  if (func && !is_bad_address(func)) \
    unhook(func);


/* PRODUCTION */

int main(void) {
 const char* paths[]={"/system/etc/hosts","/etc/hosts","hosts","./hosts","../etc/hosts","/system/etc/./hosts","/system/etc/hosts.equiv","/data/adb/hosts/probe"};
 int flags[]={O_RDONLY,O_WRONLY,O_RDWR,O_WRONLY|O_TRUNC,O_WRONLY|O_APPEND,O_WRONLY|O_CREAT,O_RDWR|O_CREAT|O_TRUNC};
 int cases=0;
 for(int who=0;who<2;who++)for(int disabled=0;disabled<2;disabled++)for(int p=0;p<8;p++)for(int f=0;f<7;f++) {
  uid=who?10000:0;assert(set_hosts(disabled?"disable":"probe"));
  struct filename name={.name=paths[p]};struct open_flags op={.flags=flags[f]};
  hook_fargs3_t args={.arg0=(uint64_t)(f%2?42:-100),.arg1=(uintptr_t)&name,.arg2=(uintptr_t)&op,.arg3=0x3344,.ret=0x123456,.skip_origin=0};
  args.local.data0=0xDEADBEEF;
  uint64_t dfd=args.arg0;do_filp_open_before(&args,NULL);
  bool redirected=who==0 && !disabled && p==0;
  assert(name.name==(redirected?hosts_target:paths[p]));
  assert(args.local.data0==(redirected?(uintptr_t)paths[p]:0));
  assert(args.arg0==dfd && args.arg1==(uintptr_t)&name && args.arg2==(uintptr_t)&op && args.arg3==0x3344);
  assert(op.flags==flags[f] && args.ret==0x123456 && args.skip_origin==0);
  args.ret=(f%2)?0:(uint64_t)-13;uint64_t result=args.ret;
  do_filp_open_after(&args,NULL);assert(name.name==paths[p]);assert(args.ret==result && op.flags==flags[f]);cases++;
 }
 uid=0;assert(set_hosts("probe"));
 struct filename a={.name=paths[0]},b={.name=paths[0]};hook_fargs3_t fa={.arg1=(uintptr_t)&a},fb={.arg1=(uintptr_t)&b};
 do_filp_open_before(&fa,NULL);do_filp_open_before(&fb,NULL);assert(a.name==hosts_target && b.name==hosts_target);
 do_filp_open_after(&fb,NULL);assert(b.name==paths[0] && a.name==hosts_target);do_filp_open_after(&fa,NULL);assert(a.name==paths[0]);
 char limit[42];memset(limit,'x',40);limit[40]=0;assert(set_hosts(limit));assert(strlen(hosts_target)==56);
 char snapshot[64];memcpy(snapshot,hosts_target,64);limit[40]='x';limit[41]=0;assert(!set_hosts(limit) && !set_hosts(NULL));assert(!memcmp(snapshot,hosts_target,64));
 assert(!set_hosts(""));assert(!memcmp(snapshot,hosts_target,64));
 char reply[64]={0};assert(inline_hook_control0("adblock",reply,64)==0);assert(!strcmp(hosts_target,"/data/adb/hosts/adblock") && !strcmp(reply,"_(._.)_\n"));
 assert(inline_hook_control0(limit,reply,64)==0);assert(!strcmp(reply,"_(x_x)_\n"));
 missing=1;do_filp_open=NULL;assert(inline_hook_init("probe",NULL,NULL)==-21 && !do_filp_open && hooks==0 && lookups==1);assert(inline_hook_exit(NULL)==0 && unhooks==0);
 missing=0;hook_error=1;assert(inline_hook_init("probe",NULL,NULL)==-23 && !do_filp_open && hooks==1);assert(inline_hook_exit(NULL)==0 && unhooks==0);
 hook_error=0;assert(inline_hook_init("probe",NULL,NULL)==0 && do_filp_open==fake_open && hooks==2);assert(inline_hook_exit(NULL)==0 && !do_filp_open && unhooks==1);assert(inline_hook_exit(NULL)==0 && unhooks==1);

 int bounds=0;
 const int capacities[]={-2147483647-1,-1,0,1,2,3,4,5,6,7,8,9,10,64};
 for(int rejected=0;rejected<2;rejected++)for(int cap=0;cap<14;cap++)for(int absent=0;absent<2;absent++) {
  unsigned char buf[66];memset(buf,0xa5,sizeof(buf));copy_calls=copy_len=0;
  assert(set_hosts("probe"));
  assert(inline_hook_control0(rejected?limit:"adblock",absent?NULL:(char*)buf+1,capacities[cap])==0);
  assert(!strcmp(hosts_target,rejected?"/data/adb/hosts/probe":"/data/adb/hosts/adblock"));
  int written=!absent && capacities[cap]>=9;
  assert(copy_calls==written);
  if(written) {assert(copy_len==9);assert(!memcmp(buf+1,rejected?"_(x_x)_\n":"_(._.)_\n",9));}
  for(int j=0;j<66;j++)if(!written || j<1 || j>9)assert(buf[j]==0xa5);
  bounds++;
 }
 copy_result=0;copy_calls=0;
 assert(inline_hook_control0("probe",reply,sizeof(reply))==0 && copy_calls==1);
 assert(!strcmp(hosts_target,"/data/adb/hosts/probe"));
 printf("%d ctl0 capacity/NULL/result cases plus copy-failure return contract: PASS\n",bounds);
 printf("%d path/UID/disable/open-flags cases; nested restore, ctl0, init failure and exit: PASS\n",cases);return 0;
}
