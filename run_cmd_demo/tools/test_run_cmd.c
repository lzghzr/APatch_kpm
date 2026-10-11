// Developer 主机夹具：生产函数原样插入，模拟 worker 与 UMH 的调用上下文。
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint32_t u32;
typedef unsigned int gfp_t;
typedef unsigned short umode_t;
typedef void* fl_owner_t;
struct list_head {
  struct list_head *next, *prev;
};
#define INIT_LIST_HEAD(p) ((p)->next = (p)->prev = (p))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define __user
#define MYKPM_VERSION "test"
#define KPM_NAME(x)
#define KPM_VERSION(x)
#define KPM_LICENSE(x)
#define KPM_AUTHOR(x)
#define KPM_DESCRIPTION(x)
#define KPM_INIT(x)
#define KPM_CTL0(x)
#define KPM_EXIT(x)
#define UMH_WAIT_PROC 2
#define kfunc_def(name) (*kf_##name)
#define kfunc(name) kf_##name
#define kvar(name) kv_##name
#define kvar_def(name) (*kv_##name)
#define kvar_val(name) (*kvar(name))
#define kvar_lookup_name(name) kv_##name = (typeof(kv_##name))lookup(#name)
#define kfunc_lookup_name(name) kf_##name = (typeof(kf_##name))lookup(#name)
#define printk(...) ((void)0)
struct cred {
  int context;
  uid_t uid, euid;
  void* security;
};
static struct {
  int security_offset, uid_offset, euid_offset;
} cred_offset = {offsetof(struct cred, security), offsetof(struct cred, uid), offsetof(struct cred, euid)};
struct lock_class_key;
struct kthread_work;
struct task_struct {
  int unused;
};
static struct task_struct initial_task;
static struct {
  int real_cred_offset;
  int cred_offset;
} task_struct_offset = {0x80, -1};
struct btf {
  int unused;
};
static int legacy_api, use_btf, btf_missing, legacy_alloc_fail, legacy_thread_fail, legacy_allocs, legacy_frees;
static void* legacy_heap;
static uint32_t worker_entry[32], task_sid_entry[32];
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name);
static int blob_offset, sid_error, sid_zero, getter_error;
static struct cred kernel_cred;
static const struct cred* active_cred = &kernel_cred;
static int override_depth, override_calls, revert_calls;
struct subprocess_info {
  char prefix[0x38];
  const char* path;
  char** argv;
  char** envp;
  int (*init)(struct subprocess_info*, struct cred*);
};
struct kthread_worker {
  int unused;
};
struct file {
  int refs;
  int context;
};
static struct file null_file;
static struct file* stdio_files[3];
static int open_error, replace_error_fd = -1, open_calls, replace_calls, close_calls;
static int lock_depth, ctl_active;
static unsigned long run_cmd_lock(unsigned int* lock) {
  assert(!lock_depth);
  lock_depth++;
  return 0;
}
static void run_cmd_unlock(unsigned int* lock, unsigned long flags) { assert(lock_depth-- == 1); }
static struct subprocess_info helper;
static struct cred caller, snapshot;
static struct kthread_worker worker;
static struct kthread_work* queued_work;
static int alloc_fail, cred_fail, worker_fail, queue_fail, exec_ret, setup_calls, copied, copy_short, ran, live_creds;
static long prepare_ret;
static const char* missing;
static uint32_t entry[64], sid_entry[32];
static char observed[4096];
static void* lookup(const char* name);
static long fake_prepare_run_cmd(void);
static void fake_task_getsecid(struct task_struct*, u32*);
static void* fake_kmalloc(size_t, gfp_t);
static void fake_kfree(const void*);
static void fake_init_worker(struct kthread_worker*, const char*, struct lock_class_key*);
static int fake_worker_fn(void*);
static struct task_struct* fake_create_thread(int (*)(void*), void*, int, const char*, ...);
static int fake_wake(struct task_struct*);
static bool fake_legacy_queue(struct kthread_worker*, struct kthread_work*);

static int compat_copy_to_user(char* dst, const void* src, int len) {
  assert(!lock_depth);
  copied = len;
  memcpy(dst, src, len);
  return copy_short ? len - 1 : len;
}
/* PRODUCTION_FUNCTIONS */
static struct cred* fake_prepare_kernel_cred(struct task_struct* daemon) {
  assert(daemon == &initial_task);
  assert(!lock_depth && !ctl_active && !live_creds);
  if (cred_fail)
    return NULL;
  snapshot = kernel_cred;
  snapshot.security = &snapshot.context;
  live_creds++;
  return &snapshot;
}
static void fake_abort_creds(struct cred* old) {
  assert(old == &snapshot && live_creds == 1);
  live_creds--;
}
static int fake_secctx_to_secid(const char* data, u32 len, u32* sid) {
  assert(!ctl_active && !lock_depth && !strcmp(data, RUN_CMD_CONTEXT) && len == strlen(data));
  *sid = sid_zero ? 0 : 3;
  return sid_error;
}
static void fake_getsecid(const struct cred* cred, u32* sid) { *sid = getter_error ? 99 : cred->context; }
static void fake_transfer(struct cred* new, const struct cred* old) {
  assert(old == &snapshot && live_creds == 1 && !ctl_active && !lock_depth);
  assert(active_cred == &kernel_cred && !override_depth);
  new->context = old->context;
  new->security = &new->context;
}
static const struct cred* fake_override_creds(const struct cred* new) {
  assert(!ctl_active && !lock_depth && !override_depth && active_cred == &kernel_cred);
  assert(new->context == snapshot.context);
  const struct cred* old = active_cred;
  active_cred = new;
  override_depth++;
  override_calls++;
  return old;
}
static void fake_revert_creds(const struct cred* old) {
  assert(!ctl_active && !lock_depth && override_depth == 1 && old == &kernel_cred);
  active_cred = old;
  override_depth--;
  revert_calls++;
}
static struct file* fake_filp_open(const char* path, int flags, umode_t mode) {
  assert(!ctl_active && !lock_depth && !strcmp(path, "/dev/null") && flags == O_RDWR && mode == 0);
  assert(override_depth == 1 && active_cred->context == snapshot.context);
  open_calls++;
  if (open_error)
    return ERR_PTR(open_error);
  null_file.refs++;
  null_file.context = active_cred->context;
  return &null_file;
}
static int fake_replace_fd(unsigned int fd, struct file* file, unsigned int flags) {
  assert(!ctl_active && !lock_depth && file == &null_file && fd < 3 && flags == 0);
  assert(active_cred == &kernel_cred && !override_depth);
  replace_calls++;
  if ((int)fd == replace_error_fd)
    return -ENOMEM;
  if (stdio_files[fd])
    stdio_files[fd]->refs--;
  stdio_files[fd] = file;
  file->refs++;
  return fd;
}
static int fake_filp_close(struct file* file, fl_owner_t id) {
  assert(!ctl_active && !lock_depth && file == &null_file && file->refs > 0 && !id);
  close_calls++;
  file->refs--;
  return 0;
}
static void helper_exit_files(void) {
  for (unsigned int fd = 0; fd < 3; fd++) {
    if (stdio_files[fd]) {
      stdio_files[fd]->refs--;
      stdio_files[fd] = NULL;
    }
  }
  assert(null_file.refs == 0);
}
static struct subprocess_info* fake_setup(const char* path, char** argv, char** env, gfp_t mask,
                                          int (*init)(struct subprocess_info*, struct cred*),
                                          void (*cleanup)(struct subprocess_info*), void* data) {
  assert(!ctl_active && !lock_depth);
  setup_calls++;
  assert(path == sh && mask == 0 && !cleanup && !data);
  assert(argv[0] == sh && !strcmp(argv[1], "-c") && !argv[3]);
  assert(!strcmp(env[0], "HOME=/") && !env[2]);
  if (alloc_fail)
    return NULL;
  helper.path = "";
  helper.argv = argv;
  helper.envp = env;
  helper.init = init;
  return &helper;
}
static int fake_exec(struct subprocess_info* info, int wait) {
  assert(!ctl_active && !lock_depth && info == &helper && wait == UMH_WAIT_PROC && info->path == sh);
  struct cred new = {0};
  assert(info->init(info, &new) == 0 && new.context == snapshot.context);
  assert(null_file.context == new.context&& active_cred == &kernel_cred && !override_depth);
  for (unsigned int fd = 0; fd < 3; fd++) assert(stdio_files[fd] == &null_file);
  assert(null_file.refs == 3);
  strcpy(observed, info->argv[2]);
  ran++;
  helper_exit_files();
  return exec_ret;
}
static struct kthread_worker* fake_create_worker(unsigned int flags, const char* namefmt, ...) {
  assert(!ctl_active && !lock_depth && flags == 0 && !strcmp(namefmt, "run_cmd_demo"));
  return worker_fail ? ERR_PTR(-ENOMEM) : &worker;
}
static bool fake_queue_work(struct kthread_worker* owner, struct kthread_work* work) {
  assert(!lock_depth && owner == &worker && work == &cmd_work);
  if (queue_fail)
    return false;
  assert(!queued_work);
  queued_work = work;
  return true;
}
static long fake_prepare_run_cmd(void) {
  subprocess_info_path_offset = offsetof(struct subprocess_info, path);
  kfunc(call_usermodehelper_setup) = fake_setup;
  kfunc(call_usermodehelper_exec) = fake_exec;
  kfunc(prepare_kernel_cred) = fake_prepare_kernel_cred;
  kfunc(security_secctx_to_secid) = fake_secctx_to_secid;
  kfunc(selinux_cred_getsecid) = fake_getsecid;
  kvar(init_task) = &initial_task;
  cred_sid_offset = 0;
  cred_security_offset = offsetof(struct cred, security);
  kfunc(abort_creds) = fake_abort_creds;
  kfunc(security_transfer_creds) = fake_transfer;
  kfunc(override_creds) = fake_override_creds;
  kfunc(revert_creds) = fake_revert_creds;
  kfunc(kthread_create_worker) = fake_create_worker;
  kfunc(kthread_queue_work) = fake_queue_work;
  kfunc(filp_open) = fake_filp_open;
  kfunc(replace_fd) = fake_replace_fd;
  kfunc(filp_close) = fake_filp_close;
  if (legacy_api) {
    kfunc(selinux_cred_getsecid) = NULL;
    kfunc(selinux_task_getsecid) = fake_task_getsecid;
    kfunc(kthread_create_worker) = NULL;
    kfunc(__init_kthread_worker) = fake_init_worker;
    kfunc(kthread_worker_fn) = fake_worker_fn;
    kfunc(kthread_create_on_node) = fake_create_thread;
    kfunc(wake_up_process) = fake_wake;
    kfunc(__kmalloc) = fake_kmalloc;
    kfunc(kfree) = fake_kfree;
    kfunc(kthread_queue_work) = fake_legacy_queue;
    legacy_worker_size = 40;
  }
  return prepare_ret;
}

static struct {
  struct btf_type type;
  struct btf_member members[4];
} btf_records[11];
static struct btf test_btf;
static struct btf* native_btf = &test_btf;
static const char* btf_names[] = {"",
                                  "subprocess_info",
                                  "cred",
                                  "task_security_struct",
                                  "kthread_work",
                                  "kthread_worker",
                                  "path",
                                  "security",
                                  "sid",
                                  "node",
                                  "func",
                                  "worker",
                                  "canceling"};
static struct btf* fake_btf_get(void) {
  assert(!ctl_active && !lock_depth);
  return native_btf;
}
static int fake_btf_find(const struct btf* btf, const char* name, unsigned char kind) {
  assert(btf == &test_btf && kind == 4);
  for (int i = 1; i <= 5; i++)
    if (!strcmp(name, btf_names[i]))
      return i == btf_missing ? -ENOENT : i;
  return -ENOENT;
}
static const struct btf_type* fake_btf_type(const struct btf* btf, u32 id) {
  assert(btf == &test_btf && id < 11);
  return &btf_records[id].type;
}
static const char* fake_btf_name(const struct btf* btf, u32 offset) {
  assert(btf == &test_btf && offset < sizeof(btf_names) / sizeof(btf_names[0]));
  return btf_names[offset];
}
static const struct btf_type* fake_btf_size(const struct btf* btf, const struct btf_type* type, u32* size) {
  assert(btf == &test_btf);
  for (unsigned int depth = 0; depth < 32; depth++) {
    u32 kind = (type->info >> 24) & 31;
    if (kind == 8) {
      type = fake_btf_type(btf, type->size);
      continue;
    }
    if (kind == 2 || kind == 1 || kind == 4) {
      *size = kind == 2 ? 8 : type->size;
      return type;
    }
    return ERR_PTR(-EINVAL);
  }
  return ERR_PTR(-EINVAL);
}
static void fake_task_getsecid(struct task_struct* task, u32* sid) {
  assert(task == &initial_task);
  *sid = getter_error ? 99 : kernel_cred.context;
}
static void* fake_kmalloc(size_t size, gfp_t flags) {
  assert(size == 40 && flags == 0 && !legacy_heap);
  if (legacy_alloc_fail)
    return NULL;
  legacy_heap = malloc(size);
  assert(legacy_heap);
  memset(legacy_heap, 0xa5, size);
  legacy_allocs++;
  return legacy_heap;
}
static void fake_kfree(const void* ptr) {
  assert(ptr == legacy_heap);
  free(legacy_heap);
  legacy_heap = NULL;
  legacy_frees++;
}
static void fake_init_worker(struct kthread_worker* owner, const char* name, struct lock_class_key* key) {
  assert(owner == legacy_heap && !strcmp(name, "run_cmd_demo") && !key);
  for (size_t i = 0; i < 40; i++) assert(((unsigned char*)owner)[i] == 0);
}
static int fake_worker_fn(void* data) {
  assert(data == legacy_heap);
  return 0;
}
static struct task_struct* fake_create_thread(int (*fn)(void*), void* data, int node, const char* name, ...) {
  assert(fn == fake_worker_fn && data == legacy_heap && node == -1 && !strcmp(name, "run_cmd_demo"));
  return legacy_thread_fail ? ERR_PTR(-ENOMEM) : &initial_task;
}
static int fake_wake(struct task_struct* task) {
  assert(task == &initial_task);
  return 1;
}
static bool fake_legacy_queue(struct kthread_worker* owner, struct kthread_work* work) {
  assert(owner == legacy_heap && work == &cmd_work && !queued_work && !lock_depth);
  queued_work = work;
  return true;
}
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { return (uintptr_t)lookup(name); }
static void* lookup(const char* name) {
  if (missing && !strcmp(name, missing))
    return NULL;
  if (!strcmp(name, "call_usermodehelper_exec"))
    return entry;
  if (!strcmp(name, "call_usermodehelper_setup"))
    return fake_setup;
  if (!strcmp(name, "prepare_kernel_cred"))
    return fake_prepare_kernel_cred;
  if (!strcmp(name, "security_secctx_to_secid"))
    return fake_secctx_to_secid;
  if (!strcmp(name, "selinux_cred_getsecid"))
    return legacy_api ? NULL : sid_entry;
  if (!strcmp(name, "init_task"))
    return &initial_task;
  if (!strcmp(name, "selinux_blob_sizes"))
    return &blob_offset;
  if (!strcmp(name, "abort_creds"))
    return fake_abort_creds;
  if (!strcmp(name, "security_transfer_creds"))
    return fake_transfer;
  if (!strcmp(name, "override_creds"))
    return fake_override_creds;
  if (!strcmp(name, "revert_creds"))
    return fake_revert_creds;
  if (!strcmp(name, "kthread_create_worker"))
    return legacy_api ? NULL : fake_create_worker;
  if (!strcmp(name, "kthread_queue_work"))
    return legacy_api ? NULL : fake_queue_work;
  if (!strcmp(name, "filp_open"))
    return fake_filp_open;
  if (!strcmp(name, "replace_fd"))
    return fake_replace_fd;
  if (!strcmp(name, "filp_close"))
    return fake_filp_close;
  if (!strcmp(name, "selinux_task_getsecid"))
    return legacy_api ? task_sid_entry : NULL;
  if (!strcmp(name, "__init_kthread_worker"))
    return legacy_api ? worker_entry : NULL;
  if (!strcmp(name, "kthread_worker_fn"))
    return legacy_api ? fake_worker_fn : NULL;
  if (!strcmp(name, "kthread_create_on_node"))
    return legacy_api ? fake_create_thread : NULL;
  if (!strcmp(name, "wake_up_process"))
    return legacy_api ? fake_wake : NULL;
  if (!strcmp(name, "__kmalloc"))
    return legacy_api ? fake_kmalloc : NULL;
  if (!strcmp(name, "kfree"))
    return legacy_api ? fake_kfree : NULL;
  if (!strcmp(name, "queue_kthread_work"))
    return legacy_api ? fake_legacy_queue : NULL;
  if (!strcmp(name, "__lockdep_no_validate__") || !strcmp(name, "lockdep_init_map"))
    return NULL;
  if (!strcmp(name, "bpf_get_btf_vmlinux"))
    return use_btf ? fake_btf_get : NULL;
  if (!strcmp(name, "btf_find_by_name_kind"))
    return use_btf ? fake_btf_find : NULL;
  if (!strcmp(name, "btf_type_by_id"))
    return use_btf ? fake_btf_type : NULL;
  if (!strcmp(name, "btf_name_by_offset"))
    return use_btf ? fake_btf_name : NULL;
  if (!strcmp(name, "btf_resolve_size"))
    return use_btf ? fake_btf_size : NULL;
  assert(0);
  return NULL;
}
static void reset(void) {
  legacy_api = use_btf = btf_missing = legacy_alloc_fail = legacy_thread_fail = 0;
  legacy_worker_size = -1;
  cmd_btf = NULL;
  native_btf = &test_btf;
  alloc_fail = cred_fail = worker_fail = queue_fail = exec_ret = setup_calls = copied = copy_short = ran = 0;
  caller.context = 3;
  kernel_cred.context = 1;
  sid_error = sid_zero = getter_error = 0;
  cred_sid_offset = -1;
  cred_security_offset = -1;
  cred_offset.security_offset = offsetof(struct cred, security);
  blob_offset = 0;
  for (unsigned int i = 0; i < 32; i++) sid_entry[i] = 0xd503201f;
  sid_entry[2] = 0xf9400008 | ((offsetof(struct cred, security) / 8) << 10);
  sid_entry[3] = 0xb9400108;
  sid_entry[4] = 0xb9000028;
  sid_entry[5] = 0xd65f03c0;
  prepare_ret = 0;
  missing = NULL;
  subprocess_info_path_offset = -1;
  for (unsigned int i = 0; i < 64; i++) entry[i] = 0xd503201f;
  entry[2] = 0xf9401c09;
  entry[5] = 0xb4000029;
}
static void offsets(void) {
  reset();
  assert(prepare_run_cmd() == 0 && subprocess_info_path_offset == offsetof(struct subprocess_info, path));
  reset();
  entry[0] = 0x14000002;  // 跳板，目标仍在同一夹具内。
  assert(prepare_run_cmd() == 0 && subprocess_info_path_offset == 0x38);
  reset();
  entry[5] = 0xb4000028;  // CBZ 寄存器不对应，后续候选不能补救首个错误。
  entry[7] = 0xf940240a;
  entry[8] = 0xb400002a;
  assert(prepare_run_cmd() == -ENOENT && subprocess_info_path_offset == -1);
  reset();
  entry[2] = 0xb9401c09;  // 32 位读取不是 path。
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[5] = 0x34000029;  // 32 位 CBZ 不接受。
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[0] = 0xd65f03c0;  // RET 之后的候选不扫描。
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[2] = entry[5] = 0xd503201f;
  entry[32] = 0xf9401c09;
  entry[33] = 0xb4000029;
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[2] = entry[5] = 0xd503201f;
  entry[31] = 0xf9401c09;
  entry[32] = 0xb4000029;
  assert(prepare_run_cmd() == -ENOENT);
  const char* names[] = {"call_usermodehelper_setup", "call_usermodehelper_exec", "prepare_kernel_cred", "abort_creds",
                         "security_transfer_creds",   "kthread_create_worker",    "kthread_queue_work"};
  for (unsigned int i = 0; i < 7; i++) {
    reset();
    missing = names[i];
    assert(prepare_run_cmd() == -ENOENT);
  }
  assert(inst_is_b(0x14000000) && !inst_is_b(0x94000000));
  assert(inst_get_b_label(0x14000001) == 4 && inst_get_b_label(0x17ffffff) == -4);
  assert(inst_get_b_label(0x15ffffff) == 0x7fffffc && inst_get_b_label(0x16000000) == -0x8000000);
  assert(inst_get_b_label(0x94000000) == -1);
}
static void sid_offsets(void) {
  reset();
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0);
  sid_entry[0] = 0x14000002;
  cred_sid_offset = -1;
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0);
  reset();
  sid_entry[4] = 0xb9000008;  // 写出地址不是 x1。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  sid_entry[3] = 0xb9400128;  // SID 基址寄存器不对应。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  sid_entry[4] = 0xf9000028;  // 输出不是 u32。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  sid_entry[0] = 0xd65f03c0;
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  sid_entry[2] = 0xf9400008 | (((offsetof(struct cred, security) + 8) / 8) << 10);
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  sid_entry[2] = sid_entry[3] = sid_entry[4] = 0xd503201f;
  sid_entry[16] = 0xf9400008 | ((offsetof(struct cred, security) / 8) << 10);
  sid_entry[17] = 0xb9400108;
  sid_entry[18] = 0xb9000028;
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  sid_entry[4] = 0xb9000008;
  sid_entry[7] = sid_entry[2];
  sid_entry[8] = sid_entry[3];
  sid_entry[9] = 0xb9000028;
  assert(prepare_run_cmd() == -ENOENT);
  // 构造独立页中的 blob 全局，覆盖真实的 ADRP/LDRSW/ADD 路径。
  void* page;
  assert(posix_memalign(&page, 0x1000, 0x1000) == 0);
  uint32_t* code = page;
  int* blob = (int*)((char*)page + 0x800);
  const uint32_t words[] = {0xd503201f, 0x90000008, 0xf9400009 | ((offsetof(struct cred, security) / 8) << 10),
                            0xb9880108, 0x8b080128, 0xb9400508,
                            0xb9000028, 0xd65f03c0};
  memcpy(code, words, sizeof(words));
  assert(fake_prepare_run_cmd() == 0);
  kfunc(call_usermodehelper_exec) = (typeof(kfunc(call_usermodehelper_exec)))entry;
  kfunc(selinux_cred_getsecid) = (typeof(kfunc(selinux_cred_getsecid)))code;
  kvar(selinux_blob_sizes) = blob;
  *blob = 16;
  cred_sid_offset = -1;
  assert(calculate_offsets() == 0 && cred_sid_offset == 20);
  cred_offset.security_offset = -1;
  cred_security_offset = cred_sid_offset = -1;
  assert(calculate_offsets() == 0 && cred_sid_offset == 20);
  assert(cred_security_offset == offsetof(struct cred, security) && cred_offset.security_offset == -1);
  cred_offset.security_offset = offsetof(struct cred, security);
  *blob = 0;
  cred_sid_offset = -1;
  assert(calculate_offsets() == 0 && cred_sid_offset == 4);
  *blob = -1;
  cred_sid_offset = -1;
  assert(calculate_offsets() == -ENOENT && cred_sid_offset == -1);
  *blob = 0;
  kvar(selinux_blob_sizes) = blob + 1;
  assert(calculate_offsets() == -ENOENT);
  kvar(selinux_blob_sizes) = NULL;
  assert(calculate_offsets() == -ENOENT);
  kvar(selinux_blob_sizes) = blob;
  code[4] ^= 1U << 16;  // ADD 的 blob 寄存器不对应。
  assert(calculate_offsets() == -ENOENT);
  free(page);
}
static void missing_kp_security(void) {
  reset();
  cred_offset.security_offset = -1;
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0);
  assert(cred_security_offset == offsetof(struct cred, security) && cred_offset.security_offset == -1);
  reset();
  cred_offset.security_offset = -1;
  sid_entry[4] = 0xb9000008;
  assert(prepare_run_cmd() == -ENOENT && cred_security_offset == -1 && cred_sid_offset == -1);
  reset();
  cred_offset.security_offset = -1;
  sid_entry[3] = 0xb9400128;
  assert(prepare_run_cmd() == -ENOENT && cred_security_offset == -1 && cred_sid_offset == -1);
  reset();
  cred_offset.security_offset = -1;
  sid_entry[0] = 0xd65f03c0;
  assert(prepare_run_cmd() == -ENOENT && cred_security_offset == -1 && cred_sid_offset == -1);
}
static long control(const char* args, char* out, int size) {
  ctl_active = 1;
  long ret = run_cmd_control0(args, out, size);
  ctl_active = 0;
  return ret;
}
static void finish_work(void) {
  assert(queued_work && !ctl_active);
  struct kthread_work* work = queued_work;
  queued_work = NULL;
  work->func(work);
}

static void btf_fixture(void) {
  memset(btf_records, 0, sizeof(btf_records));
  for (int i = 1; i <= 5; i++) btf_records[i].type.info = (4U << 24) | 1;
  btf_records[1].type.size = sizeof(struct subprocess_info);
  btf_records[1].members[0] = (struct btf_member){6, 6, 0x38 * 8};
  btf_records[2].type.size = sizeof(struct cred);
  btf_records[2].members[0] = (struct btf_member){7, 6, offsetof(struct cred, security) * 8};
  btf_records[3].type.size = 4;
  btf_records[3].members[0] = (struct btf_member){8, 9, 0};
  btf_records[4].type.size = 40;
  btf_records[4].type.info = (4U << 24) | 4;
  btf_records[4].members[0] = (struct btf_member){9, 8, 0};
  btf_records[4].members[1] = (struct btf_member){10, 10, 16 * 8};
  btf_records[4].members[2] = (struct btf_member){11, 6, 24 * 8};
  btf_records[4].members[3] = (struct btf_member){12, 7, 32 * 8};
  btf_records[5].type.size = 40;
  btf_records[5].type.info = 4U << 24;
  btf_records[6].type.info = 2U << 24;
  btf_records[7].type.info = 1U << 24;
  btf_records[7].type.size = 4;
  btf_records[8].type.info = 4U << 24;
  btf_records[9].type.info = btf_records[10].type.info = 8U << 24;
  btf_records[9].type.size = 7;
  btf_records[10].type.size = 6;
  btf_records[8].type.size = 16;
}
static void legacy_fixture(void) {
  legacy_api = 1;
  for (int i = 0; i < 32; i++) worker_entry[i] = task_sid_entry[i] = 0xd503201f;
  const uint32_t words[] = {0x91002001, 0x7900001f, 0x7900041f, 0xf9000401, 0xf9000421, 0xf9000c1f, 0xd65f03c0};
  memcpy(worker_entry, words, sizeof(words));
  task_sid_entry[2] = 0xf9400008 | ((task_struct_offset.real_cred_offset / 8) << 10);
  task_sid_entry[3] = 0xf9400108 | ((offsetof(struct cred, security) / 8) << 10);
  task_sid_entry[4] = 0xb9400109;
  task_sid_entry[6] = 0xb9000029;
  task_sid_entry[7] = 0xd65f03c0;
}
static void legacy_cred_slots(void) {
  task_struct_offset.cred_offset = 0x88;
  for (int slot = 0; slot < 2; slot++) {
    reset();
    legacy_fixture();
    int offset = slot ? task_struct_offset.cred_offset : task_struct_offset.real_cred_offset;
    task_sid_entry[2] = 0xf9400008 | ((offset / 8) << 10);
    assert(prepare_run_cmd() == 0 && cred_security_offset == offsetof(struct cred, security)
           && cred_sid_offset == 0);
  }
  reset();
  legacy_fixture();
  task_sid_entry[2] = 0xf9400008 | ((0x90 / 8) << 10);  // 两个槽位以外的字段。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  task_sid_entry[2] = 0xf9400008 | ((task_struct_offset.cred_offset / 8) << 10);
  task_sid_entry[3] ^= 1U << 5;  // security 的基址不再来自凭据指针。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  task_sid_entry[2] = 0xf9400008 | ((task_struct_offset.cred_offset / 8) << 10);
  task_sid_entry[6] = 0xb9000009;  // SID 没有写入输出参数。
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  task_sid_entry[2] = 0xf9400008 | ((task_struct_offset.cred_offset / 8) << 10);
  cred_offset.security_offset += 8;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  for (int i = 0; i < 16; i++) task_sid_entry[i] = 0xd503201f;
  task_sid_entry[16] = 0xf9400008 | ((task_struct_offset.cred_offset / 8) << 10);
  task_sid_entry[17] = 0xf9400108 | ((offsetof(struct cred, security) / 8) << 10);
  task_sid_entry[18] = 0xb9400109;
  task_sid_entry[19] = 0xb9000029;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  task_struct_offset.cred_offset = -1;
  reset();
}
static void compat_offsets(void) {
  reset();
  entry[5] = 0xb5000029;
  assert(prepare_run_cmd() == 0 && subprocess_info_path_offset == 0x38);
  reset();
  entry[5] = 0xd503201f;
  entry[11] = 0xb4000029;
  assert(prepare_run_cmd() == 0);
  reset();
  entry[3] = 0x91000429;  // add x9,x1,#1 覆盖 path。
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[3] = 0xa9812121;  // stp x1,x8,[x9,#16]! 改写 path 基址。
  assert(prepare_run_cmd() == -ENOENT);
  reset();
  entry[3] = 0xa9012121;  // 即使未回写，也不接纳 path 基址的配对存储。
  assert(prepare_run_cmd() == -ENOENT);
  assert(inst_is_stp_imm(0xa90123e8) && inst_is_stp_imm(0x290123e8) && !inst_is_stp_imm(0xa88123e8));
  assert(!inst_is_stp_imm(0xa80123e8) && !inst_is_stp_imm(0xa98123e8));
  assert(!inst_is_stp_imm(0xa94123e8) && !inst_is_stp_imm(0xad0123e8) && !inst_is_stp_imm(0x694123e8));
  assert(inst_is_cbnz(0xb5000029) && inst_get_cbnz_sf(0xb5000029) == 1 && inst_get_cbnz_rt(0xb5000029) == 9);
  assert(inst_get_cbnz_imm19(0xb5ffffe9) == 0x7ffff && !inst_is_cbnz(0xb4000029));
  reset();
  legacy_fixture();
  assert(prepare_run_cmd() == 0 && legacy_worker_size == 40 && cred_sid_offset == 0);
  const char* names[] = {"__init_kthread_worker",
                         "kthread_worker_fn",
                         "kthread_create_on_node",
                         "wake_up_process",
                         "__kmalloc",
                         "kfree",
                         "queue_kthread_work",
                         "selinux_task_getsecid"};
  for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    reset();
    legacy_fixture();
    missing = names[i];
    assert(prepare_run_cmd() == -ENOENT);
  }
  reset();
  legacy_fixture();
  worker_entry[4] ^= 1U;
  assert(prepare_run_cmd() == -ENOENT && legacy_worker_size == -1);
  reset();
  legacy_fixture();
  task_sid_entry[2] ^= 1U << 10;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  task_sid_entry[6] = 0xb9000009;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  legacy_fixture();
  assert(prepare_run_cmd() == 0);
  kfunc(__init_kthread_worker) = fake_init_worker;
  legacy_alloc_fail = 1;
  assert(PTR_ERR(create_cmd_worker()) == -ENOMEM && !legacy_heap);
  legacy_alloc_fail = 0;
  legacy_thread_fail = 1;
  assert(PTR_ERR(create_cmd_worker()) == -ENOMEM && !legacy_heap && legacy_allocs == legacy_frees);
  legacy_thread_fail = 0;
  assert(create_cmd_worker() == legacy_heap && legacy_heap);
  fake_kfree(legacy_heap);
  assert(legacy_allocs == legacy_frees);
  reset();
  btf_fixture();
  use_btf = 1;
  entry[0] = sid_entry[0] = 0xd65f03c0;  // 完整 BTF 不扫描指令。
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0 && subprocess_info_path_offset == 0x38);
  reset();
  btf_fixture();
  use_btf = 1;
  btf_missing = 3;
  sid_entry[4] = 0xb9000008;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1 && cred_security_offset == -1);
  reset();
  btf_fixture();
  use_btf = 1;
  btf_missing = 3;
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0);
  reset();
  btf_fixture();
  use_btf = 1;
  btf_records[1].members[0].offset |= 1;
  assert(prepare_run_cmd() == 0 && subprocess_info_path_offset == 0x38);  // 缺失字段走完整指令链。
  reset();
  btf_fixture();
  use_btf = 1;
  btf_records[3].type.info |= 1U << 31;
  btf_records[3].members[0].offset |= 4U << 24;
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 0);  // bitfield 不作为 SID。
  reset();
  btf_fixture();
  use_btf = 1;
  btf_records[4].members[3].offset = 36 * 8;
  assert(prepare_run_cmd() == -EINVAL);
  reset();
  btf_fixture();
  use_btf = 1;
  cred_offset.security_offset += 8;
  assert(prepare_run_cmd() == -EINVAL);
  reset();
  btf_fixture();
  use_btf = 1;
  blob_offset = 16;
  assert(prepare_run_cmd() == 0 && cred_sid_offset == 16);
  reset();
  btf_fixture();
  use_btf = 1;
  native_btf = ERR_PTR(-ENOENT);
  assert(prepare_run_cmd() == 0 && !cmd_btf);
  reset();
  btf_fixture();
  use_btf = 1;
  btf_records[9].type.info = 12U << 24;  // 不可求尺寸的类型，原生 API 返回 ERR_PTR。
  sid_entry[4] = 0xb9000008;
  assert(prepare_run_cmd() == -ENOENT && cred_sid_offset == -1);
  reset();
  btf_fixture();
  use_btf = 1;
  native_btf = NULL;
  assert(prepare_run_cmd() == 0 && !cmd_btf);
  reset();
  btf_fixture();
  use_btf = 1;
  legacy_fixture();
  worker_entry[0] = 0xd65f03c0;
  assert(prepare_run_cmd() == 0 && legacy_worker_size == 40);  // BTF 包括旧 worker 尺寸。
  reset();
}

static void legacy_execution(void) {
  reset();
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    legacy_api = 1;
    getter_error = 1;
    assert(run_cmd_init(NULL, NULL, NULL) == -EINVAL && !cmd_worker && live_creds == 1);
    assert(run_cmd_exit(NULL) == 0 && !live_creds);
    getter_error = 0;
    assert(run_cmd_init("legacy command", NULL, NULL) == 0 && snapshot.context == 3 && queued_work);
    finish_work();
    assert(!strcmp(observed, "legacy command") && !queued_work && cmd_result == 0);
    char reply[RUN_CMD_REPLY_SIZE];
    assert(control("legacy next", reply, sizeof(reply)) == 0 && queued_work);
    finish_work();
    assert(!strcmp(observed, "legacy next") && run_cmd_exit(NULL) == -EBUSY);
    _exit(0);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && status == 0);
  reset();
}
int main(void) {
  compat_offsets();
  legacy_cred_slots();
  legacy_execution();
  offsets();
  sid_offsets();
  missing_kp_security();
  reset();
  prepare_ret = -ENOENT;
  assert(run_cmd_init(NULL, NULL, NULL) == -ENOENT && !live_creds && !cmd_worker);
  assert(run_cmd_exit(NULL) == 0);
  prepare_ret = 0;
  char huge[RUN_CMD_MAX_SIZE + 1];
  memset(huge, 'a', sizeof(huge));
  huge[sizeof(huge) - 1] = 0;
  assert(run_cmd_init(huge, NULL, NULL) == -E2BIG && !live_creds);
  cred_fail = 1;
  assert(run_cmd_init(NULL, NULL, NULL) == -ENOMEM && !live_creds);
  assert(run_cmd_exit(NULL) == 0);
  cred_fail = 0;
  worker_fail = 1;
  assert(run_cmd_init(NULL, NULL, NULL) == -ENOMEM && live_creds == 1 && !cmd_worker);
  assert(run_cmd_exit(NULL) == 0 && !live_creds);
  worker_fail = 0;
  sid_error = -EINVAL;
  assert(run_cmd_init(NULL, NULL, NULL) == -EINVAL && !live_creds && !cmd_worker);
  sid_error = 0;
  sid_zero = 1;
  assert(run_cmd_init(NULL, NULL, NULL) == -EINVAL && !live_creds && !cmd_worker);
  sid_zero = 0;
  getter_error = 1;
  assert(run_cmd_init(NULL, NULL, NULL) == -EINVAL && live_creds == 1 && !cmd_worker);
  assert(run_cmd_exit(NULL) == 0 && !live_creds);
  getter_error = 0;
  caller.context = 29;  // UI 加载者与执行域须不同。
  for (int fail = 0; fail < 2; fail++) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
      queue_fail = fail;
      assert(run_cmd_init("initial command", NULL, NULL) == 0);
      if (fail) {
        assert(!queued_work && cmd_status == CMD_DONE && cmd_result == -EAGAIN);
      } else {
        assert(queued_work && !setup_calls);
        finish_work();
        assert(!strcmp(observed, "initial command"));
      }
      _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && status == 0);
  }
  cred_offset.security_offset = -1;
  assert(run_cmd_init(NULL, NULL, NULL) == 0 && live_creds == 1 && !queued_work);
  assert(cred_offset.security_offset == -1 && snapshot.context == 3);
  assert(snapshot.context == 3 && caller.context == 29 && kernel_cred.context == 1);
  const char* domain_names[] = {"prepare_kernel_cred", "security_secctx_to_secid", "selinux_cred_getsecid",
                                "init_task"};
  for (unsigned int i = 0; i < sizeof(domain_names) / sizeof(domain_names[0]); i++) {
    missing = domain_names[i];
    assert(prepare_run_cmd() == -ENOENT);
  }
  const char* stdio_names[] = {"filp_open", "replace_fd", "filp_close"};
  for (unsigned int i = 0; i < sizeof(stdio_names) / sizeof(stdio_names[0]); i++) {
    missing = stdio_names[i];
    assert(prepare_run_cmd() == -ENOENT);
  }
  missing = NULL;
  assert(prepare_run_cmd() == 0);
  assert(fake_prepare_run_cmd() == 0);
  struct cred helper_cred = {0};
  open_error = -EACCES;
  open_calls = replace_calls = close_calls = 0;
  assert(run_cmd_prepare(&helper, &helper_cred) == -EACCES);
  assert(open_calls == 1 && !replace_calls && !close_calls && null_file.refs == 0);
  open_error = 0;
  for (int fd = 0; fd < 3; fd++) {
    replace_error_fd = fd;
    open_calls = replace_calls = close_calls = 0;
    assert(run_cmd_prepare(&helper, &helper_cred) == -ENOMEM);
    assert(open_calls == 1 && replace_calls == fd + 1 && close_calls == 1 && null_file.refs == fd);
    helper_exit_files();
  }
  replace_error_fd = -1;
  open_calls = replace_calls = close_calls = 0;
  assert(run_cmd_prepare(&helper, &helper_cred) == 0);
  assert(open_calls == 1 && replace_calls == 3 && close_calls == 1 && null_file.refs == 3);
  assert(helper_cred.context == snapshot.context);
  helper_exit_files();
  const char* cred_names[] = {"override_creds", "revert_creds"};
  for (unsigned int i = 0; i < sizeof(cred_names) / sizeof(cred_names[0]); i++) {
    missing = cred_names[i];
    assert(prepare_run_cmd() == -ENOENT);
  }
  missing = NULL;
  assert(prepare_run_cmd() == 0);
  assert(fake_prepare_run_cmd() == 0);
  assert(override_calls == 5 && revert_calls == 5 && !override_depth && active_cred == &kernel_cred);
  char out[RUN_CMD_REPLY_SIZE];
  assert(control("result", out, sizeof(out)) == 0 && !strcmp(out, "idle\n"));
  assert(control(NULL, out, sizeof(out)) == -EINVAL);
  assert(control("", out, sizeof(out)) == -EINVAL);
  assert(control("exit 7", NULL, sizeof(out)) == -EINVAL);
  assert(control("exit 7", out, sizeof(out) - 1) == -EINVAL && !queued_work);
  assert(control("exit 7", out, -1) == -EINVAL);
  assert(control(huge, out, sizeof(out)) == -E2BIG && !queued_work);
  char command[] = "exit 7";
  assert(control(command, out, sizeof(out)) == 0 && !strcmp(out, "queued\n") && !setup_calls);
  memset(command, 'x', sizeof(command) - 1);
  assert(control("result", out, sizeof(out)) == -EINPROGRESS && !strcmp(out, "pending\n"));
  assert(control("echo replacement", out, sizeof(out)) == -EBUSY);
  exec_ret = 1792;
  finish_work();
  assert(control("result", out, sizeof(out)) == 1792 && !strcmp(out, "ret=1792\n"));
  assert(!strcmp(observed, "exit 7") && setup_calls == 1 && live_creds == 1);
  caller.context = 99;
  const int statuses[] = {0, -ENOMEM, -EACCES, -ENOENT, 1792};
  for (unsigned int i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
    exec_ret = statuses[i];
    assert(control("echo next", out, sizeof(out)) == 0 && !strcmp(out, "queued\n"));
    finish_work();
    memset(out, 0x5a, sizeof(out));
    assert(control("result", out, sizeof(out)) == statuses[i]);
    assert(copied == (int)strlen(out) + 1);
    for (unsigned int j = copied; j < sizeof(out); j++) assert(out[j] == 0x5a);
    assert(snapshot.context == 3 && live_creds == 1);
  }
  alloc_fail = 1;
  assert(control("echo alloc", out, sizeof(out)) == 0);
  int previous = ran;
  finish_work();
  assert(control("result", out, sizeof(out)) == -ENOMEM && ran == previous);
  alloc_fail = 0;
  queue_fail = 1;
  assert(control("echo queue", out, sizeof(out)) == -EAGAIN && !queued_work);
  assert(control("result", out, sizeof(out)) == -EAGAIN);
  queue_fail = 0;
  copy_short = 1;
  assert(control("echo copy", out, sizeof(out)) == -EFAULT && queued_work);
  copy_short = 0;
  exec_ret = 0;
  finish_work();
  assert(control("result", out, sizeof(out)) == 0);
  assert(run_cmd_exit(NULL) == -EBUSY && live_creds == 1);
  assert(!lock_depth && !queued_work);
  assert(override_calls == revert_calls && !override_depth && active_cred == &kernel_cred);
  puts("run_cmd production async/credential/offset tests passed");
  return 0;
}
