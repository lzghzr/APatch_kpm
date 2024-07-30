#ifndef __CGROUP_FREEZE_H
#define __CGROUP_FREEZE_H

#include <ktypes.h>
#include <linux/thread_info.h>

// KernelPatch/kernel/linux/include/linux/bitops.h
#define BITS_PER_LONG 64
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

static inline void set_bit(int nr, volatile unsigned long* addr) {
  unsigned long mask = BIT_MASK(nr);
  unsigned long* p = ((unsigned long*)addr) + BIT_WORD(nr);
  *p |= mask;
}

static inline void clear_bit(int nr, volatile unsigned long* addr) {
  unsigned long mask = BIT_MASK(nr);
  unsigned long* p = ((unsigned long*)addr) + BIT_WORD(nr);
  *p &= ~mask;
}

static inline int test_bit(int nr, const volatile unsigned long* addr) {
  return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1)));
}

// linux/thread_info.h
static inline void set_ti_thread_flag(struct thread_info* ti, int flag) {
  set_bit(flag, (unsigned long*)&ti->flags);
}

static inline void clear_ti_thread_flag(struct thread_info* ti, int flag) {
  clear_bit(flag, (unsigned long*)&ti->flags);
}

#define set_thread_flag(flag) \
  set_ti_thread_flag(current_thread_info(), flag)

#define clear_thread_flag(flag) \
  clear_ti_thread_flag(current_thread_info(), flag)

#define css_for_each_descendant_pre(pos, css)               \
  for ((pos) = css_next_descendant_pre(NULL, (css)); (pos); \
       (pos) = css_next_descendant_pre((pos), (css)))

// linux/lockdep.h
struct lock_class_key;
// linux/signal.h
struct ksignal;

// linux/sched.h
#define PF_KTHREAD 0x00200000
#define PF_FREEZER_SKIP 0x40000000

#define TASK_INTERRUPTIBLE 0x0001

#define SIGNAL_GROUP_EXIT 0x00000004

#define JOBCTL_STOP_PENDING_BIT 17
#define JOBCTL_TRAP_STOP_BIT 19
#define JOBCTL_TRAP_NOTIFY_BIT 20
#define JOBCTL_TRAP_FREEZE_BIT 23

#define JOBCTL_STOP_PENDING (1UL << JOBCTL_STOP_PENDING_BIT)
#define JOBCTL_TRAP_STOP (1UL << JOBCTL_TRAP_STOP_BIT)
#define JOBCTL_TRAP_NOTIFY (1UL << JOBCTL_TRAP_NOTIFY_BIT)
#define JOBCTL_TRAP_FREEZE (1UL << JOBCTL_TRAP_FREEZE_BIT)

#define JOBCTL_TRAP_MASK (JOBCTL_TRAP_STOP | JOBCTL_TRAP_NOTIFY)
#define JOBCTL_PENDING_MASK (JOBCTL_STOP_PENDING | JOBCTL_TRAP_MASK)

struct signal_struct;

struct task_struct {
  unsigned int __state;
  // unknow
};

// linux/cgroup.h
struct css_task_iter {
  struct cgroup_subsys* ss;
  unsigned int flags;
  struct list_head* cset_pos;
  struct list_head* cset_head;
  struct list_head* tcset_pos;
  struct list_head* tcset_head;
  struct list_head* task_pos;
  struct list_head* tasks_head;
  struct list_head* mg_tasks_head;
  struct list_head* dying_tasks_head;
  struct list_head* cur_tasks_head;
  struct css_set* cur_cset;
  struct css_set* cur_dcset;
  struct task_struct* cur_task;
  struct list_head iters_node;
  // unknow
};

// asm-generic/atomic-long.h
typedef atomic_t atomic_long_t;
// linux/mutex.h
struct mutex {
  atomic_long_t owner;
  spinlock_t wait_lock;
  struct list_head wait_list;
  // unknow
};
// linux/seq_file.h
struct seq_file {
  char* buf;
  size_t size;
  size_t from;
  size_t count;
  size_t pad_until;
  loff_t index;
  loff_t read_pos;
  u64 version;
  struct mutex lock;
  // unknow
};

// linux/rbtree.h
struct rb_node {
  unsigned long __rb_parent_color;
  struct rb_node* rb_right;
  struct rb_node* rb_left;
} __attribute__((aligned(sizeof(long))));

// linux/kernfs.h
struct kernfs_node {
  atomic_t count;
  atomic_t active;
  struct kernfs_node* parent;
  const char* name;
  struct rb_node rb;
  const void* ns;
  unsigned int hash;
  // unknow
};
struct kernfs_open_file {
  struct kernfs_node* kn;
  struct file* file;
  void* priv;
  struct mutex mutex;
  int event;
  struct list_head list;
  char* prealloc_buf;
  size_t atomic_write_len;
  bool mmapped;
  const struct vm_operations_struct* vm_ops;
};

// linux/uidgid.h
#define KUIDT_INIT(value) (kuid_t){ value }
#define KGIDT_INIT(value) (kgid_t){ value }

// linux/time64.h
typedef __s64 time64_t;
struct timespec64 {
  time64_t tv_sec;
  long tv_nsec;
};

// linux/fs.h
struct iattr {
  unsigned int ia_valid;
  umode_t ia_mode;
  kuid_t ia_uid;
  kgid_t ia_gid;
  loff_t ia_size;
  struct timespec64 ia_atime;
  struct timespec64 ia_mtime;
  struct timespec64 ia_ctime;
  struct file* ia_file;
};

// linux/cgroup-defs.h
enum {
  CGRP_NOTIFY_ON_RELEASE,
  CGRP_CPUSET_CLONE_CHILDREN,
  CGRP_FREEZE,
  CGRP_FROZEN,
};

struct cgroup_subsys_state {
  struct cgroup* cgroup;
  struct cgroup_subsys* ss;
  // unknow
};

struct cgroup {
  struct cgroup_subsys_state self;
  unsigned long flags;
  // unknow
};

enum {
  CFTYPE_ONLY_ON_ROOT = (1 << 0),
  CFTYPE_NOT_ON_ROOT = (1 << 1),
};

#define MAX_CFTYPE_NAME 64

struct poll_table_struct;
struct cftype {
  char name[MAX_CFTYPE_NAME];
  unsigned long private;
  size_t max_write_len;
  unsigned int flags;
  unsigned int file_offset;
  struct cgroup_subsys* ss;
  struct list_head node;
  struct kernfs_ops* kf_ops;
  int (*open)(struct kernfs_open_file* of); // unknow v4
  void (*release)(struct kernfs_open_file* of);  // unknow v4
  // u64(*read_u64)(struct cgroup_subsys_state* css, struct cftype* cft);
  int (*seq_show_v4)(struct seq_file* sf, void* v);
  s64(*read_s64)(struct cgroup_subsys_state* css, struct cftype* cft);
  int (*seq_show)(struct seq_file* sf, void* v);
  void* (*seq_start)(struct seq_file* sf, loff_t* ppos);
  void* (*seq_next)(struct seq_file* sf, void* v, loff_t* ppos);
  void (*seq_stop)(struct seq_file* sf, void* v);
  // int (*write_u64)(struct cgroup_subsys_state* css, struct cftype* cft, u64 val);
  ssize_t(*write_v4)(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off);
  int (*write_s64)(struct cgroup_subsys_state* css, struct cftype* cft, s64 val);
  ssize_t(*write)(struct kernfs_open_file* of, char* buf, size_t nbytes, loff_t off);
  unsigned int (*poll)(struct kernfs_open_file* of, struct poll_table_struct* pt);
};

// fs/internal.h
struct open_flags {
  int open_flag;
  umode_t mode;
  int acc_mode;
  int intent;
  int lookup_flags;
};

// security.h
struct selinux_state {
  bool disabled;
  bool enforcing;
  bool checkreqprot;
  bool initialized;
  // unknow
};

// linux/umh.h
struct subprocess_info;

#endif /* __CGROUP_FREEZE_H */
