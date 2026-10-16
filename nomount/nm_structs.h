/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __NM_STRUCTS_H
#define __NM_STRUCTS_H

struct inode;
struct super_block;
struct file;
struct kiocb;
struct iov_iter;
struct dentry;
struct mutex;
struct lock_class_key;
struct key;
struct key_type;
struct key_preparsed_payload;
struct kstat;
struct vfsmount;
struct user_namespace;
struct mnt_idmap;

// 已核对目标 BTF 的挂载前部；上下文成员仅在相应原生 ABI 下读取。
struct nm_mount_context_head {
  struct dentry* root;
  struct super_block* super;
  int flags;
  union {
    struct user_namespace* userns;
    struct mnt_idmap* idmap;
  } context;
};

// key_type 的共同前16字节；后续flags及回调位置由布局层取得。
struct nm_key_type_head {
  const char* name;
  unsigned long def_datalen;
};
struct nm_key_callbacks {
  int (*preparse)(struct key_preparsed_payload*);
  void (*free_preparse)(struct key_preparsed_payload*);
  int (*instantiate)(struct key*, struct key_preparsed_payload*);
};
// name/def_datalen、三个回调和link均为独立必备成员；总和只证明可读前缀，非sizeof(key_type)。
enum { NM_KEY_TYPE_PROBE_SIZE = sizeof(struct nm_key_type_head) + sizeof(struct nm_key_callbacks) + 2 * sizeof(void*) };
// key_preparsed_payload 中 data 与 datalen 连续；其起点跨版本变化。
struct nm_key_data {
  const void* data;
  unsigned long datalen;
};

// 完整无调试 mutex 定义；原生完整初始化必须匹配对应字段并直接返回。
struct nm_mutex_count {
  int count;
  u32 wait_lock;
  void* wait_next;
  void* wait_prev;
  void* owner;
  u32 osq;
};
struct nm_mutex_owner {
  unsigned long owner;
  u32 wait_lock;
  u32 osq;
  void* wait_next;
  void* wait_prev;
};

// 已对照首轮目标源码 7fc8455b2fa8 的 include/linux/fs.h 与目标访存。
// 只表示连续片段，不表示完整 inode 或 file_operations 的大小。
struct nm_inode_owner_prefix {
  u16 i_mode;
  u16 i_opflags;
  u32 i_uid;
  u32 i_gid;
  u32 i_flags;
};

// i_sb 的位置已有偏移；相邻的操作表和映射共用一个连续片段。
struct nm_inode_ops_mapping {
  const void* i_op;
  struct super_block* i_sb;
  void* i_mapping;
};

// ARM64 的 timespec / timespec64 均为两个 64 位字段。6.6 将 ctime 改为内部名称。
struct nm_timespec {
  int64_t seconds;
  int64_t nanoseconds;
};
struct nm_inode_size_times {
  int64_t i_size;
  struct nm_timespec i_atime;
  struct nm_timespec i_mtime;
  struct nm_timespec i_ctime;
};

// 止于 s_op 的共同前部；不包含后续锁和文件系统私有字段。
struct nm_super_head {
  void* list_next;
  void* list_prev;
  u32 s_dev;
  u8 s_blocksize_bits;
  unsigned long s_blocksize;
  int64_t s_maxbytes;
  void* s_type;
  const void* s_op;
};

// drop_inode／evict_inode／put_super在两目标声明中连续；只取其实际起点。
struct nm_super_lifecycle_ops {
  int (*drop_inode)(struct inode*);
  void (*evict_inode)(struct inode*);
  void (*put_super)(struct super_block*);
};

// 两个目标的 i_fop／i_flctx 连续，i_data 紧随其后；地址和完整尺寸另由入口核对。
struct nm_inode_file_locks {
  const void* i_fop;
  void* i_flctx;
};

// inode_unhashed 只检查 hlist_node 的 pprev；绝对起点从原生检查取得。
struct nm_hlist_node {
  void* next;
  void* pprev;
};

struct nm_file_inode_ops {
  struct inode* f_inode;
  const void* f_op;
};

struct nm_file_ops_head {
  void* owner;
  void* llseek;
};

// 4.4 / 4.9 / 4.14 / 4.19 / 5.15 / 6.6 的共同前部。
// 后续 iopoll、iterate 等字段会变化；只共用止于 write_iter 的片段。
struct nm_file_io_ops {
  void* owner;
  void* llseek;
  void* read;
  void* write;
  long (*read_iter)(struct kiocb*, struct iov_iter*);
  long (*write_iter)(struct kiocb*, struct iov_iter*);
};

// 两目标的 iterate 紧随共同IO前部；shared成员是否存在另由原生枚举入口核对。
struct nm_file_iteration_ops {
  struct nm_file_io_ops io;
  void* iterate;
  void* iterate_shared;
};

// ki_complete 只作 NULL 检查，不调用；其回调签名在后续内核有变化。
struct nm_kiocb_head {
  struct file* ki_filp;
  int64_t ki_pos;
  void* ki_complete;
};

struct nm_file_flags_mode {
  u32 f_flags;
  u32 f_mode;
};

// path.h / dcache.h 的共同前部。BTF 可用时，逐字段核对后使用。
struct nm_path {
  void* mnt;
  void* dentry;
};

// f_path 紧邻已有 f_inode/f_op 片段；使用时以 f_inode 偏移向前定位。
struct nm_file_path_inode_ops {
  struct nm_path f_path;
  struct inode* f_inode;
  const void* f_op;
};

struct nm_qstr {
  u32 hash;
  u32 len;
  const char* name;
};

struct nm_dentry_head {
  u32 d_flags;
  u32 d_seq;
  void* hash_next;
  void* hash_pprev;
  void* d_parent;
  struct nm_qstr d_name;
  struct inode* d_inode;
};

struct nm_dentry_ops_data {
  const void* d_op;
  struct super_block* d_sb;
  unsigned long d_time;
  void* d_fsdata;
};

// spinlock为4字节时，lockref的lock/count紧邻d_op；完整mutex入口先确认锁形态。
struct nm_dentry_lockref_ops {
  u32 lock;
  int count;
  const void* d_op;
};

struct nm_inode_lookup_ops {
  struct dentry* (*lookup)(struct inode*, struct dentry*, unsigned int);
};

struct nm_dentry_revalidation_ops {
  int (*d_revalidate)(struct dentry*, unsigned int);
  int (*d_weak_revalidate)(struct dentry*, unsigned int);
};

struct nm_dentry_control_ops {
  int (*d_revalidate)(struct dentry*, unsigned int);
  int (*d_weak_revalidate)(struct dentry*, unsigned int);
  void* d_hash;
  void* d_compare;
  void* d_delete;
};

// 两目标的release／prune连续；init的存在由原生prune槽与共同前部的关系核对。
struct nm_dentry_release_prune {
  void (*d_release)(struct dentry*);
  void (*d_prune)(struct dentry*);
};

// 已核对两套完整声明的末端连续片段；这里只描述槽布局，不调用这些void*。
// 片段保留自然对齐，完整inode/dentry表的64字节对齐由尺寸计算层单独处理。
struct nm_inode_acl_tail {
  void* getattr;
  void* listxattr;
  void* fiemap;
  void* update_time;
  void* atomic_open;
  void* tmpfile;
  void* set_acl;
  u64 reserved[4];
};
struct nm_inode_xattr_acl_tail {
  void* getattr;
  void* setxattr;
  void* getxattr;
  void* listxattr;
  void* removexattr;
  void* fiemap;
  void* update_time;
  void* atomic_open;
  void* tmpfile;
  void* set_acl;
};
struct nm_super_cache_tail {
  void* nr_cached_objects;
  void* free_cached_objects;
};
struct nm_super_drop_prefix {
  void* drop_inode;
  void* evict_inode;
  void* put_super;
  void* sync_fs;
  void* freeze_super;
  void* freeze_fs;
  void* thaw_super;
  void* unfreeze_fs;
  void* statfs;
  void* remount_fs;
};
// 两目标启用QUOTA；此片段明确包含三个quota槽，不适用于删去这些槽的声明。
struct nm_super_reporting_tail {
  void* show_options;
  void* show_options2;
  void* show_devname;
  void* show_path;
  void* show_stats;
  void* quota_read;
  void* quota_write;
  void* get_dquots;
  void* bdev_try_to_free_page;
  struct nm_super_cache_tail cache;
};
struct nm_super_mount_tail {
  struct nm_super_drop_prefix lifecycle;
  void* remount_fs2;
  void* clone_mnt_data;
  void* copy_mnt_data;
  void* umount_begin;
  struct nm_super_reporting_tail reporting;
};
struct nm_super_context_tail {
  struct nm_super_drop_prefix lifecycle;
  void* clone_mnt_data;
  void* copy_mnt_data;
  void* update_mnt_data;
  void* umount_begin;
  void* umount_end;
  struct nm_super_reporting_tail reporting;
  u64 reserved[4];
};
struct nm_dentry_canonical_tail {
  struct nm_dentry_release_prune lifecycle;
  void* iput;
  void* dname;
  void* automount;
  void* manage;
  void* real;
  void* canonical_path;
  u64 reserved[3];
};
struct nm_dentry_select_tail {
  struct nm_dentry_release_prune lifecycle;
  void* iput;
  void* dname;
  void* automount;
  void* manage;
  void* select_inode;
  void* real;
  void* canonical_path;
};
// 两份声明各至少有14个独立指针槽；只在这个已确认的前缀内找canonical回调。
enum { NM_DENTRY_TAIL_PROBE_SIZE = 14 * sizeof(void*) };

// 共同的16字节布局；actor返回类型由目标原型确认。
struct nm_dir_context {
  union {
    int (*actor)(struct nm_dir_context*, const char*, int, int64_t, u64, unsigned int);
    bool (*actor_bool)(struct nm_dir_context*, const char*, int, int64_t, u64, unsigned int);
  };
  int64_t pos;
};

enum nm_ops_kind {
  NM_FILE_OPS,
  NM_INODE_OPS,
  NM_SUPER_OPS,
  NM_DENTRY_OPS,
  NM_KEY_TYPE,
};

// 自建清零表的存储容量，不表示原生sizeof，也不用于读取原表。
// 已核对声明的ARM64保守上界：inode 256、dentry 192、key 200字节（含lockdep预算）。
enum { NM_OWNED_OPERATIONS_CAPACITY = 512 };

// include/linux/stat.h 的共同前部，止于 size；不外推时间与 blocks 布局。
struct nm_kstat_prefix {
  u32 result_mask;
  u16 mode;
  unsigned int nlink;
  u32 blksize;
  u64 attributes;
  u64 attributes_mask;
  u64 ino;
  u32 dev;
  u32 rdev;
  u32 uid;
  u32 gid;
  int64_t size;
};

// inode 编号位于开头的 kstat 连续片段；布局选择由目标证据取得。
struct nm_kstat_inode_first {
  u64 ino;
  u32 dev;
  u16 mode;
  unsigned int nlink;
  u32 uid;
  u32 gid;
  u32 rdev;
  int64_t size;
};

// 两种已核对的 kstat 时间／blocks 连续片段，用于核对 generic_fillattr 的目标位置。
struct nm_kstat_blocks {
  struct nm_kstat_prefix prefix;
  struct nm_timespec atime, mtime, ctime, btime;
  u64 blocks;
};
struct nm_kstat_inode_first_blocks {
  struct nm_kstat_inode_first prefix;
  struct nm_timespec atime, mtime, ctime;
  unsigned long blksize;
  u64 blocks;
};

#endif
