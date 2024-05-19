#ifndef __HR_HOSTS_REDIRECT_H
#define __HR_HOSTS_REDIRECT_H

#include <ktypes.h>
#include <linux/llist.h>
#include <linux/spinlock.h>

#define HASH_LEN_DECLARE u32 hash; u32 len
#define DNAME_INLINE_LEN 32
#define LOOKUP_FOLLOW 0x0001

struct vfsmount {
  struct dentry* mnt_root;
  struct super_block* mnt_sb;
  int mnt_flags;
  struct user_namespace* mnt_userns;
  // unknow
};
struct hlist_bl_node {
  struct hlist_bl_node* next, ** pprev;
};
struct qstr {
  union {
    struct {
      HASH_LEN_DECLARE;
    };
    u64 hash_len;
  };
  const unsigned char* name;
};
struct dentry {
  unsigned int d_flags;
  spinlock_t d_seq;
  struct hlist_bl_node d_hash;
  struct dentry* d_parent;
  struct qstr d_name;
  struct inode* d_inode;
  unsigned char d_iname[DNAME_INLINE_LEN];
  // unknow
};

struct path {
  struct vfsmount* mnt;
  struct dentry* dentry;
};

struct file {
  union {
    struct llist_node    fu_llist;
    struct rcu_head      fu_rcuhead;
  } f_u;
  struct path     f_path;
  struct inode* f_inode;
  // unknow
};

struct fs_struct {
  int users;
  spinlock_t lock;
  spinlock_t seq;
  int umask;
  int in_exec;
  struct path root, pwd;
};

struct open_flags {
  int open_flag;
  umode_t mode;
  int acc_mode;
  int intent;
  int lookup_flags;
};

#endif /* __HR_HOSTS_REDIRECT_H */
