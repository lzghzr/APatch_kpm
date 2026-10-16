/* SPDX-License-Identifier: GPL-2.0-only */
/* File callbacks adapted from maxsteeel/nomount 1ded61dc908c511072162fa0bee44e6ccdb7b4c7. */
struct cred;
struct vm_area_struct;
struct pipe_inode_info;

static struct file* kfunc_def(nm_dentry_open)(const struct nm_path*, int, const struct cred*);
static void kfunc_def(nm_fput)(struct file*);
static int64_t kfunc_def(nm_vfs_llseek)(struct file*, int64_t, int);
static int kfunc_def(nm_readonly_mmap)(struct file*, struct vm_area_struct*);

// 完整 backing 引擎准备时安装原生权限检查；文件对象阶段可独立准备回调表。
static int (*nm_backing_open_permission)(const struct nm_path*);

static int nm_prepare_file_functions(void) {
  kfunc(nm_dentry_open) = (typeof(kfunc(nm_dentry_open)))kallsyms_lookup_name_by_suffix("dentry_open");
  kfunc(nm_fput) = (typeof(kfunc(nm_fput)))kallsyms_lookup_name_by_suffix("fput");
  kfunc(nm_vfs_llseek) = (typeof(kfunc(nm_vfs_llseek)))kallsyms_lookup_name_by_suffix("vfs_llseek");
  kfunc(nm_readonly_mmap) =
      (typeof(kfunc(nm_readonly_mmap)))kallsyms_lookup_name_by_suffix("generic_file_readonly_mmap");
  return kfunc(nm_dentry_open) && kfunc(nm_fput) && kfunc(nm_vfs_llseek) && kfunc(nm_readonly_mmap) ? 0 : -ENOENT;
}

static int nm_open(struct inode* inode, struct file* file) {
  if (nm_file_flags(file) & (03U | 01000U))  // O_ACCMODE / O_TRUNC：首轮只读。
    return -EROFS;
  struct nm_inode_info* info = nm_inode_private(inode);
  if (!info)
    return -ENODEV;
  if (info->flags & NM_FLAG_VIRTUAL_DIR) {
    nm_set_file_private(file, NULL);
    return 0;
  }
  if (!info->r_path.dentry)
    return -ENODEV;
  if (nm_backing_open_permission) {
    int rc = nm_backing_open_permission(&info->r_path);
    if (rc)
      return rc;
  }
  // 目标 asm-generic/fcntl.h：O_CREAT | O_EXCL | O_NOCTTY。
  struct file* backing =
      kfunc(nm_dentry_open)(&info->r_path, nm_file_flags(file) & ~(0100U | 0200U | 0400U), nm_file_cred(file));
  if (IS_ERR(backing))
    return PTR_ERR(backing);
  nm_set_file_private(file, backing);
  return 0;
}

static int nm_release(struct inode* inode, struct file* file) {
  struct file* backing = nm_file_private(file);
  nm_set_file_private(file, NULL);
  if (backing)
    kfunc(nm_fput)(backing);
  return 0;
}

static int64_t nm_llseek(struct file* file, int64_t offset, int whence) {
  struct file* backing = nm_file_private(file);
  if (!backing)
    return -EINVAL;
  *nm_file_position(backing) = *nm_file_position(file);
  int64_t rc = kfunc(nm_vfs_llseek)(backing, offset, whence);
  *nm_file_position(file) = *nm_file_position(backing);
  return rc;
}

static long nm_read_iter(struct kiocb* request, struct iov_iter* iter) {
  struct nm_kiocb_head* iocb = (void*)request;
  // 首轮只接同步请求。异步请求必须在交给 backing 前拒绝，不能事后撤销已排队的 I/O。
  if (iocb->ki_complete)
    return -EOPNOTSUPP;
  struct file* outer = iocb->ki_filp;
  struct file* backing = nm_file_private(outer);
  const struct nm_file_io_ops* ops = backing ? nm_file_ops(backing) : NULL;
  long (*callback)(struct kiocb*, struct iov_iter*) = ops ? ops->read_iter : NULL;
  if (!callback)
    return -EINVAL;
  iocb->ki_filp = backing;
  long rc = callback(request, iter);
  iocb->ki_filp = outer;
  return rc;
}

static int nm_mmap(struct file* file, struct vm_area_struct* area) {
  struct file* backing = nm_file_private(file);
  if (!backing || nm_file_mapping(file) != nm_file_mapping(backing))
    return -EINVAL;
  // 保留 outer file 的 VMA 引用和 backing 页缓存；原生 helper 拒绝共享可写映射。
  int rc = kfunc(nm_readonly_mmap)(file, area);
  if (!rc)
    nm_inode_mmap_ready(nm_file_inode(file));
  return rc;
}

static long nm_splice_read(struct file* file, int64_t* position, struct pipe_inode_info* pipe, unsigned long length,
                           unsigned int flags) {
  struct file* backing = nm_file_private(file);
  long (*callback)(struct file*, int64_t*, struct pipe_inode_info*, unsigned long, unsigned int) =
      backing ? nm_fop(backing, struct_offset.fop_splice_read) : NULL;
  return callback ? callback(backing, position, pipe, length, flags) : -EINVAL;
}
// 发布前构造完整目标尺寸的操作表；失败不发布，已发布表由模块驻留持有。
static void* nm_new_file_operations(void) {
  struct struct_offset offsets = struct_offset;
  int rc = nm_validate_file_offsets(&offsets);
  if (rc)
    return ERR_PTR(rc);
  void* table = nm_new_operations(NM_FILE_OPS, NULL);
  if (IS_ERR(table))
    return table;
  struct nm_file_io_ops* io = table;
  io->llseek = nm_llseek;
  io->read_iter = nm_read_iter;
  nm_set_fop(table, offsets.fop_open, nm_open);
  nm_set_fop(table, offsets.fop_release, nm_release);
  nm_set_fop(table, offsets.fop_mmap, nm_mmap);
  nm_set_fop(table, offsets.fop_splice_read, nm_splice_read);
  return table;
}
