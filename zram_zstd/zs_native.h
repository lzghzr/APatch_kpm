/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ZS_NATIVE_H
#define ZS_NATIVE_H

struct module;

/* ACK zcomp contract; every size/member is checked against the live module BTF. */
struct zcomp_params {
  void* dict;
  size_t dict_sz;
  int level;
  void* drv_data;
};
struct zcomp_ctx {
  void* context;
};
struct zcomp_req {
  const unsigned char* src;
  const size_t src_len;
  unsigned char* dst;
  size_t dst_len;
};
struct zcomp_ops {
  int (*compress)(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
  int (*decompress)(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
  int (*create_ctx)(struct zcomp_params*, struct zcomp_ctx*);
  void (*destroy_ctx)(struct zcomp_ctx*);
  int (*setup_params)(struct zcomp_params*);
  void (*release_params)(struct zcomp_params*);
  const char* name;
};
struct zs_native_node {
  void* next;
  void** pprev;
};
struct zcomp {
  void* stream;
  const struct zcomp_ops* ops;
  struct zcomp_params* params;
  struct zs_native_node node;
};
/* Supported local_lock_t is empty; the BTF gate also checks that omitted member. */
struct zcomp_strm {
  void* buffer;
  void* local_copy;
  struct zcomp_ctx ctx;
};

int zs_native_compress(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
int zs_native_decompress(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
int zs_native_create_zstd(struct zcomp_params*, struct zcomp_ctx*);
int zs_native_create_lz4(struct zcomp_params*, struct zcomp_ctx*);
int zs_native_create_lz4kd(struct zcomp_params*, struct zcomp_ctx*);
void zs_native_destroy(struct zcomp_ctx*);
int zs_native_setup_zstd(struct zcomp_params*);
int zs_native_setup_lz4(struct zcomp_params*);
int zs_native_setup_lz4kd(struct zcomp_params*);
void zs_native_release(struct zcomp_params*);

int zs_native_compress_impl(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
int zs_native_decompress_impl(struct zcomp_params*, struct zcomp_ctx*, struct zcomp_req*);
int zs_native_create_zstd_impl(struct zcomp_params*, struct zcomp_ctx*);
int zs_native_create_lz4_impl(struct zcomp_params*, struct zcomp_ctx*);
int zs_native_create_lz4kd_impl(struct zcomp_params*, struct zcomp_ctx*);
void zs_native_destroy_impl(struct zcomp_ctx*);
int zs_native_setup_zstd_impl(struct zcomp_params*);
int zs_native_setup_lz4_impl(struct zcomp_params*);
int zs_native_setup_lz4kd_impl(struct zcomp_params*);
void zs_native_release_impl(struct zcomp_params*);

static bool zs_native_seen;
static bool zs_native_ready;
static void zs_native_try_install(struct module* owner, void* show);
static bool zs_codec_selectable(unsigned int index);
#endif
