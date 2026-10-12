#ifndef __ZS_STRUCTS_H
#define __ZS_STRUCTS_H

struct crypto_tfm;
struct crypto_alg;
struct module;

// include/linux/module.h：本轮目标的 state 均为首个 32 位字段，
// 由六份 BTF 与七份 try_module_get 入口核对；只在原生 module_mutex 下读取。
enum zs_module_state { ZS_MODULE_LIVE, ZS_MODULE_COMING, ZS_MODULE_GOING, ZS_MODULE_UNFORMED };

struct zs_module_prefix {
  enum zs_module_state state;
};

// include/linux/crypto.h：已核对 4.4～6.6 的共同前缀。
// cra_refcnt 的 atomic_t / refcount_t 都是一个 32 位计数，此处只表示其存储，不操作引用。
// cra_name 的长度随厂商布局变化；柔性数组仅标出共同起点，不表示完整 crypto_alg。
struct zs_crypto_alg_prefix {
  struct list_head cra_list;
  struct list_head cra_users;
  u32 cra_flags;
  unsigned int cra_blocksize;
  unsigned int cra_ctxsize;
  unsigned int cra_alignmask;
  int cra_priority;
  atomic_t cra_refcnt;
  char cra_name[];
};

struct zs_compress_alg {
  int (*coa_compress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
  int (*coa_decompress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
};

struct zs_alg_lifecycle {
  int (*cra_init)(struct crypto_tfm*);
  void (*cra_exit)(struct crypto_tfm*);
  void (*cra_destroy)(struct crypto_alg*);
  struct module* cra_module;
};

#endif
