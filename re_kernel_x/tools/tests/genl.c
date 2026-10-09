#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "re_kernel_host.h"
#define __user
#define __aligned(n) __attribute__((aligned(n)))
#define GFP_ATOMIC 0
#define logkm(...) ((void)0)
#define kfunc(name) kf_##name
#define kfunc_def(n) (*kf_##n)
#define kfunc_call(n, ...) \
  if (kf_##n)              \
    return kf_##n(__VA_ARGS__);
#define kfunc_call_void(n, ...) \
  if (kf_##n)                   \
    kf_##n(__VA_ARGS__);
#define kfunc_not_found() ((void)0)
#define kvar(n) kv_##n
#define lookup_name(n) n = original_genl_rcv_msg
#define kfunc_lookup_name(n) ((void)0)
typedef uint32_t u32, __u32;
typedef int32_t s32;
typedef unsigned int gfp_t;
struct net {
  struct sock* socket;
};
struct sock {
  struct net* net;
};
struct sk_buff {
  struct sock* sk;
  unsigned int len, tail;
  unsigned char* head;
  char cb[48] __aligned(8);
};
typedef struct {
  uint32_t val;
} kuid_t, kgid_t;
/* PRODUCTION_NETLINK_TYPES */
struct nlmsghdr {
  uint32_t nlmsg_len;
  uint16_t nlmsg_type, nlmsg_flags;
  uint32_t nlmsg_seq, nlmsg_pid;
};
struct nlattr {
  uint16_t nla_len, nla_type;
};
struct genlmsghdr {
  uint8_t cmd, version;
  uint16_t reserved;
};
struct genl_family {
  unsigned char unknow[0x400];
} __aligned(8);
struct genl_multicast_group {
  char name[16];
  char unknow[0x30];
} __aligned(8);
struct genl_family_config {
  unsigned int hdrsize;
  char name[16];
  unsigned int version, maxattr;
};
#define NLMSG_HDRLEN 16
#define GENL_HDRLEN 4
#define NLMSG_ALIGN(n) (((n) + 3U) & ~3U)
#define NLM_F_DUMP 0x300
#define NLA_HDRLEN 4
#define NLA_ALIGN(n) (((n) + 3U) & ~3U)
#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
static struct {
  int16_t genl_family_id, genl_family_config, genl_family_n_mcgrps, genl_family_n_mcgrps_size;
  int16_t genl_family_mcgrp_offset, genl_family_mcgrps, net_genl_sock, sock_sk_net;
  int16_t sk_buff_len, sk_buff_tail, sk_buff_head, sk_buff_data, binder_buffer_data;
} struct_offset = {0,
                   4,
                   0x27,
                   1,
                   0x20,
                   0x50,
                   offsetof(struct net, socket),
                   offsetof(struct sock, net),
                   offsetof(struct sk_buff, len),
                   offsetof(struct sk_buff, tail),
                   offsetof(struct sk_buff, head),
                   offsetof(struct sk_buff, head),
                   -1};
typedef struct {
  uintptr_t arg0, arg1, ret;
  int skip_origin;
} hook_fargs2_t;
static struct genl_family rekernel_genl_family;
static struct genl_multicast_group rekernel_genl_mcgrp;
static bool rekernel_genl_registered;
static uid_t rekernel_net_uids[32];
static unsigned int rekernel_net_uid_count, rekernel_net_uid_guard;
// 本测试只覆盖规则收发；缓冲读取在 cleanup 测试核对。
static int (*kf_binder_alloc_copy_from_buffer)(void) = (void*)1;
static struct rekernel_free_async_rule rekernel_free_async_rules[REKERNEL_FREE_ASYNC_MAX];
static unsigned int rekernel_free_async_count, rekernel_free_async_guard;
static struct net init_net, other_net;
static struct net* kv_init_net = &init_net;
static struct sock socket = {&init_net};
static pthread_mutex_t uid_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long rekernel_context_lock(unsigned int* lock) {
  assert(pthread_mutex_lock(&uid_mutex) == 0);
  return 123;
}
static void rekernel_context_unlock(unsigned int* lock, unsigned long flags) {
  assert(flags == 123);
  assert(pthread_mutex_unlock(&uid_mutex) == 0);
}
static unsigned char storage[512], wire[512];
static struct sk_buff buffer = {&socket, 0, 0, storage};
static int alloc_error, header_error, nla_error, nla_calls, multicast_result;
static int allocated, freed, sent, wire_len, cancelled;
static int registered, unregistered, register_error, hook_error, hooked, unwrapped;
static int original_genl_rcv_msg(struct sk_buff* skb, struct nlmsghdr* nlh) { return -777; }
static int (*genl_rcv_msg)(struct sk_buff*, struct nlmsghdr*);
static int hook_wrap(void* func, int count, void* before, void* after, void* data) {
  assert(func == original_genl_rcv_msg && count == 2 && before && !after && !data);
  if (!hook_error)
    hooked++;
  return hook_error;
}
static void hook_unwrap(void* func, void* before, void* after) {
  assert(func == original_genl_rcv_msg && before && !after && hooked > 0);
  hooked--;
  unwrapped++;
}
static void set_u32(void* ptr, uint32_t n) { memcpy(ptr, &n, 4); }
static struct sk_buff* nlmsg_new(size_t size, gfp_t flags) {
  assert(size == 264 && flags == GFP_ATOMIC);
  if (alloc_error)
    return NULL;
  memset(storage, 0xa5, sizeof(storage));
  buffer.len = buffer.tail = 0;
  nla_calls = 0;
  allocated++;
  return &buffer;
}
static void nlmsg_free(struct sk_buff* skb) {
  assert(skb == &buffer);
  freed++;
}
static void native_trim(struct sk_buff* skb, unsigned int len) {
  assert(len <= skb->len);
  skb->len = skb->tail = len;
  cancelled++;
}
static void* native_genlmsg_put(struct sk_buff* skb, u32 portid, u32 seq, const struct genl_family* family, int flags,
                                uint8_t cmd) {
  if (header_error)
    return NULL;
  assert(!portid && !seq && !flags && cmd == 1 && family == &rekernel_genl_family);
  struct nlmsghdr* nlh = (void*)skb->head;
  *nlh = (struct nlmsghdr){.nlmsg_type = 77};
  struct genlmsghdr* hdr = (void*)(skb->head + 16);
  *hdr = (struct genlmsghdr){1, 1, 0};
  skb->tail = skb->len = 20;
  return skb->head + 20;
}
static int native_nla_put(struct sk_buff* skb, int type, int len, const void* data) {
  if (++nla_calls == nla_error)
    return -EMSGSIZE;
  unsigned int size = NLA_ALIGN(4 + len);
  assert(skb->tail + size <= 284);
  struct nlattr* attr = (void*)(skb->head + skb->tail);
  memset(attr, 0, size);
  *attr = (struct nlattr){4 + len, type};
  if (len)
    memcpy((char*)attr + 4, data, len);
  skb->tail += size;
  skb->len = skb->tail;
  return 0;
}
static int native_broadcast(struct sock* sk, struct sk_buff* skb, u32 portid, u32 group, gfp_t flags) {
  assert(sk == &socket && skb == &buffer && !portid && group == 19 && flags == GFP_ATOMIC);
  wire_len = skb->len;
  memcpy(wire, skb->head, wire_len);
  sent++;
  freed++;  // 内核 broadcast 接管 skb，包括无订阅者和发送错误。
  return multicast_result;
}
static int native_register(struct genl_family* family) {
  assert(hooked == 1 && family == &rekernel_genl_family);
  struct genl_family_config* config = (void*)(family->unknow + 4);
  assert(!strcmp(config->name, "rekernel_x2") && !config->hdrsize && config->version == 1 && config->maxattr == 49);
  assert(family->unknow[0x27] == 1);
  void* group;
  memcpy(&group, family->unknow + 0x50, sizeof(group));
  assert(group == &rekernel_genl_mcgrp && !strcmp(group, "events"));
  registered++;
  if (!register_error) {
    set_u32(family->unknow, 77);
    set_u32(family->unknow + 0x20, 19);
  }
  return register_error;
}
static int native_unregister(const struct genl_family* family) {
  unregistered++;
  return 0;
}
static int (*kf_genl_register_family)(struct genl_family*) = native_register;
static int (*kf___genl_register_family)(struct genl_family*) = native_register;
static int (*kf_genl_unregister_family)(const struct genl_family*) = native_unregister;
static void* (*kf_genlmsg_put)(struct sk_buff*, u32, u32, const struct genl_family*, int, uint8_t) = native_genlmsg_put;
static int (*kf_nla_put)(struct sk_buff*, int, int, const void*) = native_nla_put;
static void (*kf_skb_trim)(struct sk_buff*, unsigned int) = native_trim;
static int (*kf_netlink_broadcast)(struct sock*, struct sk_buff*, u32, u32, gfp_t) = native_broadcast;
static int kf___alloc_skb = 1, kf_kfree_skb = 1;

/* PRODUCTION_FUNCTIONS */

// 按固定的上游编号独立解码实际字节，检查长度、嵌套标志、字段和 padding。
static unsigned char* expect_attr(unsigned char* pos, int type, const void* value, size_t len) {
  struct nlattr hdr;
  memcpy(&hdr, pos, 4);
  assert(hdr.nla_type == type && hdr.nla_len == len + 4);
  assert(!memcmp(pos + 4, value, len));
  for (size_t i = 4 + len; i < NLA_ALIGN(4 + len); i++) assert(pos[i] == 0);
  return pos + NLA_ALIGN(4 + len);
}
static void decode_event(const struct rekernel_event* msg) {
  struct nlmsghdr* nlh = (void*)wire;
  assert(nlh->nlmsg_len == wire_len && nlh->nlmsg_type == 77 && !nlh->nlmsg_pid && !nlh->nlmsg_seq
         && !nlh->nlmsg_flags);
  struct genlmsghdr* hdr = (void*)(wire + 16);
  assert(hdr->cmd == 1 && hdr->version == 1 && !hdr->reserved);
  struct nlattr* event = (void*)(wire + 20);
  struct nlattr* payload = (void*)(wire + 24);
  assert(event->nla_type == (1 | 0x8000) && event->nla_len == wire_len - 20);
  assert(payload->nla_type == ((msg->type == BINDER ? 10 : msg->type == SIGNAL ? 20 : 30) | 0x8000));
  assert(payload->nla_len == wire_len - 24);
  unsigned char* pos = wire + 28;
  if (msg->type == BINDER) {
    int type = msg->binder.type == REPLY ? 2 : msg->binder.type == TRANSACTION ? 1 : 3;
    pos = expect_attr(pos, 11, &type, 4);
    pos = expect_attr(pos, 12, &msg->binder.oneway, 4);
    pos = expect_attr(pos, 13, &msg->binder.src_pid, 4);
    pos = expect_attr(pos, 14, &msg->binder.src_uid, 4);
    pos = expect_attr(pos, 15, &msg->binder.dst_pid, 4);
    pos = expect_attr(pos, 16, &msg->binder.dst_uid, 4);
    pos = expect_attr(pos, 17, &msg->binder.code, 4);
    pos = expect_attr(pos, 18, msg->binder.rpc_name, strlen(msg->binder.rpc_name) + 1);
  } else if (msg->type == SIGNAL) {
    pos = expect_attr(pos, 21, &msg->signal.signum, 4);
    pos = expect_attr(pos, 22, &msg->signal.src_pid, 4);
    pos = expect_attr(pos, 23, &msg->signal.src_uid, 4);
    pos = expect_attr(pos, 24, &msg->signal.dst_pid, 4);
    pos = expect_attr(pos, 25, &msg->signal.dst_uid, 4);
  } else {
    pos = expect_attr(pos, 31, &msg->network.family, 4);
    pos = expect_attr(pos, 32, &msg->network.uid, 4);
    pos = expect_attr(pos, 33, &msg->network.data_len, 4);
  }
  assert(pos == wire + wire_len && allocated == freed);
}
static struct nlmsghdr* command(unsigned int cmd, uid_t uid) {
  memset(storage, 0, sizeof(storage));
  buffer.sk = &socket;
  buffer.len = 28;
  NETLINK_CB(&buffer).creds.uid.val = REKERNEL_GENL_UID;
  struct nlmsghdr* nlh = (void*)storage;
  *nlh = (struct nlmsghdr){.nlmsg_len = 28, .nlmsg_type = 77};
  *(struct genlmsghdr*)(storage + 16) = (struct genlmsghdr){cmd, 1, 0};
  *(struct nlattr*)(storage + 20) = (struct nlattr){8, 40};
  memcpy(storage + 24, &uid, 4);
  return nlh;
}
static unsigned int ingress_calls;
// 包长先由 netlink_rcv_skb 检查，只有合法信封才进入生产 hook。
static int receive(struct nlmsghdr* nlh) {
  if (buffer.len < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > buffer.len)
    return 0;
  ingress_calls++;
  hook_fargs2_t args = {.arg0 = (uintptr_t)&buffer, .arg1 = (uintptr_t)nlh, .ret = -777};
  genl_rcv_msg_before(&args, NULL);
  assert(args.skip_origin);
  return (int)args.ret;
}
static void* uid_thread(void* data) {
  uid_t uid = 20000 + (uintptr_t)data;
  for (int i = 0; i < 500; i++) {
    assert(net_uid_update(uid, true) == 0 && net_uid_monitored(uid));
    assert(net_uid_update(uid, false) == 0 && !net_uid_monitored(uid));
  }
  return NULL;
}
static void append_attr(struct nlmsghdr* nlh, unsigned int type, const void* data, unsigned int len) {
  unsigned int start = buffer.len;
  assert(start + NLA_ALIGN(len + 4) <= sizeof(storage));
  struct nlattr* attr = (void*)(storage + start);
  *attr = (struct nlattr){len + 4, type};
  memcpy(storage + start + 4, data, len);
  nlh->nlmsg_len = buffer.len = start + NLA_ALIGN(len + 4);
}
static struct nlmsghdr* rule_command(unsigned int cmd, const char* rpc, int code, unsigned char strategy) {
  struct nlmsghdr* nlh = command(cmd, 0);
  nlh->nlmsg_len = buffer.len = 20;
  append_attr(nlh, 42, rpc, strlen(rpc) + 1);
  append_attr(nlh, 43, &code, 4);
  if (cmd == 4)
    append_attr(nlh, 41, &strategy, 1);
  return nlh;
}
static void test_sender_uid(void) {
  assert(REKERNEL_GENL_UID == 1000);
  assert(!rekernel_net_uid_count && !free_async_has_rules());
  assert(receive(command(2, 10042)) == 0);
  assert(receive(rule_command(4, "android.test.IAuth", 7, REKERNEL_FREE_ASYNC_SKIP)) == 0);
  uid_t uids[REKERNEL_NET_UID_MAX];
  struct rekernel_free_async_rule rules[REKERNEL_FREE_ASYNC_MAX];
  memcpy(uids, rekernel_net_uids, sizeof(uids));
  memcpy(rules, rekernel_free_async_rules, sizeof(rules));
  const uid_t denied[] = {0, 999, 1001, 2000, 10000, (uid_t)-1};
  for (unsigned int i = 0; i < ARRAY_SIZE(denied); i++) {
    for (unsigned int cmd = 2; cmd <= 5; cmd++) {
      struct nlmsghdr* nlh = cmd < 4 ? command(cmd, cmd == 2 ? 1000 : 10042)
                                     : rule_command(cmd, "android.test.IAuth", 7, REKERNEL_FREE_ASYNC_BY_DATA);
      // 报文 PID 与目标 UID 均不参与鉴权；接收 socket 不因发送者变化而改变。
      nlh->nlmsg_pid = 1000;
      NETLINK_CB(&buffer).creds.pid = 1000;
      NETLINK_CB(&buffer).creds.uid.val = denied[i];
      assert(receive(nlh) == -EPERM);
      assert(rekernel_net_uid_count == 1 && rekernel_free_async_count == 1);
      assert(!memcmp(uids, rekernel_net_uids, sizeof(uids)));
      assert(!memcmp(rules, rekernel_free_async_rules, sizeof(rules)));
    }
  }
  struct nlmsghdr* nlh = command(2, 1000);
  NETLINK_CB(&buffer).creds.uid.val = 2000;
  nlh->nlmsg_type = 78;
  hook_fargs2_t args = {.arg0 = (uintptr_t)&buffer, .arg1 = (uintptr_t)nlh, .ret = -777};
  genl_rcv_msg_before(&args, NULL);
  assert(!args.skip_origin && (int)args.ret == -777);
  assert(receive(command(3, 10042)) == 0 && !rekernel_net_uid_count);
  assert(receive(rule_command(5, "android.test.IAuth", 7, 0)) == 0 && !free_async_has_rules());
  puts(
      "production Genl authorization: sender UID 1000, six rejected UIDs, four commands, forged payload/PID, "
      "unchanged state, other family untouched: PASS");
}
static void* rule_thread(void* data) {
  char name[32];
  snprintf(name, sizeof(name), "rpc%u", (unsigned int)(uintptr_t)data);
  for (int i = 0; i < 500; i++) {
    assert(free_async_update(name, 9, REKERNEL_FREE_ASYNC_SKIP, true) == 0);
    assert(free_async_lookup(name, 9) == REKERNEL_FREE_ASYNC_SKIP);
    assert(free_async_update(name, 9, 0, false) == 0);
    assert(free_async_lookup(name, 9) == REKERNEL_FREE_ASYNC_BY_CODE);
  }
  return NULL;
}
static void test_rules(void) {
  assert(!free_async_has_rules());
  kf_binder_alloc_copy_from_buffer = NULL;
  assert(receive(rule_command(4, "rpc", 7, 1)) == -EOPNOTSUPP && !free_async_has_rules());
  struct_offset.binder_buffer_data = 0x58;
  assert(receive(rule_command(4, "legacy", 7, 1)) == 0);
  assert(receive(rule_command(5, "legacy", 7, 0)) == 0 && !free_async_has_rules());
  struct_offset.binder_buffer_data = -1;
  kf_binder_alloc_copy_from_buffer = (void*)1;
  assert(receive(rule_command(4, "android.test.IFoo", -1, 1)) == 0);
  assert(free_async_has_rules() && rekernel_free_async_count == 1);
  assert(free_async_lookup("android.test.IFoo", 7) == 1);
  assert(receive(rule_command(4, "android.test.IFoo", 7, 2)) == 0);
  assert(free_async_lookup("android.test.IFoo", 7) == 2);
  assert(free_async_lookup("android.test.IFoo", 8) == 1);
  assert(free_async_lookup("android.test.IFoo", 0xffffffff) == 1);
  assert(free_async_lookup("other", 7) == 2);
  assert(receive(rule_command(4, "android.test.IFoo", 7, 1)) == 0 && rekernel_free_async_count == 2);
  assert(free_async_lookup("android.test.IFoo", 7) == 1);
  assert(receive(rule_command(5, "android.test.IFoo", 7, 0)) == 0);
  assert(free_async_lookup("android.test.IFoo", 7) == 1);
  assert(receive(rule_command(5, "android.test.IFoo", -1, 0)) == 0 && !free_async_has_rules());
  assert(receive(rule_command(5, "missing", 7, 0)) == 0);
  for (int strategy = 0; strategy <= 4; strategy++) {
    if (strategy >= 1 && strategy <= 3)
      continue;
    assert(receive(rule_command(4, "rpc", 7, strategy)) == -EINVAL);
  }
  assert(receive(rule_command(4, "rpc", 7, 3)) == 0 && free_async_lookup("rpc", 7) == 3);
  assert(receive(rule_command(5, "rpc", 7, 0)) == 0);
  assert(receive(rule_command(4, "rpc", -2, 1)) == -EINVAL);
  assert(receive(rule_command(4, "", 7, 1)) == -EINVAL);
  char name[141];
  memset(name, 'x', 139);
  name[139] = 0;
  assert(receive(rule_command(4, name, 7, 1)) == 0);
  assert(receive(rule_command(5, name, 7, 0)) == 0);
  name[139] = 'x';
  name[140] = 0;
  assert(receive(rule_command(4, name, 7, 1)) == -EINVAL);
  for (int type = 41; type <= 43; type++) {
    struct nlmsghdr* nlh = rule_command(4, "rpc", 7, 1);
    struct nlattr* attr = (void*)(storage + 20);
    while (attr->nla_type != type) attr = (void*)((char*)attr + NLA_ALIGN(attr->nla_len));
    struct nlattr copy = *attr;
    unsigned char value[144];
    memcpy(value, attr + 1, copy.nla_len - 4);
    append_attr(nlh, type, value, copy.nla_len - 4);
    assert(receive(nlh) == -EINVAL);
    for (int flag = 14; flag <= 15; flag++) {
      nlh = rule_command(4, "rpc", 7, 1);
      attr = (void*)(storage + 20);
      while (attr->nla_type != type) attr = (void*)((char*)attr + NLA_ALIGN(attr->nla_len));
      attr->nla_type |= 1 << flag;
      assert(receive(nlh) == -EINVAL);
    }
  }
  for (int type = 41; type <= 43; type++) {
    struct nlmsghdr* nlh = rule_command(4, "rpc", 7, 1);
    struct nlattr* attr = (void*)(storage + 20);
    while (attr->nla_type != type) attr = (void*)((char*)attr + NLA_ALIGN(attr->nla_len));
    attr->nla_type = 48;  // 缺少必需属性。
    assert(receive(nlh) == -EINVAL);
    nlh = rule_command(4, "rpc", 7, 1);
    attr = (void*)(storage + 20);
    while (attr->nla_type != type) attr = (void*)((char*)attr + NLA_ALIGN(attr->nla_len));
    attr->nla_len = 4;  // 空字符串或数值宽度错误。
    assert(receive(nlh) == -EINVAL);
  }
  struct nlmsghdr* nlh = rule_command(4, "rpc", 7, 1);
  storage[27] = 'x';  // 缺少 NUL。
  assert(receive(nlh) == -EINVAL);
  nlh = rule_command(4, "rpc", 7, 1);
  storage[25] = 0;  // 嵌入 NUL。
  assert(receive(nlh) == -EINVAL);
  for (int i = 0; i < 32; i++) {
    snprintf(name, sizeof(name), "rpc%d", i);
    assert(receive(rule_command(4, name, 7, 1)) == 0);
  }
  assert(receive(rule_command(4, "overflow", 7, 1)) == -ENOSPC);
  assert(receive(rule_command(4, "rpc31", 7, 2)) == 0);  // 满容量仍能更新。
  assert(receive(rule_command(5, "rpc15", 7, 0)) == 0);
  assert(free_async_lookup("rpc31", 7) == 2);
  assert(receive(rule_command(4, "overflow", 7, 1)) == 0);
  for (int i = 0; i < 32; i++) {
    snprintf(name, sizeof(name), "rpc%d", i);
    assert(receive(rule_command(5, name, 7, 0)) == 0);
  }
  assert(receive(rule_command(5, "overflow", 7, 0)) == 0 && !free_async_has_rules());
  // 随机规则报文失败时，所有数组字节和计数都必须保持。
  uint32_t rng = 456;
  for (int i = 0; i < 20000; i++) {
    for (unsigned int j = 20; j < sizeof(storage); j++) {
      rng = rng * 1664525 + 1013904223;
      storage[j] = rng >> 24;
    }
    buffer.len = 20 + i % 493;
    struct nlmsghdr* nlh = (void*)storage;
    *nlh = (struct nlmsghdr){.nlmsg_len = buffer.len, .nlmsg_type = 77};
    *(struct genlmsghdr*)(storage + 16) = (struct genlmsghdr){4 + i % 2, 1, 0};
    struct rekernel_free_async_rule saved[REKERNEL_FREE_ASYNC_MAX];
    memcpy(saved, rekernel_free_async_rules, sizeof(saved));
    unsigned int count = rekernel_free_async_count;
    if (receive(nlh) < 0) {
      assert(rekernel_free_async_count == count);
      assert(!memcmp(saved, rekernel_free_async_rules, sizeof(saved)));
    }
  }
  pthread_t threads[8];
  for (uintptr_t i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, rule_thread, (void*)i) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(!free_async_has_rules());
  puts(
      "production free-async rules: wire commands, exact/wildcard priority, update/delete/full, malformed strings, "
      "BY_DATA accepted, eight writers: PASS");
}
int main(void) {
  init_net.socket = &socket;
  hook_error = 1;
  assert(start_rekernel_genl_server() == -EOPNOTSUPP && !hooked && !registered);
  hook_error = 0;
  register_error = -EEXIST;
  assert(start_rekernel_genl_server() == -EEXIST && !hooked && unwrapped == 1);
  register_error = 0;
  kf_genl_register_family = NULL;  // 旧内核入口 fallback。
  assert(start_rekernel_genl_server() == 0 && hooked == 1 && registered == 2);
  struct rekernel_event msg = {.type = BINDER,
                               .binder = {.type = TRANSACTION,
                                          .oneway = 1,
                                          .src_pid = 11,
                                          .src_uid = 10001,
                                          .dst_pid = 22,
                                          .dst_uid = 10002,
                                          .code = 0xffffffff}};
  memset(msg.binder.rpc_name, 'x', 139);
  msg.binder.rpc_name[139] = 0;
  assert(send_netlink_message(&msg) == 0 && wire_len == 228);
  decode_event(&msg);
  msg.binder.type = REPLY;
  msg.binder.rpc_name[0] = 0;
  assert(send_netlink_message(&msg) == 0);
  decode_event(&msg);
  msg.binder.type = OVERFLOW;
  assert(send_netlink_message(&msg) == 0);
  decode_event(&msg);
  for (int i = 1; i <= 10; i++) {
    int previous = sent;
    nla_error = i;
    assert(send_netlink_message(&msg) == -EMSGSIZE && sent == previous && allocated == freed);
  }
  nla_error = 0;
  msg = (struct rekernel_event){.type = SIGNAL, .signal = {9, 11, 10001, 22, 10002}};
  assert(send_netlink_message(&msg) == 0 && wire_len == 68);
  decode_event(&msg);
  msg = (struct rekernel_event){.type = NETWORK, .network = {6, 10002, 123}};
  assert(send_netlink_message(&msg) == 0 && wire_len == 52);
  decode_event(&msg);
  multicast_result = -ESRCH;
  assert(send_netlink_message(&msg) == 0 && allocated == freed);
  multicast_result = -EIO;
  assert(send_netlink_message(&msg) == -EIO && allocated == freed);
  multicast_result = 0;
  alloc_error = 1;
  assert(send_netlink_message(&msg) == -ENOMEM && allocated == freed);
  alloc_error = 0;
  header_error = 1;
  assert(send_netlink_message(&msg) == -EMSGSIZE && allocated == freed);
  header_error = 0;
  msg.type = 999;
  assert(send_netlink_message(&msg) == -EMSGSIZE && allocated == freed);

  struct nlmsghdr* nlh = command(2, 10042);
  assert(receive(nlh) == 0 && net_uid_monitored(10042) && rekernel_net_uid_count == 1);
  assert(receive(nlh) == 0 && rekernel_net_uid_count == 1);
  assert(receive(command(3, 10042)) == 0 && !net_uid_monitored(10042));
  assert(receive(command(3, 10042)) == 0 && !rekernel_net_uid_count);
  for (int i = 0; i < 32; i++) assert(receive(command(2, 10000 + i)) == 0);
  assert(receive(command(2, 99999)) == -ENOSPC && !net_uid_monitored(99999));
  assert(receive(command(3, 10015)) == 0 && !net_uid_monitored(10015) && net_uid_monitored(10031));
  assert(receive(command(2, 99999)) == 0 && net_uid_monitored(99999));
  for (int i = 0; i < 32; i++) assert(receive(command(3, 10000 + i)) == 0);
  assert(receive(command(3, 99999)) == 0 && !rekernel_net_uid_count);
  assert(receive(command(4, 1)) == -EINVAL);  // 缺少规则参数。
  nlh = command(2, 10042);
  nlh->nlmsg_flags = NLM_F_DUMP;
  assert(receive(nlh) == -EOPNOTSUPP);
  nlh = command(2, 10042);
  storage[17] = 2;
  assert(receive(nlh) == -EINVAL);
  nlh = command(2, 10042);
  buffer.sk = NULL;
  assert(receive(nlh) == -ENOENT);
  nlh = command(2, 10042);
  socket.net = &other_net;
  assert(receive(nlh) == -ENOENT);
  socket.net = &init_net;
  nlh = command(2, 10042);
  nlh->nlmsg_len = 19;
  assert(receive(nlh) == -EINVAL);
  nlh = command(2, 10042);
  nlh->nlmsg_len = 29;
  unsigned int calls = ingress_calls;
  assert(receive(nlh) == 0 && ingress_calls == calls && !rekernel_net_uid_count);
  nlh->nlmsg_len = NLMSG_HDRLEN - 1;
  assert(receive(nlh) == 0 && ingress_calls == calls && !rekernel_net_uid_count);
  for (int length = 0; length <= 12; length++) {
    if (length == 8)
      continue;
    nlh = command(2, 10042);
    ((struct nlattr*)(storage + 20))->nla_len = length;
    assert(receive(nlh) == -EINVAL);
  }
  nlh = command(2, 10042);
  nlh->nlmsg_len = buffer.len = 20;
  assert(receive(nlh) == -EINVAL);
  nlh = command(2, 10042);
  ((struct nlattr*)(storage + 20))->nla_type |= NLA_F_NESTED;
  assert(receive(nlh) == -EINVAL);
  nlh = command(2, 10042);
  ((struct nlattr*)(storage + 20))->nla_type |= NLA_F_NET_BYTEORDER;
  assert(receive(nlh) == -EINVAL);
  nlh = command(2, 10042);
  memcpy(storage + 28, storage + 20, 8);
  nlh->nlmsg_len = buffer.len = 36;
  assert(receive(nlh) == -EINVAL && !rekernel_net_uid_count);
  nlh = command(2, 10042);
  nlh->nlmsg_len = buffer.len = 29;
  assert(receive(nlh) == -EINVAL && !rekernel_net_uid_count);
  nlh = command(2, 10042);
  memcpy(storage + 28, storage + 20, 8);
  ((struct nlattr*)(storage + 28))->nla_type = 48;
  nlh->nlmsg_len = buffer.len = 36;
  assert(receive(nlh) == 0 && net_uid_monitored(10042));
  assert(receive(command(3, 10042)) == 0);
  nlh = command(2, 10042);
  nlh->nlmsg_type = 78;
  hook_fargs2_t args = {.arg0 = (uintptr_t)&buffer, .arg1 = (uintptr_t)nlh, .ret = -777};
  genl_rcv_msg_before(&args, NULL);
  assert(!args.skip_origin && (int)args.ret == -777 && !rekernel_net_uid_count);

  // 随机输入只能在完整校验后修改数组。
  uint32_t rng = 123;
  for (int i = 0; i < 20000; i++) {
    for (unsigned int j = 20; j < sizeof(storage); j++) {
      rng = rng * 1664525 + 1013904223;
      storage[j] = rng >> 24;
    }
    buffer.len = 20 + i % 493;
    nlh = (void*)storage;
    *nlh = (struct nlmsghdr){.nlmsg_len = buffer.len, .nlmsg_type = 77};
    *(struct genlmsghdr*)(storage + 16) = (struct genlmsghdr){2, 1, 0};
    unsigned int previous = rekernel_net_uid_count;
    int rc = receive(nlh);
    if (rc < 0)
      assert(rekernel_net_uid_count == previous);
    else
      assert(rekernel_net_uid_count == previous + 1);
  }
  memset(rekernel_net_uids, 0, sizeof(rekernel_net_uids));
  rekernel_net_uid_count = 0;
  pthread_t threads[8];
  for (uintptr_t i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, uid_thread, (void*)i) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(!rekernel_net_uid_count);
  test_rules();
  test_sender_uid();
  assert(stop_rekernel_genl_server() == 0 && !hooked && unregistered == 1);
  assert(stop_rekernel_genl_server() == 0 && unregistered == 1);
  assert(send_netlink_message(&msg) == -ENOTCONN);
  puts(
      "production Genl: upstream wire bytes, nested attributes, 139-byte RPC, all write failures, skb ownership: PASS");
  puts(
      "production Genl receive: UID add/delete/full, malformed input, namespace/version/family, 20000 random packets, "
      "8 threads: PASS");
  puts("production Genl lifecycle: hook failure, registration rollback, old entry fallback, repeated exit: PASS");
}
