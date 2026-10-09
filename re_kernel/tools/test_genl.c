// 运行生产 Genl 收发与 Binder 上下文代码；仅替换内核调用和锁，不模拟目标内核生命周期。
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Darwin 与内核的这三个类型不同；自检不使用它们。
#define dev_t kernel_dev_t
#define mode_t kernel_mode_t
#define off_t kernel_off_t
#include "re_kernel_host.h"
#undef dev_t
#undef mode_t
#undef off_t

#define kfunc(name) kf_##name
#define kfunc_def(name) (*kf_##name)
#define kfunc_lookup_name(name) ((void)0)
#define kvar(name) kv_##name
#define logkm(...) ((void)0)
#define lookup_name(func)                           \
  func = (typeof(func))kallsyms_lookup_name(#func); \
  if (!func)                                        \
    return -21;
#define MYKPM_VERSION "8.0.0"

struct net {
  char bytes[64];
};
static struct net net;
static struct net* kv_init_net = &net;
static struct sock socket;
struct test_skb {
  struct sk_buff skb;
  unsigned int len;
  unsigned char bytes[512];
};
typedef struct {
  unsigned long arg0, arg1;
  long ret;
  bool skip_origin;
} hook_fargs2_t;
typedef struct {
  unsigned long arg0, arg1, arg2;
} hook_fargs5_t;
static void* kf___alloc_skb = (void*)1;
static void* kf_kfree_skb = (void*)1;
static void* kf_netlink_unicast = (void*)1;
static int hook_error, register_error, unregister_error;
static int hook_count, allocations, skb_count, broadcasts, unicasts, send_error, message_error;
static bool alloc_error;
static unsigned long symbol_addr = 1;
static struct task_struct* current;
static unsigned int sk_buff_len(const struct sk_buff* skb) { return ((const struct test_skb*)skb)->len; }
static void* nlmsg_data(const struct nlmsghdr* nlh) { return (char*)nlh + NLMSG_HDRLEN; }
static struct sk_buff* nlmsg_new(size_t size, gfp_t flags) {
  if (alloc_error)
    return NULL;
  assert(size <= 512);
  skb_count++;
  return (void*)calloc(1, sizeof(struct test_skb));
}
static void nlmsg_free(struct sk_buff* skb) {
  skb_count--;
  free(skb);
}
static void* kmalloc(size_t size, gfp_t flags) {
  if (alloc_error)
    return NULL;
  allocations++;
  return calloc(1, size);
}
static void kfree(void* ptr) {
  assert(ptr);
  allocations--;
  free(ptr);
}
static unsigned long kallsyms_lookup_name(const char* name) { return symbol_addr; }
static int hook_wrap(void* func, int args, void* before, void* after, void* data) {
  if (hook_error)
    return hook_error;
  hook_count++;
  return 0;
}
static void hook_unwrap(void* func, void* before, void* after) { hook_count--; }
static unsigned long rekernel_context_lock(unsigned int* lock) { return 0; }
static void rekernel_context_unlock(unsigned int* lock, unsigned long flags) {}
static int netlink_unicast(struct sock* sk, struct sk_buff* skb, u32 portid, int nonblock);

/* PRODUCTION_FUNCTIONS */

static void* mock_put(struct sk_buff* skb, u32 portid, u32 seq, const struct genl_family* family, int flags, u8 cmd) {
  if (message_error == 1)
    return NULL;
  struct test_skb* packet = (void*)skb;
  struct nlmsghdr* nlh = (void*)packet->bytes;
  *nlh = (struct nlmsghdr){NLMSG_HDRLEN + GENL_HDRLEN, genl_family_id(), flags, seq, portid};
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  *hdr = (struct genlmsghdr){cmd, REKERNEL_GENL_VERSION};
  packet->len = nlh->nlmsg_len;
  return (char*)hdr + GENL_HDRLEN;
}
static int mock_nla(struct sk_buff* skb, int type, int len, const void* data) {
  if (message_error == 2)
    return -EMSGSIZE;
  struct test_skb* packet = (void*)skb;
  assert(packet->len + NLA_ALIGN(NLA_HDRLEN + len) <= sizeof(packet->bytes));
  struct nlattr* attr = (void*)(packet->bytes + packet->len);
  *attr = (struct nlattr){NLA_HDRLEN + len, type};
  memcpy((char*)attr + NLA_HDRLEN, data, len);
  packet->len += NLA_ALIGN(attr->nla_len);
  return 0;
}
static void verify_message(struct sk_buff* skb, u8 cmd, u32 seq) {
  struct test_skb* packet = (void*)skb;
  struct nlmsghdr* nlh = (void*)packet->bytes;
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  struct nlattr* attr = (void*)((char*)hdr + GENL_HDRLEN);
  assert(nlh->nlmsg_len == packet->len && nlh->nlmsg_type == 37 && nlh->nlmsg_seq == seq);
  assert(hdr->cmd == cmd && hdr->version == 1 && attr->nla_type == REKERNEL_A_MSG);
  if (cmd == REKERNEL_C_GET_VERSION) {
    assert(attr->nla_len == NLA_HDRLEN + sizeof(MYKPM_VERSION));
    assert(!memcmp((char*)attr + NLA_HDRLEN, MYKPM_VERSION, sizeof(MYKPM_VERSION)));
  } else {
    assert(attr->nla_len == NLA_HDRLEN + 5);
    assert(!memcmp((char*)attr + NLA_HDRLEN, "event", 5));
  }
}
static int mock_broadcast(struct sock* sk, struct sk_buff* skb, u32 portid, u32 group, gfp_t flags) {
  assert(sk == &socket && portid == 0 && group == 11);
  verify_message(skb, REKERNEL_C_EVENT, 0);
  broadcasts++;
  nlmsg_free(skb);
  return send_error;
}
static int netlink_unicast(struct sock* sk, struct sk_buff* skb, u32 portid, int nonblock) {
  assert(sk == &socket && portid == 123);  // nlmsg_pid 是伪造值，目标取内核 CB。
  verify_message(skb, REKERNEL_C_GET_VERSION, 456);
  unicasts++;
  nlmsg_free(skb);
  return send_error ? send_error : 32;
}
static int mock_register(struct genl_family* family) {
  struct genl_family_config* config = (void*)((char*)family + struct_offset.genl_family_config);
  assert(!strcmp(config->name, "rekernel") && config->version == 1 && config->maxattr == 3 && !config->hdrsize);
  struct genl_multicast_group* group = *(void**)((char*)family + struct_offset.genl_family_mcgrps);
  assert(!strcmp(group->name, "events"));
  assert(*(unsigned int*)((char*)family + struct_offset.genl_family_n_mcgrps) == 1);
  if (register_error)
    return register_error;
  *(unsigned int*)((char*)family + struct_offset.genl_family_id) = 37;
  *(unsigned int*)((char*)family + struct_offset.genl_family_mcgrp_offset) = 11;
  return 0;
}
static int mock_unregister(const struct genl_family* family) { return unregister_error; }
static unsigned int ingress_calls;
// 只模拟 netlink_rcv_skb 在回调之前的包长门禁；非法包不会进入模块。
static int receive_packet(struct sk_buff* skb, struct nlmsghdr* nlh) {
  if (sk_buff_len(skb) < NLMSG_HDRLEN || nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > sk_buff_len(skb))
    return 0;
  ingress_calls++;
  return rekernel_genl_rcv_msg(skb, nlh);
}
static int receive(u8 cmd, int type, int payload, bool duplicate, uid_t sender) {
  struct test_skb packet = {0};
  packet.skb.sk = &socket;
  NETLINK_CB(&packet.skb).creds.uid.val = sender;
  NETLINK_CB(&packet.skb).portid = 123;
  struct nlmsghdr* nlh = (void*)packet.bytes;
  *nlh = (struct nlmsghdr){NLMSG_HDRLEN + GENL_HDRLEN, 37, 0, 456, 999};
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  *hdr = (struct genlmsghdr){cmd, 1};
  if (type >= 0) {
    struct nlattr* attr = (void*)((char*)hdr + GENL_HDRLEN);
    *attr = (struct nlattr){NLA_HDRLEN + payload, type};
    uid_t uid = 10001;
    memcpy((char*)attr + NLA_HDRLEN, &uid, sizeof(uid));
    nlh->nlmsg_len += NLA_ALIGN(attr->nla_len);
    if (duplicate) {
      memcpy((char*)attr + NLA_ALIGN(attr->nla_len), attr, NLA_ALIGN(attr->nla_len));
      nlh->nlmsg_len += NLA_ALIGN(attr->nla_len);
    }
  }
  packet.len = nlh->nlmsg_len;
  return receive_packet(&packet.skb, nlh);
}

int main(void) {
  struct_offset = (struct struct_offset){.genl_family_id = 0,
                                         .genl_family_config = 4,
                                         .genl_family_mcgrps = 72,
                                         .genl_family_n_mcgrps = 84,
                                         .genl_family_n_mcgrps_size = 4,
                                         .genl_family_mcgrp_offset = 88,
                                         .net_genl_sock = 16};
  *(struct sock**)(net.bytes + 16) = &socket;
  kf_genlmsg_put = mock_put;
  kf_nla_put = mock_nla;
  kf_netlink_broadcast = mock_broadcast;
  kf_genl_register_family = mock_register;
  kf_genl_unregister_family = mock_unregister;
  genl_rcv_msg = rekernel_genl_rcv_msg;
  alloc_error = true;
  assert(start_rekernel_genl_server() == -ENOMEM);
  alloc_error = false;
  hook_error = 5;
  assert(start_rekernel_genl_server() == -EOPNOTSUPP && !allocations && !hook_count);
  hook_error = 0;
  register_error = -EEXIST;
  assert(start_rekernel_genl_server() == -EEXIST && !allocations && !hook_count);
  register_error = 0;
  assert(!start_rekernel_genl_server() && allocations == 1 && hook_count == 1);
  assert(!send_netlink_message("event") && !skb_count && broadcasts == 1);
  send_error = -ESRCH;
  assert(!send_netlink_message("event") && !skb_count);
  send_error = -ENOBUFS;
  assert(send_netlink_message("event") == -ENOBUFS && !skb_count);
  send_error = 0;
  for (message_error = 1; message_error <= 2; message_error++) {
    assert(send_netlink_message("event") < 0 && !skb_count);
  }
  message_error = 0;
  assert(!receive(REKERNEL_C_GET_VERSION, -1, 0, false, 1000) && unicasts == 1 && !skb_count);
  assert(receive(REKERNEL_C_GET_VERSION, -1, 0, false, 0) == -EPERM && unicasts == 1);
  assert(receive(REKERNEL_C_EVENT, -1, 0, false, 1000) == -EOPNOTSUPP);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, -1, 0, false, 1000) == -EINVAL);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID, 3, false, 1000) == -EINVAL);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID, 5, false, 1000) == -EINVAL);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID, 4, true, 1000) == -EINVAL);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID | 0x8000, 4, false, 1000) == -EINVAL);
  assert(receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_PID, 4, false, 1000) == -EINVAL);
  assert(!rekernel_net_uid_count);
  assert(!receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID, 4, false, 1000));
  assert(net_uid_monitored(10001) && !net_uid_monitored(10002));
  assert(!receive(REKERNEL_C_ADD_MONITOR_NET, REKERNEL_A_UID, 4, false, 1000) && rekernel_net_uid_count == 1);
  assert(!receive(REKERNEL_C_DEL_MONITOR_NET, REKERNEL_A_UID, 4, false, 1000) && !net_uid_monitored(10001));
  for (uid_t i = 0; i < REKERNEL_NET_UID_MAX; i++) assert(!net_uid_update(i, true));
  assert(net_uid_update(10001, true) == -ENOSPC && !net_uid_monitored(10001));
  assert(!net_uid_update(16, false) && !net_uid_update(10001, true) && net_uid_monitored(10001));
  // 别的 family 与本 family 的权限错误分别保持原函数、返回 ACK 错误。
  struct test_skb packet = {0};
  packet.skb.sk = &socket;
  struct nlmsghdr* nlh = (void*)packet.bytes;
  nlh->nlmsg_type = 38;
  hook_fargs2_t args = {(unsigned long)&packet, (unsigned long)nlh};
  genl_rcv_msg_before(&args, NULL);
  assert(!args.skip_origin);
  nlh->nlmsg_type = 37;
  genl_rcv_msg_before(&args, NULL);
  assert(args.skip_origin && args.ret == -EPERM);
  NETLINK_CB(&packet.skb).creds.uid.val = 1000;
  NETLINK_CB(&packet.skb).portid = 123;
  struct genlmsghdr* hdr = nlmsg_data(nlh);
  *hdr = (struct genlmsghdr){REKERNEL_C_ADD_MONITOR_NET, 1};
  packet.len = NLMSG_HDRLEN + GENL_HDRLEN;
  nlh->nlmsg_len = packet.len - 1;
  assert(rekernel_genl_rcv_msg(&packet.skb, nlh) == -EINVAL);
  nlh->nlmsg_len = packet.len + 1;
  unsigned int calls = ingress_calls;
  assert(receive_packet(&packet.skb, nlh) == 0 && ingress_calls == calls);
  nlh->nlmsg_len = NLMSG_HDRLEN - 1;
  assert(receive_packet(&packet.skb, nlh) == 0 && ingress_calls == calls);
  nlh->nlmsg_len = packet.len;
  hdr->version = 2;
  assert(rekernel_genl_rcv_msg(&packet.skb, nlh) == -EINVAL);
  hdr->version = 1;
  nlh->nlmsg_flags = NLM_F_DUMP;
  assert(rekernel_genl_rcv_msg(&packet.skb, nlh) == -EOPNOTSUPP);
  nlh->nlmsg_flags = 0;
  packet.skb.sk = NULL;
  assert(rekernel_genl_rcv_msg(&packet.skb, nlh) == -ENOENT);
  packet.skb.sk = &socket;
  struct nlattr* attr = (void*)((char*)hdr + GENL_HDRLEN);
  attr->nla_type = REKERNEL_A_UID;
  for (unsigned int size = 0; size <= 12; size++) {
    attr->nla_len = size;
    nlh->nlmsg_len = packet.len = NLMSG_HDRLEN + GENL_HDRLEN + 7;
    assert(rekernel_genl_rcv_msg(&packet.skb, nlh) == -EINVAL);
  }
  // 定种子随机字节覆盖 attribute 长度、对齐和尾部残余；在 sanitizer 下执行。
  uint32_t random = 0x12345678;
  for (unsigned int i = 0; i < 10000; i++) {
    unsigned int len = i % 256;
    for (unsigned int j = 0; j < len; j++) {
      random = random * 1664525u + 1013904223u;
      ((unsigned char*)attr)[j] = random >> 24;
    }
    nlh->nlmsg_len = packet.len = NLMSG_HDRLEN + GENL_HDRLEN + len;
    (void)rekernel_genl_rcv_msg(&packet.skb, nlh);
  }
  unregister_error = -EBUSY;
  assert(stop_rekernel_genl_server() == -EBUSY && allocations == 1 && hook_count == 1);
  unregister_error = 0;
  assert(!stop_rekernel_genl_server() && !allocations && !hook_count);
  assert(!stop_rekernel_genl_server());
  assert(send_netlink_message("event") == -ENOTCONN);
  // 同任务嵌套、另一任务、分配失败的内层调用、after 回收。
  struct binder_transaction_data outer = {0}, inner = {0};
  hook_fargs5_t outer_call = {0, 0, (unsigned long)&outer}, inner_call = {0, 0, (unsigned long)&inner};
  current = (void*)1;
  binder_transaction_before(&outer_call, NULL);
  assert(binder_current_transaction() == &outer);
  current = (void*)2;
  assert(!binder_current_transaction());
  current = (void*)1;
  binder_transaction_before(&inner_call, NULL);
  assert(binder_current_transaction() == &inner);
  binder_transaction_after(&inner_call, NULL);
  assert(binder_current_transaction() == &outer);
  alloc_error = true;
  binder_transaction_before(&inner_call, NULL);
  assert(!binder_current_transaction());
  binder_transaction_after(&inner_call, NULL);
  alloc_error = false;
  assert(binder_current_transaction() == &outer);
  binder_transaction_after(&outer_call, NULL);
  assert(!binder_current_transaction() && !binder_contexts && !binder_context_unavailable && !allocations);
  puts("Genl protocol, failure cleanup and Binder context checks passed");
  return 0;
}
