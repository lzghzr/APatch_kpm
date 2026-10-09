#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#include "re_structs.h"

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a) - 1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define REKERNEL_GENL_FAMILY_NAME "rekernel_x2"
#define REKERNEL_GENL_VERSION 1
#define REKERNEL_GENL_MAXATTR 49
#define REKERNEL_GENL_MCGRP_NAME "events"
#define REKERNEL_GENL_UID 1000

#define PACKET_SIZE 256
#define MIN_USERAPP_UID 10000
#define MAX_SYSTEM_UID 2000
#define PARCEL_OFFSET 16

// 模块内部事件；发送时转换为 Generic Netlink attributes。
#define REKERNEL_EVENT_VERSION 1
#define REKERNEL_RPC_NAME_SIZE 140

#define REKERNEL_NET_UID_MAX 32
#define REKERNEL_FREE_ASYNC_MAX 32
#define REKERNEL_FREE_ASYNC_DATA_BUDGET (64 * 1024)

struct rekernel_free_async_rule {
  char rpc_name[REKERNEL_RPC_NAME_SIZE];
  int code;
  unsigned char strategy;
};

enum rekernel_free_async_strategy {
  REKERNEL_FREE_ASYNC_SKIP = 1,
  REKERNEL_FREE_ASYNC_BY_CODE,
  REKERNEL_FREE_ASYNC_BY_DATA,
};

struct rekernel_binder_context {
  struct task_struct* task;
  void* call;
  struct rekernel_binder_context* next;
};

enum report_type {
  BINDER,
  SIGNAL,
  NETWORK,
};
enum binder_type {
  REPLY,
  TRANSACTION,
  OVERFLOW,
};
// 与 ReKernel-X 的 Generic Netlink 命令和 attribute 编号一致。
enum rekernel_genl_cmd {
  REKERNEL_C_UNSPEC,
  REKERNEL_C_EVENT,
  REKERNEL_C_ADD_MONITOR_NET,
  REKERNEL_C_DEL_MONITOR_NET,
  REKERNEL_C_ADD_FREE_ASYNC,
  REKERNEL_C_DEL_FREE_ASYNC,
};
enum rekernel_genl_attr {
  REKERNEL_A_EVENT = 1,
  REKERNEL_A_BINDER = 10,
  REKERNEL_A_BINDER_TYPE,
  REKERNEL_A_BINDER_ONEWAY,
  REKERNEL_A_BINDER_FROM_PID,
  REKERNEL_A_BINDER_FROM_UID,
  REKERNEL_A_BINDER_TARGET_PID,
  REKERNEL_A_BINDER_TARGET_UID,
  REKERNEL_A_BINDER_CODE,
  REKERNEL_A_BINDER_RPC_NAME,
  REKERNEL_A_SIGNAL = 20,
  REKERNEL_A_SIGNAL_SIGNAL,
  REKERNEL_A_SIGNAL_KILLER_PID,
  REKERNEL_A_SIGNAL_KILLER_UID,
  REKERNEL_A_SIGNAL_DST_PID,
  REKERNEL_A_SIGNAL_DST_UID,
  REKERNEL_A_NETWORK = 30,
  REKERNEL_A_NETWORK_PROTO,
  REKERNEL_A_NETWORK_TARGET_UID,
  REKERNEL_A_NETWORK_DATA_LEN,
  REKERNEL_A_UID = 40,
  REKERNEL_A_FREE_ASYNC_STRATEGY,
  REKERNEL_A_FREE_ASYNC_RPC_NAME,
  REKERNEL_A_FREE_ASYNC_CODE,
};

struct rekernel_event {
  unsigned int version;
  unsigned int type;
  union {
    struct {
      unsigned int type;
      unsigned int oneway;
      unsigned int src_pid;
      unsigned int src_uid;
      unsigned int dst_pid;
      unsigned int dst_uid;
      unsigned int code;
      char rpc_name[REKERNEL_RPC_NAME_SIZE];
    } binder;
    struct {
      unsigned int signum;
      unsigned int src_pid;
      unsigned int src_uid;
      unsigned int dst_pid;
      unsigned int dst_uid;
    } signal;
    struct {
      unsigned int family;
      unsigned int uid;
      unsigned int data_len;
    } network;
  };
};

_Static_assert(sizeof(unsigned int) == 4, "rekernel protocol requires 32-bit unsigned int");
_Static_assert(sizeof(struct rekernel_event) == 176, "rekernel event layout changed");

#endif /* __RE_KERNEL_H */
