#ifndef __RE_KERNEL_H
#define __RE_KERNEL_H

#include <ktypes.h>

#include "re_structs.h"

#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a) - 1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define PACKET_SIZE 256
#define MIN_USERAPP_UID 10000
#define MAX_SYSTEM_UID 2000
#define PARCEL_OFFSET 16
#define INTERFACETOKEN_BUFF_SIZE 140

#define REKERNEL_NET_UID_MAX 32

// Sakion 动态版协议；事件仍是 REKERNEL_A_MSG 字符串。
#define REKERNEL_GENL_FAMILY_NAME "rekernel"
#define REKERNEL_GENL_MCGRP_NAME "events"
#define REKERNEL_GENL_VERSION 1
#define REKERNEL_GENL_UID 1000
#define REKERNEL_GENL_MAXATTR 3
enum rekernel_genl_cmd {
  REKERNEL_C_UNSPEC,
  REKERNEL_C_EVENT,
  REKERNEL_C_ADD_MONITOR_NET,
  REKERNEL_C_DEL_MONITOR_NET,
  REKERNEL_C_GET_VERSION,
};
enum rekernel_genl_attr { REKERNEL_A_UNSPEC, REKERNEL_A_MSG, REKERNEL_A_UID, REKERNEL_A_PID };

#endif /* __RE_KERNEL_H */
