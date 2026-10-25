/* SPDX-License-Identifier: GPL-2.0-only */
/* Wire layout from maxsteeel/nomount kernel/src/nomount.h,
 * commit bf1847f98fed382369c43bfd652cd93774b9b8e3; checked 2026-10-22. */
#ifndef __NM_PROTOCOL_H
#define __NM_PROTOCOL_H

#define NOMOUNT_MAGIC_SIG 0x4E4F4D4F554E54ULL
#define NM_KPM_VERSION "2.2.0-20261022"
#define NM_CONTROL_VERSION "22 (KPM " NM_KPM_VERSION ")"

enum nm_command {
  NM_CMD_UNSPEC = 0,
  NM_CMD_GET_VERSION,
  NM_CMD_ADD_RULE,
  NM_CMD_DEL_RULE,
  NM_CMD_ADD_UID,
  NM_CMD_DEL_UID,
  NM_CMD_CLEAR_ALL,
  NM_CMD_CLEAR_RULES,
  NM_CMD_CLEAR_UIDS,
  NM_CMD_GET_LIST,
  NM_CMD_GET_UIDS,
  NM_CMD_BLOCK_ISOLATED_UIDS,
  NM_CMD_GET_ISOLATED_STATE,
};

struct nm_payload {
  u64 magic;
  u32 cmd;
  u32 target_uid;
  int status;
  u32 arg1;
  u32 data_size;
  char buffer[4068];
} __attribute__((packed));

struct nm_rule_hdr {
  u32 flags;
  u32 uid;
  u32 uid_end;
  u32 deny_start;
  u32 deny_end;
  u16 v_len;
  u16 r_len;
} __attribute__((packed));

struct nm_del_hdr {
  u32 uid;
  u32 uid_end;
  u32 deny_start;
  u32 deny_end;
  u16 v_len;
} __attribute__((packed));

_Static_assert(sizeof(struct nm_payload) == 4096, "NoMount payload ABI");
_Static_assert(offsetof(struct nm_payload, buffer) == 28, "NoMount payload header ABI");
_Static_assert(sizeof(struct nm_rule_hdr) == 24, "NoMount v22 rule header ABI");
_Static_assert(sizeof(struct nm_del_hdr) == 18, "NoMount v22 deletion header ABI");

#endif
