/* SPDX-License-Identifier: GPL-3.0-only */
/* Tester: Generic Netlink test client for re_kernel_x (rekernel_x2 family)
 * Supports full UID authentication matrix (AUD-001) & event streaming verification.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REKERNEL_GENL_FAMILY_NAME "rekernel_x2"
#define REKERNEL_GENL_VERSION 1
#define REKERNEL_GENL_MCGRP_NAME "events"

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

static int nla_put(char *buf, int offset, uint16_t type, const void *data, int len) {
  struct nlattr *nla = (struct nlattr *)(buf + offset);
  nla->nla_type = type;
  nla->nla_len = NLA_HDRLEN + len;
  if (data && len > 0)
    memcpy((char *)nla + NLA_HDRLEN, data, len);
  return NLA_ALIGN(nla->nla_len);
}

static int nla_put_u32(char *buf, int offset, uint16_t type, uint32_t val) {
  return nla_put(buf, offset, type, &val, sizeof(val));
}

static int nla_put_u8(char *buf, int offset, uint16_t type, uint8_t val) {
  return nla_put(buf, offset, type, &val, sizeof(val));
}

static int nla_put_s32(char *buf, int offset, uint16_t type, int32_t val) {
  return nla_put(buf, offset, type, &val, sizeof(val));
}

static int nla_put_str(char *buf, int offset, uint16_t type, const char *str) {
  return nla_put(buf, offset, type, str, strlen(str) + 1);
}

struct genl_info {
  uint16_t family_id;
  uint32_t mcast_id;
};

static int resolve_family(int fd, const char *name, struct genl_info *info) {
  char req[256];
  memset(req, 0, sizeof(req));

  struct nlmsghdr *nlh = (struct nlmsghdr *)req;
  nlh->nlmsg_type = GENL_ID_CTRL;
  nlh->nlmsg_flags = NLM_F_REQUEST; /* Do not request ACK for getfamily */
  nlh->nlmsg_seq = 1;

  struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
  gh->cmd = CTRL_CMD_GETFAMILY;
  gh->version = 1;

  int off = NLMSG_LENGTH(GENL_HDRLEN);
  off += nla_put_str(req, off, CTRL_ATTR_FAMILY_NAME, name);
  nlh->nlmsg_len = off;

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  if (sendto(fd, req, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("sendto resolve_family");
    return -1;
  }

  char resp[4096];
  int len = recv(fd, resp, sizeof(resp), 0);
  if (len < 0) {
    perror("recv resolve_family");
    return -1;
  }

  info->family_id = 0;
  info->mcast_id = 0;

  for (nlh = (struct nlmsghdr *)resp; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
    if (nlh->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
      if (err->error != 0) {
        fprintf(stderr, "resolve_family error: %d (%s)\n", err->error, strerror(-err->error));
        return -1;
      }
      continue;
    }
    if (nlh->nlmsg_type != GENL_ID_CTRL)
      continue;

    int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    struct nlattr *attr = (struct nlattr *)((char *)NLMSG_DATA(nlh) + GENL_HDRLEN);

    while (attr_len >= (int)sizeof(struct nlattr)) {
      uint16_t type = attr->nla_type & NLA_TYPE_MASK;
      if (type == CTRL_ATTR_FAMILY_ID) {
        info->family_id = *(uint16_t *)((char *)attr + NLA_HDRLEN);
      } else if (type == CTRL_ATTR_MCAST_GROUPS) {
        int grp_len = attr->nla_len - NLA_HDRLEN;
        struct nlattr *grp_attr = (struct nlattr *)((char *)attr + NLA_HDRLEN);
        while (grp_len >= (int)sizeof(struct nlattr)) {
          int inner_len = grp_attr->nla_len - NLA_HDRLEN;
          struct nlattr *ia = (struct nlattr *)((char *)grp_attr + NLA_HDRLEN);
          char grp_name[64] = {0};
          uint32_t grp_id = 0;
          while (inner_len >= (int)sizeof(struct nlattr)) {
            uint16_t itype = ia->nla_type & NLA_TYPE_MASK;
            if (itype == CTRL_ATTR_MCAST_GRP_NAME) {
              strncpy(grp_name, (char *)ia + NLA_HDRLEN, sizeof(grp_name) - 1);
            } else if (itype == CTRL_ATTR_MCAST_GRP_ID) {
              grp_id = *(uint32_t *)((char *)ia + NLA_HDRLEN);
            }
            inner_len -= NLA_ALIGN(ia->nla_len);
            ia = (struct nlattr *)((char *)ia + NLA_ALIGN(ia->nla_len));
          }
          if (strcmp(grp_name, REKERNEL_GENL_MCGRP_NAME) == 0) {
            info->mcast_id = grp_id;
          }
          grp_len -= NLA_ALIGN(grp_attr->nla_len);
          grp_attr = (struct nlattr *)((char *)grp_attr + NLA_ALIGN(grp_attr->nla_len));
        }
      }
      attr_len -= NLA_ALIGN(attr->nla_len);
      attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
    }
  }

  return (info->family_id > 0) ? 0 : -1;
}

static int send_genl_cmd(int fd, uint16_t family_id, uint8_t cmd, const char *attrs, int attrs_len, int seq) {
  char req[1024];
  memset(req, 0, sizeof(req));

  struct nlmsghdr *nlh = (struct nlmsghdr *)req;
  nlh->nlmsg_type = family_id;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = seq;

  struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
  gh->cmd = cmd;
  gh->version = REKERNEL_GENL_VERSION;

  int off = NLMSG_LENGTH(GENL_HDRLEN);
  if (attrs && attrs_len > 0) {
    memcpy(req + off, attrs, attrs_len);
    off += attrs_len;
  }
  nlh->nlmsg_len = off;

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  if (sendto(fd, req, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("sendto");
    return -1;
  }

  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  char resp[1024];
  while (1) {
    int len = recv(fd, resp, sizeof(resp), 0);
    if (len < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        fprintf(stderr, "timeout waiting for ACK seq=%d\n", seq);
      } else {
        perror("recv ACK");
      }
      return -errno;
    }

    for (nlh = (struct nlmsghdr *)resp; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
      if (nlh->nlmsg_seq != (uint32_t)seq)
        continue;
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        return err->error;
      }
    }
  }
}

static int run_client_suite_as_uid(uid_t target_uid, int expected_rc) {
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (fd < 0) {
    perror("socket(NETLINK_GENERIC)");
    return 1;
  }

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(fd);
    return 1;
  }

  struct genl_info info;
  if (resolve_family(fd, REKERNEL_GENL_FAMILY_NAME, &info) < 0) {
    fprintf(stderr, "[FAIL] Could not resolve family '%s'\n", REKERNEL_GENL_FAMILY_NAME);
    close(fd);
    return 1;
  }

  int passes = 0;
  int total = 4;
  char attr_buf[256];
  int aoff;
  int rc;

  /* 1. ADD_MONITOR_NET */
  aoff = 0;
  aoff += nla_put_u32(attr_buf, aoff, REKERNEL_A_UID, 10088);
  rc = send_genl_cmd(fd, info.family_id, REKERNEL_C_ADD_MONITOR_NET, attr_buf, aoff, 101);
  if (rc == expected_rc) {
    printf("  [PASS] ADD_MONITOR_NET: rc=%d (matches expected %d)\n", rc, expected_rc);
    passes++;
  } else {
    printf("  [FAIL] ADD_MONITOR_NET: rc=%d (expected %d)\n", rc, expected_rc);
  }

  /* 2. DEL_MONITOR_NET */
  aoff = 0;
  aoff += nla_put_u32(attr_buf, aoff, REKERNEL_A_UID, 10088);
  rc = send_genl_cmd(fd, info.family_id, REKERNEL_C_DEL_MONITOR_NET, attr_buf, aoff, 102);
  if (rc == expected_rc) {
    printf("  [PASS] DEL_MONITOR_NET: rc=%d (matches expected %d)\n", rc, expected_rc);
    passes++;
  } else {
    printf("  [FAIL] DEL_MONITOR_NET: rc=%d (expected %d)\n", rc, expected_rc);
  }

  /* 3. ADD_FREE_ASYNC */
  aoff = 0;
  aoff += nla_put_u8(attr_buf, aoff, REKERNEL_A_FREE_ASYNC_STRATEGY, 2 /* BY_CODE */);
  aoff += nla_put_str(attr_buf, aoff, REKERNEL_A_FREE_ASYNC_RPC_NAME, "com.tester.probe");
  aoff += nla_put_s32(attr_buf, aoff, REKERNEL_A_FREE_ASYNC_CODE, 1);
  rc = send_genl_cmd(fd, info.family_id, REKERNEL_C_ADD_FREE_ASYNC, attr_buf, aoff, 103);
  if (rc == expected_rc) {
    printf("  [PASS] ADD_FREE_ASYNC: rc=%d (matches expected %d)\n", rc, expected_rc);
    passes++;
  } else {
    printf("  [FAIL] ADD_FREE_ASYNC: rc=%d (expected %d)\n", rc, expected_rc);
  }

  /* 4. DEL_FREE_ASYNC */
  aoff = 0;
  aoff += nla_put_str(attr_buf, aoff, REKERNEL_A_FREE_ASYNC_RPC_NAME, "com.tester.probe");
  aoff += nla_put_s32(attr_buf, aoff, REKERNEL_A_FREE_ASYNC_CODE, 1);
  rc = send_genl_cmd(fd, info.family_id, REKERNEL_C_DEL_FREE_ASYNC, attr_buf, aoff, 104);
  if (rc == expected_rc) {
    printf("  [PASS] DEL_FREE_ASYNC: rc=%d (matches expected %d)\n", rc, expected_rc);
    passes++;
  } else {
    printf("  [FAIL] DEL_FREE_ASYNC: rc=%d (expected %d)\n", rc, expected_rc);
  }

  close(fd);
  return (passes == total) ? 0 : 1;
}

static int test_multicast_listen(int duration_sec) {
  int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (fd < 0) {
    perror("socket(NETLINK_GENERIC)");
    return 1;
  }

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(fd);
    return 1;
  }

  struct genl_info info;
  if (resolve_family(fd, REKERNEL_GENL_FAMILY_NAME, &info) < 0) {
    fprintf(stderr, "[FAIL] Could not resolve family '%s' for multicast\n", REKERNEL_GENL_FAMILY_NAME);
    close(fd);
    return 1;
  }

  if (info.mcast_id == 0) {
    fprintf(stderr, "[FAIL] Multicast group 'events' not found\n");
    close(fd);
    return 1;
  }

  if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &info.mcast_id, sizeof(info.mcast_id)) < 0) {
    perror("setsockopt(NETLINK_ADD_MEMBERSHIP)");
    close(fd);
    return 1;
  }

  printf("[INFO] Joined multicast group %u ('%s'), listening for %ds...\n",
         info.mcast_id, REKERNEL_GENL_MCGRP_NAME, duration_sec);
  struct timeval tv = {.tv_sec = duration_sec, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  char mbuf[4096];
  int events_received = 0;
  time_t start = time(NULL);
  while (time(NULL) - start < duration_sec) {
    int r = recv(fd, mbuf, sizeof(mbuf), 0);
    if (r <= 0)
      break;
    for (struct nlmsghdr *h = (struct nlmsghdr *)mbuf; NLMSG_OK(h, r); h = NLMSG_NEXT(h, r)) {
      if (h->nlmsg_type == info.family_id) {
        struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(h);
        if (g->cmd == REKERNEL_C_EVENT) {
          events_received++;
          if (events_received <= 3) {
            printf("  -> Live Event #%d received (len=%u, cmd=%u)\n", events_received, h->nlmsg_len, g->cmd);
          }
        }
      }
    }
  }

  printf("[PASS] Multicast event stream: successfully captured %d kernel events\n", events_received);
  close(fd);
  return (events_received > 0) ? 0 : 1;
}

int main(int argc, char **argv) {
  printf("=============================================================\n");
  printf("  re_kernel_x Real-Device Verification Suite (Netlink & Auth)\n");
  printf("=============================================================\n");

  uid_t current_uid = getuid();
  printf("Current process UID: %d, EUID: %d\n", current_uid, geteuid());

  if (current_uid == 0) {
    printf("[MODE] Root execution detected. Running comprehensive AUD-001 UID Auth Matrix:\n\n");
    fflush(stdout);

    struct {
      uid_t uid;
      const char *desc;
      int expected_rc;
    } test_matrix[] = {
        {1000, "AID_SYSTEM (Target Allowed UID)", 0},
        {0, "AID_ROOT (Root - Should be Denied)", -EPERM},
        {2000, "AID_SHELL (ADB Shell - Should be Denied)", -EPERM},
        {10459, "AID_APP (cn.myflv.noactive App UID - Denied)", -EPERM},
    };

    int matrix_passes = 0;
    int matrix_total = sizeof(test_matrix) / sizeof(test_matrix[0]);

    for (int i = 0; i < matrix_total; i++) {
      printf("[TEST UID %d] %s (Expected: %s):\n",
             test_matrix[i].uid, test_matrix[i].desc,
             test_matrix[i].expected_rc == 0 ? "0 (ALLOW)" : "-EPERM (DENY)");
      fflush(stdout);

      pid_t pid = fork();
      if (pid == 0) {
        if (setresgid(test_matrix[i].uid, test_matrix[i].uid, test_matrix[i].uid) < 0 ||
            setresuid(test_matrix[i].uid, test_matrix[i].uid, test_matrix[i].uid) < 0) {
          perror("setresuid failed");
          exit(2);
        }
        int rc = run_client_suite_as_uid(test_matrix[i].uid, test_matrix[i].expected_rc);
        exit(rc);
      } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
          printf("  => Result: PASS\n\n");
          matrix_passes++;
        } else {
          printf("  => Result: FAIL (exit code %d)\n\n", WEXITSTATUS(status));
        }
      } else {
        perror("fork");
      }
    }

    printf("=============================================================\n");
    printf("[MULTICAST STREAMING TEST]\n");
    int mcast_rc = test_multicast_listen(3);

    printf("=============================================================\n");
    printf("Matrix Results: %d/%d UID Tests Passed\n", matrix_passes, matrix_total);
    printf("Multicast Stream: %s\n", mcast_rc == 0 ? "PASS" : "FAIL");
    printf("Overall: %s\n", (matrix_passes == matrix_total && mcast_rc == 0) ? "ALL PASS" : "SOME FAIL");

    return (matrix_passes == matrix_total && mcast_rc == 0) ? 0 : 1;
  } else {
    int expected_rc = (current_uid == 1000) ? 0 : -EPERM;
    printf("[MODE] Single UID execution: UID=%d (Expected RC: %d)\n", current_uid, expected_rc);
    int rc = run_client_suite_as_uid(current_uid, expected_rc);
    int mcast_rc = test_multicast_listen(3);
    return (rc == 0 && mcast_rc == 0) ? 0 : 1;
  }
}
