#ifndef __RUN_CMD_H
#define __RUN_CMD_H

#include <linux/list.h>

struct subprocess_info;
struct kthread_worker;
struct lock_class_key;
// 摘自 Android 5.15 的 linux/kthread.h。
struct kthread_work {
  struct list_head node;
  void (*func)(struct kthread_work* work);
  struct kthread_worker* worker;
  int canceling;
};

#define RUN_CMD_REPLY_SIZE 32
#define RUN_CMD_MAX_SIZE 4096
#define RUN_CMD_CONTEXT "u:r:magisk:s0"

enum run_cmd_status { CMD_IDLE, CMD_PENDING, CMD_DONE };

#endif /* __RUN_CMD_H */
