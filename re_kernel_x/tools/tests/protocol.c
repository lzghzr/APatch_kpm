#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "re_kernel_host.h"

#define ENOMEM 12
#define EMSGSIZE 90
#define GFP_ATOMIC 0
#define MSG_DONTWAIT 1
#define IS_ERR(p) ((uintptr_t)(p) > UINTPTR_MAX - 4096)
#define logkm(...) ((void)0)

typedef int pid_t;
struct task_struct {
  unsigned int uid;
};
typedef struct {
  uintptr_t arg0, arg1, arg2, arg3, arg4;
} hook_fargs5_t;
struct uid_value {
  unsigned int val;
};
struct binder_transaction_data {
  unsigned int code;
  size_t data_size;
  struct {
    struct {
      uintptr_t buffer;
    } ptr;
  } data;
};
static _Thread_local struct task_struct* current;
static struct rekernel_binder_context* binder_contexts;
static unsigned int binder_context_guard, binder_context_unavailable;
static pthread_mutex_t context_mutex = PTHREAD_MUTEX_INITIALIZER;
static int context_alloc_error, context_allocated, context_freed;
static bool rekernel_genl_registered = true;
static struct rekernel_event captured;
static int sent, copy_error, frozen = 1;

static bool frozen_task_group(struct task_struct* task) { return frozen && task; }
static struct uid_value task_uid(struct task_struct* task) { return (struct uid_value){task->uid}; }
static unsigned long rekernel_context_lock(unsigned int* lock) {
  assert(pthread_mutex_lock(&context_mutex) == 0);
  return 123;
}
static void rekernel_context_unlock(unsigned int* lock, unsigned long flags) {
  assert(flags == 123);
  assert(pthread_mutex_unlock(&context_mutex) == 0);
}
static void* kmalloc(size_t size, int flags) {
  if (context_alloc_error)
    return NULL;
  void* ptr = malloc(size);
  assert(ptr);
  __atomic_add_fetch(&context_allocated, 1, __ATOMIC_RELAXED);
  return ptr;
}
static void kfree(void* ptr) {
  __atomic_add_fetch(&context_freed, 1, __ATOMIC_RELAXED);
  free(ptr);
}
static void* memdup_user(const void* data, size_t len) {
  if (copy_error)
    return (void*)(uintptr_t)-ENOMEM;
  void* copy = malloc(len ? len : 1);
  assert(copy);
  memcpy(copy, data, len);
  return copy;
}
static void kvfree(void* data) { free(data); }
static int send_netlink_message(const struct rekernel_event* msg) {
  captured = *msg;
  sent++;
  return 0;
}

// 测试脚本在这里插入生产 send_netlink_message 和 rekernel_report。
/* PRODUCTION_FUNCTIONS */

static void zero_tail(size_t start) {
  const unsigned char* bytes = (const unsigned char*)&captured;
  for (size_t i = start; i < sizeof(captured); i++) assert(bytes[i] == 0);
}

static void* context_thread(void* data) {
  struct task_struct task = {(unsigned int)(uintptr_t)data};
  struct binder_transaction_data tr = {0};
  current = &task;
  for (int i = 0; i < 500; i++) {
    hook_fargs5_t call = {.arg2 = (uintptr_t)&tr};
    binder_transaction_before(&call, NULL);
    assert(binder_current_transaction() == &tr);
    binder_transaction_after(&call, NULL);
    assert(binder_current_transaction() == NULL);
  }
  return NULL;
}

int main(void) {
  struct task_struct src = {10001}, dst = {10002};
  current = &src;
  rekernel_report(NETWORK, 6, 123, NULL, 10042, NULL, true);
  assert(sent == 1 && captured.version == 1 && captured.type == NETWORK);
  assert(captured.network.family == 6 && captured.network.uid == 10042 && captured.network.data_len == 123);
  zero_tail(8 + sizeof(captured.network));

  rekernel_report(BINDER, REPLY, 11, &src, 22, &dst, false);
  assert(sent == 2 && captured.type == BINDER && captured.binder.type == REPLY);
  assert(captured.binder.src_pid == 11 && captured.binder.dst_pid == 22);
  assert(captured.binder.src_uid == 10001 && captured.binder.dst_uid == 10002);
  assert(!captured.binder.oneway && !captured.binder.code);
  zero_tail(8 + 7 * 4);

  unsigned char parcel[PARCEL_OFFSET + REKERNEL_RPC_NAME_SIZE * 2] = {0};
  parcel[PARCEL_OFFSET] = 'a';
  parcel[PARCEL_OFFSET + 2] = 'b';
  struct binder_transaction_data tr = {29, sizeof(parcel), {{(uintptr_t)parcel}}};
  hook_fargs5_t call = {.arg2 = (uintptr_t)&tr};
  binder_transaction_before(&call, NULL);
  rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
  assert(sent == 3 && captured.binder.oneway && captured.binder.code == 29);
  assert(!strcmp(captured.binder.rpc_name, "ab"));
  zero_tail(8 + 7 * 4 + 3);
  for (size_t len = 0; len <= PARCEL_OFFSET + 2; len++) {
    tr.data_size = len;
    rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
    assert(captured.binder.rpc_name[0] == (len > PARCEL_OFFSET + 1 ? 'a' : 0));
  }
  tr.data_size = sizeof(parcel);
  for (size_t i = PARCEL_OFFSET; i + 1 < sizeof(parcel); i += 2) parcel[i] = 'x';
  rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
  assert(strlen(captured.binder.rpc_name) == REKERNEL_RPC_NAME_SIZE - 1);
  zero_tail(8 + 7 * 4 + strlen(captured.binder.rpc_name) + 1);

  rekernel_report(SIGNAL, 9, 11, &src, 22, &dst, false);
  assert(captured.type == SIGNAL && captured.signal.signum == 9);
  assert(captured.signal.src_pid == 11 && captured.signal.dst_uid == 10002);
  zero_tail(8 + sizeof(captured.signal));
  int before = sent;
  dst.uid = src.uid;
  rekernel_report(SIGNAL, 9, 11, &src, 22, &dst, false);
  dst.uid++;
  frozen = 0;
  rekernel_report(SIGNAL, 9, 11, &src, 22, &dst, false);
  frozen = 1;
  unsigned int codes[] = {0, 28, 29, 32, 33, 0x7fffffff, 0xffffffff};
  for (unsigned int i = 0; i < ARRAY_SIZE(codes); i++) {
    tr.code = codes[i];
    rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
    assert(sent == ++before && captured.binder.code == codes[i]);
  }
  tr.code = 29;
  copy_error = 1;
  rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
  copy_error = 0;
  call.arg2 = 0;
  rekernel_report(BINDER, TRANSACTION, 11, &src, 22, &dst, true);
  assert(sent == before);
  binder_transaction_after(&call, NULL);

  // 同任务嵌套、参数后续变更、另一任务穿插，以及分配失败不误用外层参数。
  call.arg2 = (uintptr_t)&tr;
  binder_transaction_before(&call, NULL);
  struct binder_transaction_data inner = {0};
  hook_fargs5_t nested = {.arg2 = (uintptr_t)&inner};
  binder_transaction_before(&nested, NULL);
  assert(binder_current_transaction() == &inner);
  nested.arg2 = (uintptr_t)&tr;
  assert(binder_current_transaction() == &tr);
  current = &dst;
  assert(binder_current_transaction() == NULL);
  hook_fargs5_t other = {.arg2 = (uintptr_t)&inner};
  binder_transaction_before(&other, NULL);
  assert(binder_current_transaction() == &inner);
  current = &src;
  binder_transaction_after(&nested, NULL);
  assert(binder_current_transaction() == &tr);
  context_alloc_error = 1;
  binder_transaction_before(&nested, NULL);
  assert(binder_current_transaction() == NULL);
  context_alloc_error = 0;
  binder_transaction_after(&nested, NULL);
  assert(!binder_context_unavailable && binder_current_transaction() == &tr);
  binder_transaction_after(&call, NULL);
  current = &dst;
  assert(binder_current_transaction() == &inner);
  binder_transaction_after(&other, NULL);
  assert(!binder_contexts);
  current = &src;

  pthread_t threads[8];
  for (uintptr_t i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, context_thread, (void*)(10000 + i)) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(!binder_contexts && !binder_context_unavailable && context_allocated == context_freed);
  puts("production internal events: zero tail, all code values reported, filters, 139-byte RPC boundaries: PASS");
  puts("production Binder contexts: nesting, task isolation, argument changes, allocation failure, 8 threads: PASS");
}
