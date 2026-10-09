// 执行生产 before 和释放分派；锁桩仅核对顺序，不证明目标内核并发安全。
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define TF_ONE_WAY 1
#define TF_UPDATE_TXN 0x40
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define kvar(name) kv_##name
typedef uintptr_t binder_uintptr_t;
typedef size_t binder_size_t;
typedef int atomic_t;
struct list_head {
  struct list_head* next;
  struct list_head* prev;
};
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member)                                         \
  for (pos = container_of((head)->next, typeof(*pos), member); &pos->member != (head); \
       pos = container_of(pos->member.next, typeof(*pos), member))
static void list_add_tail(struct list_head* entry, struct list_head* head) {
  entry->prev = head->prev;
  entry->next = head;
  head->prev->next = entry;
  head->prev = entry;
}
static void list_del_init(struct list_head* entry) {
  entry->prev->next = entry->next;
  entry->next->prev = entry->prev;
  entry->next = entry->prev = entry;
}
struct binder_alloc {
  int unused;
};
struct binder_proc {
  void* tsk;
  struct binder_alloc alloc;
  bool is_dead;
  bool is_frozen;
  int outstanding_txns;
};
struct binder_node {
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
  bool has_async_transaction;
  struct list_head async_todo;
};
struct binder_transaction;
struct binder_buffer {
  struct binder_node* target_node;
  struct binder_transaction* transaction;
  size_t data_size;
  size_t offsets_size;
  size_t extra_buffers_size;
  int pid;
};
enum { BINDER_WORK_TRANSACTION = 1 };
enum binder_stat_types { BINDER_STAT_TRANSACTION = 0 };
struct binder_work {
  struct list_head entry;
  int type;
};
struct binder_transaction {
  struct binder_work work;
  struct binder_proc* to_proc;
  struct binder_buffer* buffer;
  unsigned int code;
  unsigned int flags;
};
struct binder_thread;
typedef struct {
  uintptr_t arg0, arg1, arg2;
} hook_fargs3_t;
static bool trace = true, frozen = true, freeze_on_lock;
static unsigned int lock_level, releases, frees, fixups, transactions;
static struct binder_buffer* released;
static struct binder_transaction* discarded;
static struct binder_proc* target;
static atomic_t stats_deleted;
static atomic_t* kv_binder_stats = &stats_deleted;
static bool binder_transaction_buffer_release_ver4, binder_transaction_buffer_release_ver5,
    binder_transaction_buffer_release_ver6;
static void (*binder_free_txn_fixups)(struct binder_transaction*);
static bool frozen_task_group(void* task) { return frozen; }
static void binder_node_lock(struct binder_node* node) { assert(lock_level++ == 0); }
static void binder_inner_proc_lock(struct binder_proc* proc) {
  assert(lock_level++ == 1);
  if (freeze_on_lock)
    proc->is_frozen = true;
}
static void binder_inner_proc_unlock(struct binder_proc* proc) { assert(--lock_level == 1); }
static void binder_node_unlock(struct binder_node* node) { assert(--lock_level == 0); }
static void rekernel_binder_transaction(void* data, bool reply, struct binder_transaction* t, void* node) {}
static void atomic_inc(atomic_t* value) { (*value)++; }
static void kfree(struct binder_transaction* t) {
  assert(!lock_level && t == discarded && !t->buffer);
  transactions++;
}
static void cleanup_fixups(struct binder_transaction* t) {
  assert(!lock_level && t == discarded && !t->buffer);
  fixups++;
}
static void binder_alloc_free_buf(struct binder_alloc* alloc, struct binder_buffer* buffer) {
  assert(!lock_level && alloc == &target->alloc && buffer == released && releases == 1);
  frees++;
}
static void release_buffer(struct binder_proc* proc, struct binder_buffer* buffer) {
  assert(!lock_level && proc == target && buffer == released);
  assert(!buffer->transaction && !discarded->buffer);
  releases++;
}
static void release3(struct binder_proc* proc, struct binder_buffer* buffer, binder_size_t* failed_at) {
  assert(!failed_at);
  release_buffer(proc, buffer);
}
static void release4(struct binder_proc* proc, struct binder_buffer* buffer, binder_size_t end, bool failure) {
  assert(end == 0 && failure);
  release_buffer(proc, buffer);
}
static void release5(struct binder_proc* proc, struct binder_thread* thread, struct binder_buffer* buffer,
                     binder_size_t end, bool failure) {
  assert(!thread && failure);
  assert(end == (binder_transaction_buffer_release_ver6 ? 0 : ALIGN(buffer->data_size, sizeof(void*))));
  release_buffer(proc, buffer);
}
static void (*binder_transaction_buffer_release_v3)(struct binder_proc*, struct binder_buffer*, binder_size_t*);
static void (*binder_transaction_buffer_release_v4)(struct binder_proc*, struct binder_buffer*, binder_size_t, bool);
static void (*binder_transaction_buffer_release)(struct binder_proc*, struct binder_thread*, struct binder_buffer*,
                                                 binder_size_t, bool);
static void (*binder_transaction_buffer_release_v6)(struct binder_proc*, struct binder_thread*, struct binder_buffer*,
                                                    binder_size_t, bool);

/* PRODUCTION_FUNCTIONS */

int main(void) {
  struct_offset.binder_transaction_to_proc = offsetof(struct binder_transaction, to_proc);
  struct_offset.binder_transaction_buffer = offsetof(struct binder_transaction, buffer);
  struct_offset.binder_transaction_code = offsetof(struct binder_transaction, code);
  struct_offset.binder_transaction_flags = offsetof(struct binder_transaction, flags);
  struct_offset.binder_node_ptr = offsetof(struct binder_node, ptr);
  struct_offset.binder_node_cookie = offsetof(struct binder_node, cookie);
  struct_offset.binder_node_async_todo = offsetof(struct binder_node, async_todo);
  struct_offset.binder_node_has_async_transaction = offsetof(struct binder_node, has_async_transaction);
  struct_offset.binder_proc_alloc = offsetof(struct binder_proc, alloc);
  struct_offset.binder_proc_is_dead = offsetof(struct binder_proc, is_dead);
  struct_offset.binder_proc_is_frozen = offsetof(struct binder_proc, is_frozen);
  struct_offset.binder_proc_outstanding_txns = offsetof(struct binder_proc, outstanding_txns);
  binder_transaction_buffer_release_v3 = release3;
  binder_transaction_buffer_release_v4 = release4;
  binder_transaction_buffer_release = binder_transaction_buffer_release_v6 = release5;
  unsigned int cases = 0;
  for (unsigned int abi = 3; abi <= 6; abi++) {
    binder_transaction_buffer_release_ver4 = abi == 4;
    binder_transaction_buffer_release_ver5 = abi == 5;
    binder_transaction_buffer_release_ver6 = abi == 6;
    for (unsigned int mode = 0; mode < 10; mode++) {
      struct binder_proc proc = {.tsk = &proc, .outstanding_txns = 2};
      struct binder_node node = {.ptr = 11, .cookie = 22, .has_async_transaction = true};
      node.async_todo.next = node.async_todo.prev = &node.async_todo;
      struct binder_buffer buffers[3];
      struct binder_transaction txns[3];
      for (unsigned int i = 0; i < 3; i++) {
        buffers[i] = (struct binder_buffer){.target_node = &node, .transaction = &txns[i], .data_size = 17, .pid = 7};
        txns[i] = (struct binder_transaction){
            .to_proc = &proc, .buffer = &buffers[i], .code = 9, .flags = TF_ONE_WAY | TF_UPDATE_TXN};
        txns[i].work.type = BINDER_WORK_TRANSACTION;
        if (i < 2 && !(mode == 1 && i == 1))
          list_add_tail(&txns[i].work.entry, &node.async_todo);
      }
      frozen = mode != 2;
      proc.is_dead = mode == 3;
      proc.is_frozen = mode == 4;
      freeze_on_lock = mode == 5;
      node.has_async_transaction = mode != 6;
      buffers[0].offsets_size = mode == 7 ? 8 : 0;
      buffers[2].extra_buffers_size = mode == 8 ? 8 : 0;
      binder_free_txn_fixups = mode == 9 ? NULL : cleanup_fixups;
      target = &proc;
      released = &buffers[0];
      discarded = &txns[0];
      releases = frees = fixups = transactions = stats_deleted = 0;
      hook_fargs3_t args = {.arg0 = (uintptr_t)&txns[2], .arg1 = (uintptr_t)&proc};
      binder_proc_transaction_before(&args, NULL);
      bool clean = mode == 0 || mode == 9;
      assert(!lock_level && releases == clean && frees == clean && transactions == clean);
      assert(fixups == (mode == 0) && stats_deleted == clean);
      assert(proc.outstanding_txns == 2 - clean);
      assert(txns[2].buffer == &buffers[2] && buffers[2].transaction == &txns[2]);
      assert(txns[1].buffer == &buffers[1]);
      if (clean)
        assert(node.async_todo.next == &txns[1].work.entry && node.async_todo.prev == &txns[1].work.entry);
      cases++;
    }
  }
  printf(
      "production before cleanup: %u ABI/state/object/release cases; incoming and newer old message retained: PASS\n",
      cases);
}
