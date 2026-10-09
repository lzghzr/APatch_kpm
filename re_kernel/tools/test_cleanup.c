// 运行生产偏移读取、匹配和队列选择；不模拟目标锁、释放或应用语义。
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define TF_ONE_WAY 1
typedef uintptr_t binder_uintptr_t;
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
static void list_del(struct list_head* entry) {
  entry->prev->next = entry->next;
  entry->next->prev = entry->prev;
}
struct binder_proc {
  void* tsk;
};
struct binder_node {
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
};
struct binder_buffer {
  struct binder_node* target_node;
  int pid;
  size_t offsets_size;
  size_t extra_buffers_size;
};
enum { BINDER_WORK_TRANSACTION = 1, BINDER_WORK_TRANSACTION_COMPLETE };
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

/* PRODUCTION_FUNCTIONS */

int main(void) {
  struct_offset.binder_transaction_to_proc = offsetof(struct binder_transaction, to_proc);
  struct_offset.binder_transaction_buffer = offsetof(struct binder_transaction, buffer);
  struct_offset.binder_transaction_code = offsetof(struct binder_transaction, code);
  struct_offset.binder_transaction_flags = offsetof(struct binder_transaction, flags);
  struct_offset.binder_node_ptr = offsetof(struct binder_node, ptr);
  struct_offset.binder_node_cookie = offsetof(struct binder_node, cookie);
  struct binder_proc proc = {.tsk = &proc};
  struct binder_node node = {.ptr = 11, .cookie = 22};
  struct binder_buffer buffer = {.target_node = &node, .pid = 7};
  struct binder_transaction incoming = {.to_proc = &proc, .buffer = &buffer, .code = 9, .flags = TF_ONE_WAY};
  unsigned int cases = 0;
  for (unsigned int frozen = 0; frozen < 2; frozen++) {
    struct_offset.binder_proc_is_frozen = frozen ? 1 : 0;
    for (unsigned int count = 0; count <= 4; count++) {
      struct list_head queue = {.next = &queue, .prev = &queue};
      struct binder_work ignored = {.type = BINDER_WORK_TRANSACTION_COMPLETE};
      struct binder_transaction unrelated = incoming;
      unrelated.work.type = BINDER_WORK_TRANSACTION;
      unrelated.code++;
      list_add_tail(&ignored.entry, &queue);
      list_add_tail(&unrelated.work.entry, &queue);
      struct binder_transaction old[4];
      for (unsigned int i = 0; i < count; i++) {
        old[i] = incoming;
        old[i].work.type = BINDER_WORK_TRANSACTION;
        list_add_tail(&old[i].work.entry, &queue);
      }
      struct binder_transaction* chosen = binder_find_outdated_transaction_ilocked(&incoming, &queue);
      assert(chosen == (count >= 2 ? &old[0] : NULL));
      if (chosen) {
        list_del(&chosen->work.entry);
        // before 每次仅选最早匹配者；原调用失败时仍保留旧消息。
        assert(queue.prev == &old[count - 1].work.entry);
        assert(binder_find_outdated_transaction_ilocked(&incoming, &queue) == (count >= 3 ? &old[1] : NULL));
      }
      assert(incoming.to_proc == &proc && incoming.code == 9 && incoming.flags == TF_ONE_WAY);
      cases++;
    }
    struct binder_transaction mismatch = incoming;
    struct binder_buffer other_buffer = buffer;
    mismatch.buffer = &other_buffer;
    other_buffer.pid++;
    assert(binder_can_update_transaction(&incoming, &mismatch) == !frozen);
  }
  struct binder_buffer other_buffer = buffer;
  struct binder_transaction mismatch = incoming;
  mismatch.buffer = &other_buffer;
  other_buffer.offsets_size = 8;
  assert(!binder_can_update_transaction(&incoming, &mismatch));
  assert(!binder_can_update_transaction(&mismatch, &incoming));
  other_buffer.offsets_size = 0;
  other_buffer.extra_buffers_size = 8;
  assert(!binder_can_update_transaction(&incoming, &mismatch));
  assert(!binder_can_update_transaction(&mismatch, &incoming));
  other_buffer.extra_buffers_size = 0;
  struct binder_proc other_proc = proc;
  mismatch.to_proc = &other_proc;
  assert(!binder_can_update_transaction(&incoming, &mismatch));
  mismatch.to_proc = &proc;
  other_buffer.target_node = NULL;
  assert(!binder_can_update_transaction(&incoming, &mismatch));
  mismatch.buffer = NULL;
  assert(!binder_can_update_transaction(&incoming, &mismatch));
  printf(
      "production FIFO cleanup: %u zero/one/backlog cases; oldest selected, newer retained, unrelated work/code "
      "ignored, incoming intact, PID layouts: PASS\n",
      cases);
}
