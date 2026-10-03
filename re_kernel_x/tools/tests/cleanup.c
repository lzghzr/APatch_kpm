#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REKERNEL_BINDER_ABI 6
#include "re_kernel_host.h"
#define TF_ONE_WAY 1
#define container_of(p, t, m) ((t*)((char*)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
  for (p = container_of((h)->next, __typeof__(*p), m); &p->m != (h); p = container_of(p->m.next, __typeof__(*p), m))
#define kvar(n) (&stats)
typedef uint32_t u32;
typedef size_t binder_size_t;
typedef uintptr_t binder_uintptr_t;
typedef struct {
  int value;
} atomic_t;
static _Thread_local int release_phase;
static void atomic_inc(atomic_t* a) {
  assert(release_phase == 4);
  release_phase = 0;
  __atomic_add_fetch(&a->value, 1, __ATOMIC_RELAXED);
}
struct list_head {
  struct list_head *next, *prev;
};
static void INIT_LIST_HEAD(struct list_head* h) { h->next = h->prev = h; }
static void __list_add(struct list_head* n, struct list_head* p, struct list_head* q) {
  q->prev = n;
  n->next = q;
  n->prev = p;
  p->next = n;
}
static void list_del_init(struct list_head* n) {
  n->prev->next = n->next;
  n->next->prev = n->prev;
  INIT_LIST_HEAD(n);
}
struct task_struct {
  bool frozen;
};
struct binder_alloc {
  int unused;
};
struct binder_proc {
  struct task_struct* tsk;
  pthread_mutex_t lock;
  int tmp_ref, outstanding;
  bool dead, frozen, released;
  struct binder_alloc alloc;
};
struct binder_node {
  pthread_mutex_t lock;
  struct list_head todo;
  bool has_async;
  binder_uintptr_t ptr, cookie;
};
struct binder_work {
  struct list_head entry;
  enum { BINDER_WORK_TRANSACTION = 1 } type;
};
struct binder_thread;
struct binder_buffer {
  bool free;
  void* kernel_data;
  struct binder_transaction* transaction;
  struct binder_node* target_node;
  size_t data_size, offsets_size, extra_buffers_size;
  int pid;
  unsigned char data[REKERNEL_FREE_ASYNC_DATA_BUDGET];
};
struct binder_transaction {
  int debug_id;
  struct binder_work work;
  struct binder_proc* proc;
  struct binder_buffer* buffer;
  unsigned int code, flags;
};
enum binder_stat_types { BINDER_STAT_TRANSACTION };
static struct {
  atomic_t deleted;
} stats;
static struct {
  int16_t binder_proc_is_dead, binder_proc_outstanding_txns, binder_proc_is_frozen;
  int16_t binder_transaction_buffer, binder_transaction_to_proc, binder_transaction_code, binder_transaction_flags;
  int16_t binder_node_ptr, binder_node_cookie, binder_stats_deleted_transaction, binder_buffer_data;
} struct_offset = {offsetof(struct binder_proc, dead),
                   offsetof(struct binder_proc, outstanding),
                   offsetof(struct binder_proc, frozen),
                   offsetof(struct binder_transaction, buffer),
                   offsetof(struct binder_transaction, proc),
                   offsetof(struct binder_transaction, code),
                   offsetof(struct binder_transaction, flags),
                   offsetof(struct binder_node, ptr),
                   offsetof(struct binder_node, cookie),
                   offsetof(__typeof__(stats), deleted),
                   -1};
typedef struct {
  uintptr_t arg0, arg1, arg2;
} hook_fargs3_t;
static unsigned long trace = IZERO;
static int notifications;
static _Thread_local int node_locked, proc_locked;
static void binder_node_lock(struct binder_node* n) {
  assert(!node_locked && !proc_locked);
  pthread_mutex_lock(&n->lock);
  node_locked = 1;
}
static void binder_node_unlock(struct binder_node* n) {
  assert(node_locked && !proc_locked);
  node_locked = 0;
  pthread_mutex_unlock(&n->lock);
}
static void binder_inner_proc_lock(struct binder_proc* p) {
  assert(node_locked && !proc_locked);
  pthread_mutex_lock(&p->lock);
  proc_locked = 1;
}
static void binder_inner_proc_unlock(struct binder_proc* p) {
  assert(proc_locked);
  proc_locked = 0;
  pthread_mutex_unlock(&p->lock);
}
static bool frozen_task_group(struct task_struct* p) { return p->frozen; }
static bool binder_node_has_async_transaction(struct binder_node* n) {
  assert(node_locked);
  return n->has_async;
}
static struct list_head* binder_node_async_todo(struct binder_node* n) {
  assert(node_locked && proc_locked);
  return &n->todo;
}
static struct binder_alloc* binder_proc_alloc(struct binder_proc* p) {
  if (!proc_locked)
    pthread_mutex_lock(&p->lock);
  assert(!p->released && p->tmp_ref > 0);
  if (!proc_locked)
    pthread_mutex_unlock(&p->lock);
  return &p->alloc;
}
static int transaction_frees, buffer_frees, releases, fixup_calls;
static bool block_release, entered_release, resume_release;
static pthread_mutex_t release_guard = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t release_cond = PTHREAD_COND_INITIALIZER;
static void native_release(struct binder_proc* p,
#if REKERNEL_BINDER_ABI >= 5
                           struct binder_thread* t,
#endif
                           struct binder_buffer* b,
#if REKERNEL_BINDER_ABI == 3
                           binder_size_t* end
#else
                           binder_size_t end, bool failure
#endif
) {
  assert(!node_locked && !proc_locked && !release_phase);
  pthread_mutex_lock(&p->lock);
  assert(!p->released && p->tmp_ref > 0 && !b->transaction);
  pthread_mutex_unlock(&p->lock);
  assert(!b->offsets_size && !b->extra_buffers_size);
#if REKERNEL_BINDER_ABI >= 5
  assert(!t);
#endif
#if REKERNEL_BINDER_ABI != 3
  assert(failure);
#endif
#if REKERNEL_BINDER_ABI == 5
  assert(end == ALIGN(b->data_size, sizeof(void*)) + b->offsets_size);
#else
  assert(!end);
#endif
  if (block_release) {
    pthread_mutex_lock(&release_guard);
    entered_release = true;
    pthread_cond_broadcast(&release_cond);
    while (!resume_release) pthread_cond_wait(&release_cond, &release_guard);
    pthread_mutex_unlock(&release_guard);
    pthread_mutex_lock(&p->lock);
    assert(!p->released && p->tmp_ref == 1);
    pthread_mutex_unlock(&p->lock);
  }
  release_phase = 1;
  __atomic_add_fetch(&releases, 1, __ATOMIC_RELAXED);
}
static void native_free_buf(struct binder_alloc* a, struct binder_buffer* b) {
  assert(!node_locked && !proc_locked && release_phase == 1 && !b->transaction);
  release_phase = 2;
  __atomic_add_fetch(&buffer_frees, 1, __ATOMIC_RELAXED);
  free(b);
}
static void native_fixups(struct binder_transaction* t) {
  assert(!node_locked && !proc_locked && release_phase == 2 && !t->buffer);
  release_phase = 3;
  __atomic_add_fetch(&fixup_calls, 1, __ATOMIC_RELAXED);
}
static void kfree(struct binder_transaction* t) {
  assert(!node_locked && !proc_locked && !t->buffer);
  assert(release_phase == 2 || release_phase == 3);
  release_phase = 4;
  __atomic_add_fetch(&transaction_frees, 1, __ATOMIC_RELAXED);
  free(t);
}
static __typeof__(&native_release) binder_transaction_buffer_release = native_release;
static void (*binder_alloc_free_buf)(struct binder_alloc*, struct binder_buffer*) = native_free_buf;
static void (*binder_free_txn_fixups)(struct binder_transaction*) = native_fixups;
static void rekernel_binder_transaction(void* a, bool b, void* c, void* d) {
  __atomic_add_fetch(&notifications, 1, __ATOMIC_RELAXED);
}
static struct rekernel_free_async_rule rekernel_free_async_rules[REKERNEL_FREE_ASYNC_MAX];
static unsigned int rekernel_free_async_count, rekernel_free_async_guard;
static pthread_mutex_t rule_guard = PTHREAD_MUTEX_INITIALIZER;
static unsigned long rekernel_context_lock(unsigned int* lock) {
  assert(lock == &rekernel_free_async_guard && !node_locked && !proc_locked);
  pthread_mutex_lock(&rule_guard);
  return 123;
}
static void rekernel_context_unlock(unsigned int* lock, unsigned long flags) {
  assert(lock == &rekernel_free_async_guard && flags == 123);
  pthread_mutex_unlock(&rule_guard);
}
static bool buffer_copy_error;
static _Thread_local unsigned int data_copy_calls, data_copy_fail_call;
static _Thread_local size_t data_copy_bytes;
static int native_buffer_copy(struct binder_alloc* alloc, void* dest, struct binder_buffer* buffer,
                              binder_size_t offset, size_t bytes) {
  assert(node_locked == proc_locked);
  assert(offset <= buffer->data_size && bytes <= buffer->data_size - offset);
  assert(offset <= sizeof(buffer->data) && bytes <= sizeof(buffer->data) - offset && !(offset % 4));
  if (node_locked) {
    assert(bytes <= 64);
    data_copy_calls++;
    data_copy_bytes += bytes;
    assert(data_copy_bytes <= REKERNEL_FREE_ASYNC_DATA_BUDGET);
    if (data_copy_calls == data_copy_fail_call)
      return -EFAULT;
  } else {
    assert(offset == 0 && bytes <= PARCEL_OFFSET + REKERNEL_RPC_NAME_SIZE * 2);
  }
  if (buffer_copy_error)
    return -EFAULT;
  memcpy(dest, buffer->data + offset, bytes);
  return 0;
}
static int (*kf_binder_alloc_copy_from_buffer)(struct binder_alloc*, void*, struct binder_buffer*, binder_size_t,
                                               size_t) = native_buffer_copy;
/* PRODUCTION_FUNCTIONS */
static struct binder_transaction* new_tx(struct binder_proc* p, struct binder_node* n, unsigned int code) {
  struct binder_transaction* t = calloc(1, sizeof(*t));
  struct binder_buffer* b = calloc(1, sizeof(*b));
  assert(t && b);
  t->proc = p;
  t->buffer = b;
  t->code = code;
  t->flags = TF_ONE_WAY;
  t->work.type = BINDER_WORK_TRANSACTION;
  INIT_LIST_HEAD(&t->work.entry);
  b->kernel_data = b->data;
  b->transaction = t;
  b->target_node = n;
  b->data_size = 31;
  b->pid = 42;
  return t;
}
static void drop_tx(struct binder_transaction* t) {
  free(t->buffer);
  free(t);
}
struct fixture {
  struct task_struct task;
  struct binder_proc proc;
  struct binder_node node;
  struct binder_transaction* incoming;
};
static void setup(struct fixture* f, int count) {
  memset(f, 0, sizeof(*f));
  f->task.frozen = true;
  f->proc.tsk = &f->task;
  // 模拟 Binder 原生调用方已经持有的引用，模块不得增加或交还它。
  f->proc.tmp_ref = 1;
  pthread_mutex_init(&f->proc.lock, NULL);
  pthread_mutex_init(&f->node.lock, NULL);
  INIT_LIST_HEAD(&f->node.todo);
  f->node.has_async = true;
  f->node.ptr = 99;
  f->node.cookie = 11;
  for (int i = 0; i < count; i++) {
    struct binder_transaction* t = new_tx(&f->proc, &f->node, 7);
    t->debug_id = i;
    __list_add(&t->work.entry, f->node.todo.prev, &f->node.todo);
    f->proc.outstanding++;
  }
  f->incoming = new_tx(&f->proc, &f->node, 7);
  transaction_frees = buffer_frees = releases = fixup_calls = notifications = stats.deleted.value = 0;
  binder_free_txn_fixups = native_fixups;
  trace = IZERO;
  memset(rekernel_free_async_rules, 0, sizeof(rekernel_free_async_rules));
  rekernel_free_async_count = 0;
  buffer_copy_error = false;
  data_copy_calls = data_copy_fail_call = 0;
  data_copy_bytes = 0;
  kf_binder_alloc_copy_from_buffer = native_buffer_copy;
  struct_offset.binder_buffer_data = -1;
  block_release = entered_release = resume_release = false;
  struct_offset.binder_proc_is_frozen = offsetof(struct binder_proc, frozen);
  struct_offset.binder_proc_outstanding_txns = offsetof(struct binder_proc, outstanding);
}
static int ids(struct fixture* f, int* dest) {
  int count = 0;
  struct binder_work* w;
  list_for_each_entry(w, &f->node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    assert(t->buffer && t->buffer->transaction == t);
    assert(w->entry.next->prev == &w->entry && w->entry.prev->next == &w->entry);
    dest[count++] = t->debug_id;
  }
  return count;
}
static void invoke(struct fixture* f) {
  data_copy_calls = 0;
  data_copy_bytes = 0;
  hook_fargs3_t a = {.arg0 = (uintptr_t)f->incoming, .arg1 = (uintptr_t)&f->proc};
  binder_proc_transaction_before(&a, NULL);
  assert(!release_phase);
}
static void unchanged(struct fixture* f, int count) {
  int actual[32];
  assert(ids(f, actual) == count);
  for (int i = 0; i < count; i++) assert(actual[i] == i);
  assert(f->proc.tmp_ref == 1 && f->proc.outstanding == count);
  assert(!releases && !buffer_frees && !fixup_calls && !stats.deleted.value && !transaction_frees);
}
static void caller_put(struct binder_proc* p) {
  pthread_mutex_lock(&p->lock);
  assert(p->tmp_ref > 0);
  if (!--p->tmp_ref && p->dead)
    p->released = true;
  pthread_mutex_unlock(&p->lock);
}
static void teardown(struct fixture* f) {
  assert(f->proc.tmp_ref == 1 || (!f->proc.tmp_ref && f->proc.released));
  while (f->node.todo.next != &f->node.todo) {
    struct binder_transaction* t = container_of(f->node.todo.next, struct binder_transaction, work.entry);
    list_del_init(&t->work.entry);
    drop_tx(t);
  }
  drop_tx(f->incoming);
  pthread_mutex_destroy(&f->node.lock);
  pthread_mutex_destroy(&f->proc.lock);
}
static void* producer(void* p) {
  struct fixture* f = p;
  // 每个发送方各自持有原生 proc 引用。
  pthread_mutex_lock(&f->proc.lock);
  f->proc.tmp_ref++;
  pthread_mutex_unlock(&f->proc.lock);
  invoke(f);
  caller_put(&f->proc);
  return NULL;
}
static void* death_hook(void* p) {
  invoke(p);
  return NULL;
}
static void set_token(struct fixture* f, const char* name) {
  struct binder_buffer* buffer = f->incoming->buffer;
  buffer->data_size = PARCEL_OFFSET + REKERNEL_RPC_NAME_SIZE * 2;
  for (unsigned int i = 0; name[i]; i++) buffer->data[PARCEL_OFFSET + i * 2] = name[i];
}
static void test_rule_cleanup(void) {
  struct fixture f;
  int actual[32];
  const char* name = "android.test.IFoo";
  setup(&f, 3);
  set_token(&f, name);
  assert(free_async_update(name, -1, 1, true) == 0);
  invoke(&f);
  unchanged(&f, 3);  // 通配 SKIP 保护全部 code。
  assert(free_async_update(name, 7, 2, true) == 0);
  invoke(&f);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2 && f.proc.outstanding == 2);
  teardown(&f);
  setup(&f, 3);
  set_token(&f, name);
  assert(free_async_update(name, -1, 2, true) == 0);
  assert(free_async_update(name, 7, 1, true) == 0);
  invoke(&f);
  unchanged(&f, 3);  // 精确 SKIP 覆盖通配 BY_CODE。
  assert(free_async_update(name, 7, 0, false) == 0);
  invoke(&f);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
  teardown(&f);
  setup(&f, 3);
  set_token(&f, name);
  assert(free_async_update("other", 7, 1, true) == 0);
  invoke(&f);
  assert(ids(&f, actual) == 2);  // 未匹配则按既有 code 去重。
  teardown(&f);
  for (int scenario = 0; scenario < 7; scenario++) {
    setup(&f, 3);
    set_token(&f, name);
    assert(free_async_update(name, -1, 1, true) == 0);
    if (scenario == 0)
      buffer_copy_error = true;
    if (scenario == 1)
      f.incoming->buffer->data_size = PARCEL_OFFSET;
    if (scenario == 2)
      f.incoming->buffer->data_size = PARCEL_OFFSET + 1;
    if (scenario == 3)
      f.incoming->buffer->data_size = PARCEL_OFFSET + strlen(name) * 2;
    if (scenario == 4)
      f.incoming->buffer->data[PARCEL_OFFSET + 1] = 1;
    if (scenario == 5)
      f.incoming->buffer->data[PARCEL_OFFSET] = 0x80;
    if (scenario == 6)
      kf_binder_alloc_copy_from_buffer = NULL;
    invoke(&f);
    unchanged(&f, 3);
    teardown(&f);
  }
  char long_name[140];
  memset(long_name, 'x', 139);
  long_name[139] = 0;
  setup(&f, 3);
  set_token(&f, long_name);
  assert(free_async_update(long_name, 7, 1, true) == 0);
  invoke(&f);
  unchanged(&f, 3);
  teardown(&f);
  setup(&f, 3);
  set_token(&f, long_name);
  f.incoming->buffer->data[PARCEL_OFFSET + 139 * 2] = 'x';
  assert(free_async_update("other", 7, 1, true) == 0);
  invoke(&f);
  unchanged(&f, 3);  // 不得截断后误匹配。
  teardown(&f);
  puts(
      "production rule cleanup: copied Binder token, SKIP protects queue/counts, exact/wildcard priority, "
      "BY_CODE oldest retained, read failures/truncated/non-ASCII tokens preserve messages: PASS");
}

static void setup_data(struct fixture* f, int count, size_t size) {
  setup(f, count);
  set_token(f, "android.test.IFoo");
  assert(size <= sizeof(f->incoming->buffer->data));
  f->incoming->buffer->data_size = size;
  struct binder_work* w;
  list_for_each_entry(w, &f->node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    t->buffer->data_size = size;
    memcpy(t->buffer->data, f->incoming->buffer->data, size);
  }
  assert(free_async_update("android.test.IFoo", 7, REKERNEL_FREE_ASYNC_BY_DATA, true) == 0);
}
static void test_data_cleanup(void) {
  struct fixture f;
  int actual[32];
  size_t sizes[] = {65, 127, 128, 129, 4095, 4096, 4097, 16384};
  for (unsigned int i = 0; i < ARRAY_SIZE(sizes); i++) {
    setup_data(&f, 3, sizes[i]);
    invoke(&f);
    assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
    assert(f.proc.outstanding == 2 && releases == 1 && stats.deleted.value == 1);
    assert(data_copy_bytes == sizes[i] * 4);
    assert(data_copy_calls == ((sizes[i] + 63) / 64) * 4);
    teardown(&f);
  }
  // 完整比较每个字节，不同头部、块边界、尾部均不能当作重复。
  size_t positions[] = {0, 63, 64, 127, 128, 4095, 4096};
  for (unsigned int i = 0; i < ARRAY_SIZE(positions); i++) {
    setup_data(&f, 3, 4097);
    struct binder_work* w;
    list_for_each_entry(w, &f.node.todo, entry) {
      struct binder_transaction* t = container_of(w, struct binder_transaction, work);
      t->buffer->data[positions[i]] ^= 1;
    }
    invoke(&f);
    unchanged(&f, 3);
    assert(data_copy_calls > 0);
    teardown(&f);
  }
  setup_data(&f, 3, 129);
  struct binder_transaction* first = container_of(f.node.todo.next, struct binder_transaction, work.entry);
  first->buffer->data[128] ^= 1;
  invoke(&f);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 1);  // 保留最早数据相同者。
  teardown(&f);
  // 任意一次锁内读取失败都停止本轮清理，不能降级成 BY_CODE。
  for (unsigned int fail = 1; fail <= 12; fail++) {
    setup_data(&f, 3, 129);
    data_copy_fail_call = fail;
    invoke(&f);
    unchanged(&f, 3);
    assert(data_copy_calls == fail);
    teardown(&f);
  }
  setup_data(&f, 3, 129);
  struct binder_work* w;
  list_for_each_entry(w, &f.node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    t->buffer->data_size--;
  }
  invoke(&f);
  unchanged(&f, 3);
  assert(!data_copy_calls);
  teardown(&f);
  // 读预算对整个队列扫描生效，比较过程中不扩大预算。
  size_t large_sizes[] = {16385, 32768, 32769, REKERNEL_FREE_ASYNC_DATA_BUDGET};
  for (unsigned int i = 0; i < ARRAY_SIZE(large_sizes); i++) {
    setup_data(&f, 3, large_sizes[i]);
    invoke(&f);
    unchanged(&f, 3);
    assert(data_copy_bytes <= REKERNEL_FREE_ASYNC_DATA_BUDGET);
    if (large_sizes[i] > REKERNEL_FREE_ASYNC_DATA_BUDGET / 2)
      assert(!data_copy_calls);
    teardown(&f);
  }
  setup_data(&f, 3, 129);
  assert(free_async_update("android.test.IFoo", 7, REKERNEL_FREE_ASYNC_BY_CODE, true) == 0);
  list_for_each_entry(w, &f.node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    t->buffer->data[128] ^= 1;
  }
  invoke(&f);
  assert(ids(&f, actual) == 2 && !data_copy_calls);  // BY_CODE 不比较 data。
  teardown(&f);
  // 原对象/FD 和额外缓冲区保护对 BY_DATA 同样生效。
  for (int scenario = 0; scenario < 4; scenario++) {
    setup_data(&f, 3, 129);
    if (scenario == 0)
      f.incoming->buffer->offsets_size = 8;
    if (scenario == 1)
      f.incoming->buffer->extra_buffers_size = 16;
    if (scenario >= 2) {
      list_for_each_entry(w, &f.node.todo, entry) {
        struct binder_transaction* t = container_of(w, struct binder_transaction, work);
        if (scenario == 2)
          t->buffer->offsets_size = 8;
        else
          t->buffer->extra_buffers_size = 16;
      }
    }
    invoke(&f);
    unchanged(&f, 3);
    assert(!data_copy_calls);
    teardown(&f);
  }
  setup_data(&f, 20, 2048);
  list_for_each_entry(w, &f.node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    if (t->debug_id < 18)
      t->buffer->data[2047] ^= 1;
  }
  invoke(&f);
  unchanged(&f, 20);  // 后两条虽相同，预算用尽后不再访问。
  assert(data_copy_bytes == REKERNEL_FREE_ASYNC_DATA_BUDGET);
  teardown(&f);
  setup_data(&f, 10, 129);
  pthread_t threads[8];
  for (int i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, producer, &f) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 9 && f.proc.outstanding == 2);
  assert(f.proc.tmp_ref == 1 && releases == 8 && buffer_frees == 8 && transaction_frees == 8);
  assert(stats.deleted.value == 8 && f.node.has_async);
  teardown(&f);
  // 独立比较器覆盖空数据/短尾/极大长度；拒绝溢出，且不读取超界数据。
  setup_data(&f, 3, 129);
  first = container_of(f.node.todo.next, struct binder_transaction, work.entry);
  size_t direct_sizes[] = {0, 1, 63, 64, 65, 127, 128, 129};
  for (unsigned int i = 0; i < ARRAY_SIZE(direct_sizes); i++) {
    first->buffer->data_size = f.incoming->buffer->data_size = direct_sizes[i];
    size_t budget = REKERNEL_FREE_ASYNC_DATA_BUDGET;
    data_copy_calls = 0;
    data_copy_bytes = 0;
    binder_node_lock(&f.node);
    binder_inner_proc_lock(&f.proc);
    assert(binder_buffer_data_equal(&f.proc, first->buffer, f.incoming->buffer, &budget));
    binder_inner_proc_unlock(&f.proc);
    binder_node_unlock(&f.node);
    assert(data_copy_bytes == direct_sizes[i] * 2);
  }
  first->buffer->data_size = f.incoming->buffer->data_size = SIZE_MAX;
  size_t budget = REKERNEL_FREE_ASYNC_DATA_BUDGET;
  data_copy_calls = 0;
  data_copy_bytes = 0;
  assert(!binder_buffer_data_equal(&f.proc, first->buffer, f.incoming->buffer, &budget) && !budget && !data_copy_calls);
  teardown(&f);
  puts(
      "production BY_DATA: full bytes/length, 64-byte and page boundaries, zero/short/overflow, all copy failures, "
      "oldest identical retained, object/FD protection, shared 64KiB budget, eight producers: PASS");
}

static void test_kernel_data_reader(void) {
  struct fixture f;
  setup_data(&f, 3, 4097);
  struct binder_buffer* b = f.incoming->buffer;
  unsigned char dest[64];
  kf_binder_alloc_copy_from_buffer = NULL;
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 0, 64) == -EOPNOTSUPP);
  assert(free_async_update("legacy", 7, 1, true) == -EOPNOTSUPP);
  struct_offset.binder_buffer_data = offsetof(struct binder_buffer, kernel_data);
  assert(free_async_update("legacy", 7, 1, true) == 0);
  for (size_t offset = 0; offset < b->data_size; offset += 4) {
    size_t bytes = b->data_size - offset;
    if (bytes > sizeof(dest))
      bytes = sizeof(dest);
    assert(binder_buffer_read(&f.proc.alloc, dest, b, offset, bytes) == 0);
    assert(!memcmp(dest, b->data + offset, bytes));
  }
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 1, 1) == -EINVAL);
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 4096, 2) == -EINVAL);
  assert(binder_buffer_read(&f.proc.alloc, dest, b, UINT64_MAX, 1) == -EINVAL);
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 0, SIZE_MAX) == -EINVAL);
  b->free = true;
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 0, 1) == -EINVAL);
  b->free = false;
  b->kernel_data = NULL;
  assert(binder_buffer_read(&f.proc.alloc, dest, b, 0, 1) == -EFAULT);
  invoke(&f);
  unchanged(&f, 3);  // RPC 读取失败，不得误清理。
  b->kernel_data = b->data;
  struct binder_transaction* second = container_of(f.node.todo.next->next, struct binder_transaction, work.entry);
  struct binder_transaction* third = container_of(f.node.todo.prev, struct binder_transaction, work.entry);
  second->buffer->data[4096] ^= 1;
  third->buffer->data[4096] ^= 1;
  invoke(&f);
  unchanged(&f, 3);  // 仅第一条匹配，跨页最后一个字节不同。
  second->buffer->data[4096] ^= 1;
  third->buffer->data[4096] ^= 1;
  second->buffer->kernel_data = NULL;
  invoke(&f);
  unchanged(&f, 3);  // 比较失败，不得误清理。
  second->buffer->kernel_data = second->buffer->data;
  invoke(&f);
  int actual[32];
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
  assert(f.proc.outstanding == 2 && releases == 1 && stats.deleted.value == 1);
  teardown(&f);
  setup_data(&f, 3, 129);
  kf_binder_alloc_copy_from_buffer = NULL;
  struct_offset.binder_buffer_data = offsetof(struct binder_buffer, kernel_data);
  assert(free_async_update("android.test.IFoo", 7, REKERNEL_FREE_ASYNC_SKIP, true) == 0);
  invoke(&f);
  unchanged(&f, 3);  // 旧映射也能读取 RPC 并匹配 SKIP。
  teardown(&f);
  setup_data(&f, 20, 2048);
  kf_binder_alloc_copy_from_buffer = NULL;
  struct_offset.binder_buffer_data = offsetof(struct binder_buffer, kernel_data);
  struct binder_work* w;
  list_for_each_entry(w, &f.node.todo, entry) {
    struct binder_transaction* t = container_of(w, struct binder_transaction, work);
    if (t->debug_id < 18)
      t->buffer->data[2047] ^= 1;
  }
  invoke(&f);
  unchanged(&f, 20);  // 旧读取路径仍遵守整次扫描预算。
  teardown(&f);
  setup(&f, 0);
  struct_offset.binder_buffer_data = 32767;  // 原生函数优先，不使用这个偏移。
  assert(binder_buffer_read(&f.proc.alloc, dest, f.incoming->buffer, 0, 1) == 0);
  teardown(&f);
  puts(
      "production legacy reader: RPC/BY_DATA, native priority, byte/page boundaries, invalid ranges/free/null, "
      "oldest retained and shared budget: PASS");
}

int main(void) {
  test_kernel_data_reader();
  test_rule_cleanup();
  test_data_cleanup();
  size_t budget = REKERNEL_FREE_ASYNC_DATA_BUDGET;
  struct fixture f;
  int actual[32];
  // TF_ONE_WAY 就足够，不需要低内核没有的 TF_UPDATE_TXN。
  setup(&f, 3);
  trace = UZERO;
  invoke(&f);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
  assert(f.proc.tmp_ref == 1 && f.proc.outstanding == 2 && f.node.has_async);
  assert(releases == 1 && buffer_frees == 1 && fixup_calls == 1 && transaction_frees == 1 && stats.deleted.value == 1);
  assert(notifications == 1);
  teardown(&f);
  // 旧内核没有 fixup 函数时仍清理无对象消息，不增加引用。
  setup(&f, 3);
  binder_free_txn_fixups = NULL;
  invoke(&f);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
  assert(f.proc.tmp_ref == 1 && releases == 1 && !fixup_calls && transaction_frees == 1 && stats.deleted.value == 1);
  teardown(&f);
  setup(&f, 1);
  invoke(&f);
  unchanged(&f, 1);
  teardown(&f);
  // 冻结/退出、对象/FD、额外缓冲区和不匹配事务必须保留消息与计数。
  for (int scenario = 0; scenario < 14; scenario++) {
    setup(&f, 3);
    if (scenario == 0)
      f.proc.dead = true;
    if (scenario == 1)
      f.proc.frozen = true;
    if (scenario == 2)
      f.task.frozen = false;
    if (scenario == 3)
      f.node.has_async = false;
    if (scenario == 4)
      f.incoming->buffer->offsets_size = 8;
    if (scenario == 5)
      f.incoming->buffer->extra_buffers_size = 16;
    if (scenario == 6)
      f.incoming->flags = 0;
    if (scenario == 7)
      f.incoming->code = 9;
    if (scenario == 8)
      f.incoming->buffer->pid = 99;
    if (scenario == 9)
      f.incoming->proc = NULL;
    if (scenario == 10)
      f.incoming->flags |= 0x40;
    if (scenario == 11)
      f.incoming->buffer->target_node = NULL;
    if (scenario == 12 || scenario == 13) {
      // 即使缺少 fixup helper，带对象的旧消息也不清理。
      binder_free_txn_fixups = NULL;
      struct binder_work* w;
      list_for_each_entry(w, &f.node.todo, entry) {
        struct binder_transaction* t = container_of(w, struct binder_transaction, work);
        if (scenario == 12)
          t->buffer->offsets_size = 8;
        else
          t->buffer->extra_buffers_size = 16;
      }
    }
    trace = UZERO;
    invoke(&f);
    unchanged(&f, 3);
    assert(notifications == 1);
    if (scenario == 11)
      f.incoming->buffer->target_node = &f.node;
    teardown(&f);
  }
  // NULL buffer/node 和不同 node 身份不匹配；不访问无效对象。
  setup(&f, 3);
  struct binder_transaction* first = container_of(f.node.todo.next, struct binder_transaction, work.entry);
  struct binder_buffer* saved = f.incoming->buffer;
  f.incoming->buffer = NULL;
  assert(!binder_can_update_transaction(first, f.incoming, REKERNEL_FREE_ASYNC_BY_CODE, &budget));
  invoke(&f);
  unchanged(&f, 3);
  f.incoming->buffer = saved;
  saved->target_node = NULL;
  assert(!binder_can_update_transaction(first, f.incoming, REKERNEL_FREE_ASYNC_BY_CODE, &budget));
  saved->target_node = &f.node;
  struct binder_node other = {.ptr = f.node.ptr, .cookie = f.node.cookie + 1};
  saved->target_node = &other;
  assert(!binder_can_update_transaction(first, f.incoming, REKERNEL_FREE_ASYNC_BY_CODE, &budget));
  other.cookie = f.node.cookie;
  other.ptr++;
  assert(!binder_can_update_transaction(first, f.incoming, REKERNEL_FREE_ASYNC_BY_CODE, &budget));
  saved->target_node = &f.node;
  teardown(&f);
  // 队列夹杂非事务 work 时不动它，仍然只清除第二条事务。
  setup(&f, 3);
  first = container_of(f.node.todo.next, struct binder_transaction, work.entry);
  struct binder_work other_work = {.type = 99};
  __list_add(&other_work.entry, &first->work.entry, first->work.entry.next);
  invoke(&f);
  assert(other_work.entry.prev == &first->work.entry && first->buffer->transaction == first);
  list_del_init(&other_work.entry);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 2);
  teardown(&f);
  // 低内核没有 is_frozen/outstanding 字段时按既有负偏移约定跳过这些字段。
  setup(&f, 3);
  struct_offset.binder_proc_is_frozen = -1;
  struct_offset.binder_proc_outstanding_txns = -1;
  f.incoming->buffer->pid = 99;
  f.proc.frozen = true;
  binder_free_txn_fixups = NULL;
  invoke(&f);
  assert(ids(&f, actual) == 2 && f.proc.outstanding == 3 && releases == 1);
  teardown(&f);
  // 解冻后仍能消费保留下来的最早事务，has_async 不被误清除。
  setup(&f, 3);
  invoke(&f);
  f.task.frozen = false;
  first = container_of(f.node.todo.next, struct binder_transaction, work.entry);
  assert(first->debug_id == 0 && first->buffer->transaction == first && f.node.has_async);
  list_del_init(&first->work.entry);
  f.proc.outstanding--;
  drop_tx(first);
  assert(ids(&f, actual) == 1 && actual[0] == 2 && f.proc.outstanding == 1);
  teardown(&f);
  // 并发发送方各清理第二条，不能重复释放或重复减计数。
  setup(&f, 10);
  pthread_t threads[8];
  for (int i = 0; i < 8; i++) assert(pthread_create(&threads[i], NULL, producer, &f) == 0);
  for (int i = 0; i < 8; i++) assert(pthread_join(threads[i], NULL) == 0);
  assert(ids(&f, actual) == 2 && actual[0] == 0 && actual[1] == 9 && f.proc.outstanding == 2);
  assert(f.proc.tmp_ref == 1 && releases == 8 && fixup_calls == 8 && stats.deleted.value == 8);
  assert(buffer_frees == 8 && transaction_frees == 8 && f.node.has_async);
  teardown(&f);
  // 锁外释放期间 proc 退出，原调用方引用仍保护资源；模块不提前交还引用。
  setup(&f, 3);
  block_release = true;
  assert(pthread_create(&threads[0], NULL, death_hook, &f) == 0);
  pthread_mutex_lock(&release_guard);
  while (!entered_release) pthread_cond_wait(&release_cond, &release_guard);
  pthread_mutex_unlock(&release_guard);
  pthread_mutex_lock(&f.proc.lock);
  f.proc.dead = true;
  assert(f.proc.tmp_ref == 1 && !f.proc.released);
  pthread_mutex_unlock(&f.proc.lock);
  pthread_mutex_lock(&release_guard);
  resume_release = true;
  pthread_cond_broadcast(&release_cond);
  pthread_mutex_unlock(&release_guard);
  assert(pthread_join(threads[0], NULL) == 0);
  assert(f.proc.tmp_ref == 1 && !f.proc.released && releases == 1 && fixup_calls == 1);
  caller_put(&f.proc);
  assert(f.proc.released && !f.proc.tmp_ref);
  teardown(&f);
  puts(
      "production cleanup ASan/UBSan: no UPDATE flag, optional fixups, release order, objects, oldest retained, proc "
      "death, eight producers: PASS (ABI "
#if REKERNEL_BINDER_ABI == 3
      "3"
#elif REKERNEL_BINDER_ABI == 4
      "4"
#elif REKERNEL_BINDER_ABI == 5
      "5"
#else
      "6"
#endif
      ")");
}
