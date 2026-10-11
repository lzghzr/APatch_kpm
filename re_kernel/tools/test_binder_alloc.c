// 5.10 的初始化入口先清零额外字段，再写入 pid。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
struct task_struct;
static struct {
  int binder_alloc_pid, binder_alloc_buffer, binder_alloc_free_async_space, binder_alloc_buffer_size;
  int task_struct_pid, task_struct_tgid, task_struct_group_leader;
} struct_offset;
static uint32_t code[32];
static unsigned long kallsyms_lookup_name(const char* name) {
  assert(!strcmp(name, "binder_alloc_init"));
  return (unsigned long)code;
}
#define lookup_name(func) func = (typeof(func))kallsyms_lookup_name(#func)
#define logkm(...) ((void)0)
/* INSTRUCTIONS */
static int calculate(void) {
  /* PRODUCTION_ALLOC */
  return 0;
}
int main(void) {
  const uint32_t android13[] = {0xd503233f, 0xd5384108, 0x91012009, 0xf9430508, 0xb945c908, 0xb900b81f,
                                0xb9008408, 0xf9002409, 0xf9002809, 0xd50323bf, 0xd65f03c0};
  memcpy(code, android13, sizeof(android13));
  assert(calculate() == 0);
  assert(struct_offset.binder_alloc_pid == 132);
  assert(struct_offset.task_struct_pid == 1480 && struct_offset.task_struct_tgid == 1484);
  assert(struct_offset.task_struct_group_leader == 1544);
  assert(struct_offset.binder_alloc_buffer == 64 && struct_offset.binder_alloc_free_async_space == 104);
  assert(struct_offset.binder_alloc_buffer_size == 120);
  memset(&struct_offset, 0, sizeof(struct_offset));
  code[2] = 0xd503201f;
  assert(calculate() == -11);  // 无 ADD 时不向入口之前扫描。
  memset(&struct_offset, 0, sizeof(struct_offset));
  code[0] = 0xd65f03c0;
  assert(calculate() == -11);
  puts("production binder_alloc_init: zero store, pid source, short backward window and missing anchor: PASS");
}
