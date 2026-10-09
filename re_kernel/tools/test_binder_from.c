// 6.6 的短入口证据；运行生产推导段，不执行 ARM64 机器码。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define logkm(...) ((void)0)
#define lookup_name_continue(func) func = (typeof(func))kallsyms_lookup_name(#func)
static struct {
  int binder_transaction_from;
} struct_offset;
static uint32_t code[0x1A] = {0xd503233f, 0xa9bd7bfd, 0xf9000bf5, 0xa9024ff4, 0x910003fd, 0x9102a815,
                              0xaa0003f4, 0xaa1503e0, 0x940e04f1, 0xf9401693, 0xb4000353, 0x14000021,
                              0x9106c268, 0x52800029, 0xb829011f, 0xaa1503e0};
static bool present = true;
static unsigned long kallsyms_lookup_name(const char* name) {
  assert(!strcmp(name, "binder_get_txn_from_and_acq_inner"));
  return present ? (unsigned long)code : 0;
}
/* INSTRUCTIONS */
static long calculate_offsets(void) {
  /* PRODUCTION_FROM */
  return 0;
}
static void rejects(unsigned int index, uint32_t replacement) {
  uint32_t saved = code[index];
  code[index] = replacement;
  assert(calculate_offsets() == -11);
  code[index] = saved;
}
int main(void) {
  assert(!calculate_offsets() && struct_offset.binder_transaction_from == 0x28);
  code[9] = 0xf9401293;  // 6.1 相同入口形态，from 位于 0x20。
  assert(!calculate_offsets() && struct_offset.binder_transaction_from == 0x20);
  code[9] = 0xf9401693;
  rejects(6, 0xd503201f);
  rejects(6, 0x2a0003f4);  // 32 位 MOV 不能保存 transaction 指针。
  rejects(6, 0xaa0103f4);
  rejects(7, 0xaa1503f4);  // transaction 保存寄存器被覆盖。
  rejects(7, 0x91000694);
  rejects(7, 0xf9400694);
  rejects(8, 0xd65f03c0);
  rejects(9, 0xb9402a93);
  rejects(9, 0xf9401673);
  rejects(9, 0xf940169f);
  rejects(10, 0xd503201f);
  rejects(10, 0x34000353);
  rejects(10, 0xb4000354);
  code[25] = code[9];
  rejects(9, 0xd503201f);  // 不跨固定 26 指令边界寻找 CBZ。
  const uint32_t sony[] = {0xd503233fu, 0xf800865eu, 0xa9bc7bfdu, 0xf9000bf7u, 0x910003fdu, 0xa90257f6u, 0xa9034ff4u,
                           0xd5384116u, 0x910042c8u, 0x88dffd08u, 0xaa0003f4u, 0x11000508u, 0x91024015u, 0xb90012c8u,
                           0x14000041u, 0x14000040u, 0xaa1f03e1u, 0xaa1503e0u, 0x52800022u, 0x2a0103e8u, 0x88e87ea2u,
                           0x2a0803e0u, 0xaa0003e1u, 0x35000841u, 0xf9401293u, 0xb4000893u};
  memcpy(code, sony, sizeof(code));
  assert(!calculate_offsets() && struct_offset.binder_transaction_from == 0x20);
  present = false;
  struct_offset.binder_transaction_from = 0x20;
  assert(!calculate_offsets() && struct_offset.binder_transaction_from == 0x20);
  puts("production Binder from: 6.1/6.6 layouts, missing/clobbered/wrong-width operands and fixed window: PASS");
  return 0;
}
