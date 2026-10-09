// 运行旧 Binder is_dead 的生产短锚点，缺少语义证据必须失败。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
struct binder_proc;
static struct {
  int16_t binder_proc_is_frozen, binder_proc_is_dead;
} struct_offset;
static uint32_t words[0x21];
static void* target = words;
static unsigned long kallsyms_lookup_name(const char* name) { return (unsigned long)target; }
#define lookup_name(func)                             \
  do {                                                \
    func = (typeof(func))kallsyms_lookup_name(#func); \
    if (!func)                                        \
      return -21;                                     \
  } while (0)

/* INSTRUCTIONS */

static int probe(void) {
  /* PRODUCTION_DEAD */
  return 0;
}
static void reset(void) {
  for (unsigned int i = 0; i < sizeof(words) / sizeof(words[0]); i++) words[i] = 0xd503201f;
  memset(&struct_offset, 0, sizeof(struct_offset));
  target = words;
}
int main(void) {
  // proc 保存到 x19；忽略 debug 全局 x21 的 LDRB。
  reset();
  words[4] = 0xaa0003f3;
  words[7] = 0x394006a8;
  words[24] = 0x39425268;
  words[25] = 0x34000008;
  assert(probe() == 0 && struct_offset.binder_proc_is_dead == 0x94);
  reset();
  words[4] = 0xaa0003f3;
  words[7] = 0x39425261;
  words[10] = 0x34000001;
  assert(probe() == 0 && struct_offset.binder_proc_is_dead == 0x94);
  words[10] = 0x34000002;
  struct_offset.binder_proc_is_dead = 0;
  assert(probe() == -11);
  words[10] = 0xb4000001;
  assert(probe() == -11);
  words[10] = 0x34000001;
  words[7] = 0x39425281;
  assert(probe() == -11);
  reset();
  words[4] = 0xaa0003f3;
  words[31] = 0x39425261;
  words[32] = 0x34000001;
  assert(probe() == -11);
  reset();
  words[0] = 0xd65f03c0;
  words[4] = 0xaa0003f3;
  words[7] = 0x39425261;
  words[10] = 0x34000001;
  assert(probe() == -11);
  reset();
  target = NULL;
  assert(probe() == -21);
  puts(
      "production Binder is_dead: proc dataflow, debug globals, wrong branch/register/width, fixed window and missing "
      "symbol: PASS");
}
