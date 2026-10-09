// Sony 5.15 镜像的固定入口窗口；只解释指令，不执行这些机器码。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define logkm(...) ((void)0)
#define lookup_name(func)                           \
  func = (typeof(func))kallsyms_lookup_name(#func); \
  if (!func)                                        \
    return -21;
static uint32_t put_code[32] = {0xd503233f, 0xf800865e, 0xa9bd7bfd, 0xf9000bf5, 0x910003fd, 0xa9024ff4, 0xb940740a,
                                0xb9400469, 0x340000ca, 0x11005d28, 0x721e751f, 0x5400076d, 0xaa1f03e0, 0x14000027,
                                0x2959280b, 0x11005d2c, 0x2a0103e8, 0x121e7581, 0x4b0b014a, 0x6b01015f, 0x54ffff0b,
                                0x2959340a, 0xb940700c, 0xaa0303f3, 0xb940006b, 0xd503201f, 0xd503201f, 0xd503201f,
                                0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f};
static uint32_t multicast_code[32] = {
    0xd503233f, 0xf800865e, 0xa9bb7bfd, 0xa90167fa, 0x910003fd, 0xa9025ff8, 0xa90357f6, 0xa9044ff4,
    0x39409c08, 0x6b03011f, 0x540008c9, 0xb9402008, 0x9000c9f9, 0x2a0403f4, 0x2a0203f5, 0xaa0103f3,
    0x9104c339, 0x0b030116, 0xc8dfff3a, 0xeb19035f, 0x54000380, 0xaa1f03f7, 0x2a1f03f8, 0x14000006,
    0x52800038, 0xd1008357, 0xc8dfff5a, 0xeb19035f, 0x540002c0, 0xb4ffff97, 0xaa1303e0, 0x2a1403e1};
static uint32_t exit_code[8] = {0xd503233f, 0xf800865e, 0xa9be7bfd, 0xf9000bf3,
                                0x910003fd, 0xaa0003f3, 0xf9408c00, 0x97ffcf86};
static uint32_t validate_code[32] = {0xd503233f, 0xd10203ff, 0xf800865e, 0xa9027bfd, 0x910083fd, 0xa9036ffc, 0xa90467fa,
                                     0xa9055ff8, 0xa90657f6, 0xa9074ff4, 0xd5384108, 0xf942f108, 0xf81f83a8, 0x39409c14,
                                     0xb81f43bf, 0x34000874, 0xf9402815, 0xaa0003f3, 0xaa1403f6, 0x394002a8, 0x34001648,
                                     0xaa1503e0, 0x2a1f03e1, 0x52800202, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
                                     0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f};
static uint32_t unregister_code[0x55];
static bool validate_present = true;
static unsigned long kallsyms_lookup_name(const char* name) {
  if (!strcmp(name, "genlmsg_put"))
    return (unsigned long)put_code;
  if (!strcmp(name, "genlmsg_multicast_allns"))
    return (unsigned long)multicast_code;
  if (!strcmp(name, "genl_pernet_exit"))
    return (unsigned long)exit_code;
  if (!strcmp(name, "genl_unregister_family"))
    return (unsigned long)unregister_code;
  if (!strcmp(name, "genl_validate_assign_mc_groups") && validate_present)
    return (unsigned long)validate_code;
  return 0;
}
/* PRODUCTION_FUNCTIONS */
static void rejects(uint32_t* word, uint32_t replacement) {
  uint32_t saved = *word;
  *word = replacement;
  assert(calculate_offsets() == -11);
  *word = saved;
}
static const uint32_t genlmsg_put_61[] = {
    0xd503233fu, 0xa9be7bfdu, 0xa9014ff4u, 0x910003fdu, 0x2a0503f3u, 0x2a0403e5u, 0xaa0303f4u, 0xb9407409u,
    0xb9400468u, 0x34000069u, 0x2a1f03e9u, 0x14000003u, 0x295a240au, 0x4b0a0129u, 0x11005d0au, 0x121e754au,
    0x6b0a013fu, 0x5400016bu, 0xb9400283u, 0x11001104u, 0x97ffebc9u, 0xb40000e0u, 0x39004013u, 0x91005008u,
    0xb9401a89u, 0x7900241fu, 0x39004409u, 0x14000002u, 0xaa1f03e8u, 0xaa0803e0u, 0xa9414ff4u, 0xa8c27bfdu};
static const uint32_t genlmsg_multicast_allns_61[] = {
    0xd503233fu, 0xa9bb7bfdu, 0xa90167fau, 0xa9025ff8u, 0xa90357f6u, 0xa9044ff4u, 0x910003fdu, 0x39409c08u,
    0x6b03011fu, 0x54000889u, 0xb9402008u, 0x2a0403f4u, 0x2a0203f5u, 0xaa0103f3u, 0xd000a179u, 0x91266339u,
    0x0b030116u, 0xc8dfff3au, 0xeb19035fu, 0x54000360u, 0xaa1f03f7u, 0x2a1f03f8u, 0x14000006u, 0x52800038u,
    0xd1008357u, 0xc8dfff5au, 0xeb19035fu, 0x540002a0u, 0xb4ffff97u, 0xaa1303e0u, 0x2a1403e1u, 0x97fd0f45u};
static const uint32_t genl_pernet_exit_61[] = {0xd503233fu, 0xa9be7bfdu, 0xf9000bf3u, 0x910003fdu,
                                               0xaa0003f3u, 0xf9408c00u, 0x97ffe5ddu, 0xf9008e7fu};
static const uint32_t genl_unregister_family_61[] = {
    0xd503233fu, 0xd101c3ffu, 0xa9037bfdu, 0xf90023f7u, 0xa90557f6u, 0xa9064ff4u, 0x9100c3fdu, 0xd5384108u, 0xaa0003f3u,
    0xf9431d08u, 0xd000a1c0u, 0x91118000u, 0xf81f83a8u, 0x9408c6f1u, 0xd000a1c0u, 0x91106000u, 0x9408b0a8u, 0xb9400261u,
    0xd000a1c0u, 0x91112000u, 0x9407f982u, 0xb40004e0u, 0x97ffe3a2u, 0x97cd8b2bu, 0xd000a174u, 0x91266294u, 0xc8dffe95u,
    0x14000002u, 0xc8dffeb5u, 0xeb1402bfu, 0x540001a0u, 0x39409e68u, 0x34ffff88u, 0x2a1f03f6u, 0xb9402268u, 0xf9407ea0u,
    0x0b0802c1u, 0x97ffebe8u, 0x39409e68u, 0x110006d6u, 0x6b0802dfu, 0x54ffff23u, 0x17fffff2u, 0x97cd8b1fu, 0xf000a980u,
    0x91124000u, 0x9408ded3u, 0xd000a1c0u, 0x91048000u, 0x52800061u, 0x52800022u, 0xaa1f03e3u, 0x97cc3e17u, 0x39409e68u,
    0x34000528u, 0xaa1f03f4u, 0xaa1f03f5u, 0xd000a1d6u, 0x52800037u, 0x14000019u, 0xd000a1c0u, 0x91106000u, 0x9408b0beu,
    0xd000a1c0u, 0x91118000u, 0x97cc78deu, 0x12800020u, 0x1400004eu, 0x8b0a0d29u, 0xf9800131u, 0xc85f7d2au, 0x8a28014au,
    0xc80b7d2au, 0x35ffffabu, 0xf9402e68u, 0x52800100u, 0xaa1303e1u, 0x8b140102u, 0x97fffed8u, 0x39409e68u, 0x910006b5u,
    0x91004694u, 0xeb0802bfu, 0x54000182u, 0xb9402268u};
static const uint32_t genlmsg_put_66[] = {
    0xd503233fu, 0xa9be7bfdu, 0xa9014ff4u, 0x910003fdu, 0xb9407409u, 0xb9400068u, 0x2a0503f3u, 0x2a0403e5u,
    0xaa0303f4u, 0x34000069u, 0x2a1f03e9u, 0x14000003u, 0x2959240au, 0x4b0a0129u, 0x11005d0au, 0x121e754au,
    0x6b0a013fu, 0x540001cbu, 0xb9406a83u, 0x11001104u, 0x97ffec2au, 0xb40000c0u, 0x39004013u, 0xb9401688u,
    0x7900241fu, 0x39004408u, 0x91005000u, 0xa9414ff4u, 0xa8c27bfdu, 0xd50323bfu, 0xd65f03c0u, 0xaa1f03e0u};
static const uint32_t genlmsg_multicast_allns_66[] = {
    0xd503233fu, 0xa9bb7bfdu, 0xa90167fau, 0xa9025ff8u, 0xa90357f6u, 0xa9044ff4u, 0x910003fdu, 0x39408008u,
    0x6b03011fu, 0x540008c9u, 0xb9406c08u, 0xf000a619u, 0x912e6339u, 0x2a0403f4u, 0x2a0203f5u, 0xaa0103f3u,
    0xc8dfff3au, 0xeb19035fu, 0x0b030116u, 0x54000380u, 0xaa1f03f7u, 0x2a1f03f8u, 0x14000006u, 0x52800038u,
    0xd1008357u, 0xc8dfff5au, 0xeb19035fu, 0x540002c0u, 0xb4ffff97u, 0xaa1303e0u, 0x2a1403e1u, 0x97fd0127u};
static const uint32_t genl_pernet_exit_66[] = {0xd503233fu, 0xa9be7bfdu, 0xf9000bf3u, 0x910003fdu,
                                               0xaa0003f3u, 0xf9408c00u, 0x97ffe5ccu, 0xf9008e7fu};
static const uint32_t genl_unregister_family_66[] = {
    0xd503233fu, 0xd101c3ffu, 0xa9037bfdu, 0xf90023f7u, 0xa90557f6u, 0xa9064ff4u, 0x9100c3fdu, 0xd5384108u, 0xaa0003f3u,
    0x9000a680u, 0x91366000u, 0xf9431108u, 0xf81f83a8u, 0x94089c11u, 0x9000a680u, 0x91354000u, 0x94088eafu, 0xb9406a61u,
    0x9000a680u, 0x91360000u, 0x9407d32bu, 0xb40004e0u, 0x97ffe3e6u, 0x97cca5b8u, 0x9000a634u, 0x912e6294u, 0xc8dffe95u,
    0x14000002u, 0xc8dffeb5u, 0xeb1402bfu, 0x540001a0u, 0x39408268u, 0x34ffff88u, 0x2a1f03f6u, 0xb9406e68u, 0xf9407ea0u,
    0x0b0802c1u, 0x97ffec4bu, 0x39408268u, 0x110006d6u, 0x6b0802dfu, 0x54ffff23u, 0x17fffff2u, 0x97cca5acu, 0xd000ae20u,
    0x91214000u, 0x9408b4bcu, 0x9000a680u, 0x91294000u, 0x52800061u, 0x52800022u, 0xaa1f03e3u, 0x97cb4ed2u, 0x39408268u,
    0x34000568u, 0xaa1f03f4u, 0xaa1f03f5u, 0x9000a696u, 0x52800037u, 0x14000019u, 0x9000a680u, 0x91354000u, 0x94088ec0u,
    0x9000a680u, 0x91366000u, 0x97cb8aa2u, 0x12800020u, 0x14000050u, 0x8b0a0d29u, 0xf9800131u, 0xc85f7d2au, 0x8a28014au,
    0xc80b7d2au, 0x35ffffabu, 0xf9402e68u, 0x52800100u, 0xaa1303e1u, 0x8b140102u, 0x97fffed6u, 0x39408268u, 0x910006b5u,
    0x91004a94u, 0xeb0802bfu, 0x540001c2u, 0xb9406e68u};
static void newer_layouts(void) {
  validate_present = false;
  memcpy(put_code, genlmsg_put_61, sizeof(put_code));
  memcpy(multicast_code, genlmsg_multicast_allns_61, sizeof(multicast_code));
  memcpy(exit_code, genl_pernet_exit_61, sizeof(exit_code));
  memcpy(unregister_code, genl_unregister_family_61, sizeof(unregister_code));
  assert(!calculate_offsets());
  assert(struct_offset.genl_family_id == 0 && struct_offset.genl_family_config == 4);
  assert(struct_offset.genl_family_mcgrps == 0x58 && struct_offset.genl_family_n_mcgrps == 0x27);
  assert(struct_offset.genl_family_n_mcgrps_size == 1 && struct_offset.genl_family_mcgrp_offset == 0x20);
  assert(struct_offset.net_genl_sock == 0x118);
  // 字节步长 ADD 模式不能接受错误参数、扩展/移位、不同循环寄存器或未知步长。
  const uint32_t bad_adds[] = {0x0b140102u, 0x8b140103u, 0x8b140122u, 0x8b150102u,
                               0x8b540102u, 0x8b140502u, 0x8bd40102u, 0x8b34f102u};
  for (unsigned int i = 0; i < ARRAY_SIZE(bad_adds); i++) rejects(&unregister_code[0x4d], bad_adds[i]);
  rejects(&unregister_code[0x4b], 0xd503201f);
  rejects(&unregister_code[0x4e], 0xd503201f);
  rejects(&unregister_code[0x51], 0x91004294u);  // 16 字节不是该形态的步长。
  rejects(&unregister_code[0x51], 0x910046b4u);  // 读取了不同的迭代寄存器。
  rejects(&unregister_code[0x51], 0x11004694u);  // 32 位累加不能充当字节偏移。
  memcpy(put_code, genlmsg_put_66, sizeof(put_code));
  memcpy(multicast_code, genlmsg_multicast_allns_66, sizeof(multicast_code));
  memcpy(exit_code, genl_pernet_exit_66, sizeof(exit_code));
  memcpy(unregister_code, genl_unregister_family_66, sizeof(unregister_code));
  assert(!calculate_offsets());
  assert(struct_offset.genl_family_id == 0x68 && struct_offset.genl_family_config == 0);
  assert(struct_offset.genl_family_mcgrps == 0x58 && struct_offset.genl_family_n_mcgrps == 0x20);
  assert(struct_offset.genl_family_n_mcgrps_size == 1 && struct_offset.genl_family_mcgrp_offset == 0x6c);
  assert(struct_offset.net_genl_sock == 0x118);
  rejects(&put_code[5], 0xd503201f);    // 缺少 hdrsize 读取。
  rejects(&put_code[8], 0xd503201f);    // 缺少 family 保存。
  rejects(&put_code[18], 0xb9406a82u);  // id 没有作为第四个参数。
  rejects(&put_code[19], 0x11001105u);  // ADD 没有写第五个参数。
  rejects(&put_code[19], 0x11001124u);  // ADD 不使用 hdrsize 的寄存器。
  rejects(&put_code[19], 0x11002104u);  // hdrsize + 8 不符合消息头长度。
  rejects(&put_code[20], 0xd503201fu);  // 缺少调用锚点。
  rejects(&put_code[12], 0x2a1f03e8u);  // hdrsize 在调用前被覆盖。
  assert(!calculate_offsets());
}

static void field_checks(void) {
  // 组指针恰好落在 family 尾部可以通过，越界或覆盖配置段必须失败。
  uint32_t pointer = validate_code[16];
  validate_code[16] = (pointer & ~(0xfffu << 10)) | ((0x3f8u / 8) << 10);
  assert(!calculate_offsets() && struct_offset.genl_family_mcgrps == 0x3f8);
  validate_code[16] = pointer;
  rejects(&validate_code[16], (pointer & ~(0xfffu << 10)) | ((0x400u / 8) << 10));
  rejects(&validate_code[16], (pointer & ~(0xfffu << 10)) | ((0x8u / 8) << 10));

  // 两个锚点保持相同组数字段，分别核对与配置段/组号重叠和范围越界。
  uint32_t count = multicast_code[8], validate_count = validate_code[13];
  const unsigned int offsets[] = {0x18, 0x20, 0x400};
  for (unsigned int i = 0; i < ARRAY_SIZE(offsets); i++) {
    multicast_code[8] = (count & ~(0xfffu << 10)) | (offsets[i] << 10);
    validate_code[13] = (validate_count & ~(0xfffu << 10)) | (offsets[i] << 10);
    assert(calculate_offsets() == -11);
  }
  multicast_code[8] = count;
  validate_code[13] = validate_count;

  // u32 计数相邻推导可能产生四字节对齐的指针，必须拒绝。
  uint32_t group = multicast_code[11];
  multicast_code[8] = 0xb9406008;   // ldr w8, [x0, #0x60]
  multicast_code[11] = 0xb9406408;  // ldr w8, [x0, #0x64]，推导 mcgrps=0x54。
  assert(calculate_offsets() == -11);
  multicast_code[8] = count;
  multicast_code[11] = group;
  assert(!calculate_offsets());
}

int main(void) {
  for (unsigned int i = 0; i < ARRAY_SIZE(unregister_code); i++) unregister_code[i] = 0xd503201f;
  field_checks();
  assert(!calculate_offsets());
  assert(struct_offset.genl_family_id == 0 && struct_offset.genl_family_config == 4);
  assert(struct_offset.genl_family_n_mcgrps == 0x27 && struct_offset.genl_family_n_mcgrps_size == 1);
  assert(struct_offset.genl_family_mcgrp_offset == 0x20 && struct_offset.genl_family_mcgrps == 0x50);
  assert(struct_offset.net_genl_sock == 0x118);
  rejects(&put_code[7], 0xd503201f);
  rejects(&put_code[24], 0xd503201f);
  rejects(&put_code[23], 0x94000000);
  put_code[25] = put_code[24];
  rejects(&put_code[24], 0xd503201f);
  put_code[25] = 0xd503201f;
  // 缺少独立函数且旧注销窗口不含模式，必须失败，不能猜组指针。
  validate_present = false;
  assert(calculate_offsets() == -11);
  validate_present = true;
  for (unsigned int i = 0; i < 5; i++) {
    const unsigned int positions[] = {13, 15, 16, 19, 20};
    rejects(&validate_code[positions[i]], 0xd503201f);
  }
  rejects(&validate_code[13], validate_code[13] + (1 << 10));  // 不同组数字段。
  rejects(&validate_code[14], 0x2a1f03f4);                     // mov w20,wzr 覆盖组数。
  rejects(&validate_code[15], (validate_code[15] & ~31u) | 19u);
  rejects(&validate_code[16], validate_code[16] | 31u);  // XZR 不是组指针。
  rejects(&validate_code[17], 0x94000000);               // 不跨 BL 匹配。
  rejects(&validate_code[17], 0xaa1f03f5);               // mov x21,xzr 覆盖组指针。
  rejects(&validate_code[19], (validate_code[19] & ~(31u << 5)) | (19u << 5));
  rejects(&validate_code[19], validate_code[19] + (1 << 10));  // name[0] 才是入口空值检查。
  rejects(&validate_code[20], (validate_code[20] & ~31u) | 9u);
  validate_code[24] = validate_code[16];
  rejects(&validate_code[16], 0xd503201f);
  validate_code[24] = 0xd503201f;
  assert(!calculate_offsets());
  newer_layouts();
  puts("production Genl anchors: Sony/6.1/6.6 seven fields, fixed windows and missing/incorrect dataflow: PASS");
  return 0;
}
