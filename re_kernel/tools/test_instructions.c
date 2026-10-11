// 使用 kpm_utils.h 的实际指令宏，覆盖寄存器、访存模式与有符号立即数边界。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "instruction_host.h"

int main(void) {
  // LLVM AArch64 汇编器编码：scaled imm12 和 ADD immediate 都是无符号值。
  assert(inst_get_ldr_imm_uint_imm(0xf9500020u) == 8192);  // ldr x0, [x1, #8192]
  assert(inst_get_str_imm_uint_imm(0xf9100020u) == 8192);  // str x0, [x1, #8192]
  assert(inst_get_add_imm_imm(0x91400820u) == 8192);       // add x0, x1, #2, lsl #12
  for (unsigned int imm = 0; imm < 4096; imm++) {
    for (unsigned int size = 2; size <= 3; size++) {
      uint32_t load = 0x39400000u | size << 30 | imm << 10 | 1 << 5;
      uint32_t store = 0x39000000u | size << 30 | imm << 10 | 1 << 5;
      assert(inst_get_ldr_imm_uint_imm(load) == (long)imm << size);
      assert(inst_get_str_imm_uint_imm(store) == (long)imm << size);
    }
    assert(inst_get_ldrb_imm_uint_imm(0x39400000u | imm << 10) == imm);
    assert(inst_get_ldrh_imm_uint_imm(0x79400000u | imm << 10) == (long)imm << 1);
    assert(inst_get_strb_imm_uint_imm(0x39000000u | imm << 10) == imm);
    for (unsigned int sf = 0; sf <= 1; sf++) {
      for (unsigned int sh = 0; sh <= 1; sh++) {
        uint32_t add = 0x11000000u | sf << 31 | sh << 22 | imm << 10 | 1 << 5;
        assert(inst_get_add_imm_imm(add) == (long)imm << (sh ? 12u : 0u));
      }
    }
  }
  assert(inst_get_ldr_imm_uint_imm(0) == -1 && inst_get_str_imm_uint_imm(0) == -1);
  assert(inst_get_add_imm_imm(0) == -1);
  // LLVM AArch64 汇编器编码：ADD extended 与 shifted register、ADDS、SUB 分开。
  struct {
    uint32_t word;
    int sf, rd, rn, rm, option, imm3;
  } extended_adds[] = {
      {0x8b34d042u, 1, 2, 2, 20, 6, 4},    // add x2, x2, w20, sxtw #4
      {0x8b36d102u, 1, 2, 8, 22, 6, 4},    // add x2, x8, w22, sxtw #4
      {0x0b36d102u, 0, 2, 8, 22, 6, 4},    // add w2, w8, w22, sxtw #4
      {0x8b36f102u, 1, 2, 8, 22, 7, 4},    // add x2, x8, x22, sxtx #4
      {0x8b365102u, 1, 2, 8, 22, 2, 4},    // add x2, x8, w22, uxtw #4
      {0x8b3dc3dfu, 1, 31, 30, 29, 6, 0},  // add sp, x30, w29, sxtw
      {0x0b220c20u, 0, 0, 1, 2, 0, 3},     // add w0, w1, w2, uxtb #3
  };
  for (unsigned int i = 0; i < sizeof(extended_adds) / sizeof(extended_adds[0]); i++) {
    uint32_t word = extended_adds[i].word;
    assert(inst_is_add_ext(word) && inst_get_add_ext_sf(word) == extended_adds[i].sf);
    assert(inst_get_add_ext_rd(word) == extended_adds[i].rd && inst_get_add_ext_rn(word) == extended_adds[i].rn);
    assert(inst_get_add_ext_rm(word) == extended_adds[i].rm);
    assert(inst_get_add_ext_option(word) == extended_adds[i].option);
    assert(inst_get_add_ext_imm3(word) == extended_adds[i].imm3);
  }
  uint32_t other_adds[] = {0x8b161102u, 0xab36d102u, 0xcb36d102u, 0x91001022u};
  for (unsigned int i = 0; i < sizeof(other_adds) / sizeof(other_adds[0]); i++) {
    assert(!inst_is_add_ext(other_adds[i]) && inst_get_add_ext_sf(other_adds[i]) == -1);
    assert(inst_get_add_ext_option(other_adds[i]) == -1 && inst_get_add_ext_imm3(other_adds[i]) == -1);
  }
  // LLVM AArch64 汇编器编码：ADD shifted register 的位宽、移位种类和移位量分别读取。
  const uint32_t shifted_adds[] = {0x8b140102u, 0x8b540102u, 0x8b940502u, 0x0b140102u};
  for (unsigned int i = 0; i < sizeof(shifted_adds) / sizeof(shifted_adds[0]); i++) {
    assert(inst_is_add_reg(shifted_adds[i]));
    assert(inst_get_add_reg_rd(shifted_adds[i]) == 2 && inst_get_add_reg_rn(shifted_adds[i]) == 8);
    assert(inst_get_add_reg_rm(shifted_adds[i]) == 20);
    assert(inst_get_add_reg_sf(shifted_adds[i]) == (i != 3));
    assert(inst_get_add_reg_shift(shifted_adds[i]) == (i == 3 ? 0 : (int)i));
    assert(inst_get_add_reg_imm6(shifted_adds[i]) == (i == 2 ? 1 : 0));
  }
  const uint32_t not_shifted_adds[] = {0x8b34d102u, 0xab140102u, 0xcb140102u, 0x91001022u};
  for (unsigned int i = 0; i < sizeof(not_shifted_adds) / sizeof(not_shifted_adds[0]); i++) {
    assert(!inst_is_add_reg(not_shifted_adds[i]));
    assert(inst_get_add_reg_shift(not_shifted_adds[i]) == -1 && inst_get_add_reg_imm6(not_shifted_adds[i]) == -1);
  }
  int displacements[] = {-134217728, -4, 0, 4, 134217724};
  for (unsigned int i = 0; i < sizeof(displacements) / sizeof(displacements[0]); i++) {
    uint32_t word = 0x94000000u | ((uint32_t)(displacements[i] / 4) & 0x3ffffffu);
    assert(inst_is_bl(word) && inst_get_bl_label(word) == displacements[i]);
  }
  assert(!inst_is_bl(0x14000000u) && inst_get_bl_label(0x14000000u) == -1);
  assert(inst_is_blr(0xd63f0260u) && inst_get_blr_rn(0xd63f0260u) == 19);
  // LLVM AArch64 汇编器生成的实际编码，覆盖助记符别名、SIMD Q 和预取。
  struct {
    uint32_t word;
    int load;
    bool imm9;
  } assembled[] = {
      {0x39404268u, 1, false},   // ldrb w8, [x19, #16]
      {0x79402268u, 1, false},   // ldrh w8, [x19, #16]
      {0xb9401268u, 1, false},   // ldr w8, [x19, #16]
      {0xf9400a68u, 1, false},   // ldr x8, [x19, #16]
      {0x39c04268u, 1, false},   // ldrsb w8, [x19, #16]
      {0x39804268u, 1, false},   // ldrsb x8, [x19, #16]
      {0x79c02268u, 1, false},   // ldrsh w8, [x19, #16]
      {0x79802268u, 1, false},   // ldrsh x8, [x19, #16]
      {0xb9801268u, 1, false},   // ldrsw x8, [x19, #16]
      {0x39004268u, 0, false},   // strb w8, [x19, #16]
      {0x79002268u, 0, false},   // strh w8, [x19, #16]
      {0xb9001268u, 0, false},   // str w8, [x19, #16]
      {0xf9000a68u, 0, false},   // str x8, [x19, #16]
      {0x3d404268u, 1, false},   // ldr b8, [x19, #16]
      {0x7d402268u, 1, false},   // ldr h8, [x19, #16]
      {0xbd401268u, 1, false},   // ldr s8, [x19, #16]
      {0xfd400a68u, 1, false},   // ldr d8, [x19, #16]
      {0x3dc00668u, 1, false},   // ldr q8, [x19, #16]
      {0x3d800668u, 0, false},   // str q8, [x19, #16]
      {0xf8500268u, 1, true},    // ldur x8, [x19, #-256]
      {0xb8900268u, 1, true},    // ldursw x8, [x19, #-256]
      {0x38d00a68u, 1, true},    // ldtrsb w8, [x19, #-256]
      {0x78900a68u, 1, true},    // ldtrsh x8, [x19, #-256]
      {0xb8900a68u, 1, true},    // ldtrsw x8, [x19, #-256]
      {0xf8100a68u, 0, true},    // sttr x8, [x19, #-256]
      {0x3c900268u, 0, true},    // stur q8, [x19, #-256]
      {0x3ccff668u, 1, true},    // ldr q8, [x19], #255
      {0x3c900e68u, 0, true},    // str q8, [x19, #-256]!
      {0xf9800a60u, -1, false},  // prfm pldl1keep, [x19, #16]
      {0xf8900260u, -1, true},   // prfum pldl1keep, [x19, #-256]
  };
  for (unsigned int i = 0; i < sizeof(assembled) / sizeof(assembled[0]); i++) {
    uint32_t word = assembled[i].word;
    assert(inst_is_ldr_imm(word) == (!assembled[i].imm9 && assembled[i].load == 1));
    assert(inst_is_str_imm(word) == (!assembled[i].imm9 && assembled[i].load == 0));
    assert(inst_is_ldr_imm9(word) == (assembled[i].imm9 && assembled[i].load == 1));
    assert(inst_is_str_imm9(word) == (assembled[i].imm9 && assembled[i].load == 0));
  }
  int offsets[] = {0, 1, 2047, 4095};
  int signed_offsets[] = {-256, -1, 0, 1, 255};
  for (int vector = 0; vector <= 1; vector++) {
    for (int size = 0; size < 4; size++) {
      for (int opc = 0; opc < 4; opc++) {
        bool load =
            vector ? opc == 1 || (opc == 3 && size == 0) : opc == 1 || (opc == 2 && size < 3) || (opc == 3 && size < 2);
        bool store = vector ? opc == 0 || (opc == 2 && size == 0) : opc == 0;
        for (unsigned int i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
          uint32_t word =
              0x39000000u | (uint32_t)size << 30 | vector << 26 | (uint32_t)opc << 22 | offsets[i] << 10 | 19 << 5 | 8;
          assert(inst_is_ldr_imm(word) == load && inst_is_str_imm(word) == store);
          assert(inst_is_ldrb_imm_uint(word) == (!vector && size == 0 && opc == 1));
#define CHECK_IMM12(abbr)                                                             \
  assert(inst_get_##abbr##_size(word) == size && inst_get_##abbr##_opc(word) == opc); \
  assert(inst_get_##abbr##_imm12(word) == offsets[i]);                                \
  assert(inst_get_##abbr##_rn(word) == 19 && inst_get_##abbr##_rt(word) == 8)
          if (load) {
            CHECK_IMM12(ldr_imm);
            assert(inst_get_str_imm_opc(word) == -1);
          } else if (store) {
            CHECK_IMM12(str_imm);
            assert(inst_get_ldr_imm_opc(word) == -1);
          } else {
            assert(inst_get_ldr_imm_opc(word) == -1 && inst_get_str_imm_opc(word) == -1);
          }
#undef CHECK_IMM12
        }
        for (int mode = 0; mode < 4; mode++) {
          for (unsigned int i = 0; i < sizeof(signed_offsets) / sizeof(signed_offsets[0]); i++) {
            uint32_t word = 0x38000000u | (uint32_t)size << 30 | vector << 26 | (uint32_t)opc << 22
                            | ((uint32_t)signed_offsets[i] & 0x1ffu) << 12 | mode << 10 | 19 << 5 | 8;
            bool unprivileged_vector = vector && mode == 2;
            assert(inst_is_ldr_imm9(word) == (load && !unprivileged_vector));
            assert(inst_is_str_imm9(word) == (store && !unprivileged_vector));
#define CHECK_IMM9(abbr)                                                                             \
  assert(inst_get_##abbr##_size(word) == size && inst_get_##abbr##_opc(word) == opc);                \
  assert(inst_get_##abbr##_mode(word) == mode && inst_get_##abbr##_imm9(word) == signed_offsets[i]); \
  assert(inst_get_##abbr##_rn(word) == 19 && inst_get_##abbr##_rt(word) == 8)
            if (load && !unprivileged_vector) {
              CHECK_IMM9(ldr_imm9);
              assert(inst_get_str_imm9_mode(word) == -1);
            } else if (store && !unprivileged_vector) {
              CHECK_IMM9(str_imm9);
              assert(inst_get_ldr_imm9_mode(word) == -1);
            } else {
              assert(inst_get_ldr_imm9_mode(word) == -1 && inst_get_str_imm9_mode(word) == -1);
            }
#undef CHECK_IMM9
          }
        }
      }
    }
  }
  assert(!inst_is_ldr_imm(0) && inst_get_ldr_imm_opc(0) == -1);
  assert(!inst_is_str_imm(0) && inst_get_str_imm_opc(0) == -1);
  assert(!inst_is_ldr_imm9(0) && inst_get_ldr_imm9_imm9(0) == -1);
  assert(!inst_is_str_imm9(0) && inst_get_str_imm9_imm9(0) == -1);
  assert(inst_is_ldr_imm(inst_get_ldr_imm_value()));
  assert(inst_is_str_imm(inst_get_str_imm_value()));
  assert(inst_is_ldr_imm9(inst_get_ldr_imm9_value()));
  assert(inst_is_str_imm9(inst_get_str_imm9_value()));
  for (int sf = 0; sf <= 1; sf++) {
    for (int hw = 0; hw < 4; hw++) {
      uint32_t word = 0x52800000u | (uint32_t)sf << 31 | hw << 21 | 7 << 5 | 1;
      assert(inst_is_movz_imm(word) && inst_get_movz_imm_sf(word) == sf);
      assert(inst_get_movz_imm_hw(word) == hw && inst_get_movz_imm_imm16(word) == 7 && inst_get_movz_imm_rd(word) == 1);
    }
  }
  assert(inst_is_orr_imm(0x32000be1u) && inst_get_orr_imm_sf(0x32000be1u) == 0);
  assert(inst_get_orr_imm_rn(0x32000be1u) == 31 && inst_get_orr_imm_rd(0x32000be1u) == 1);
  assert(inst_get_orr_imm_n(0x32000be1u) == 0 && inst_get_orr_imm_immr(0x32000be1u) == 0);
  assert(inst_get_orr_imm_imms(0x32000be1u) == 2);
  const int64_t page_offsets[] = {-4294967296LL, -4096, 0, 4096, 4294963200LL};
  for (unsigned int i = 0; i < sizeof(page_offsets) / sizeof(page_offsets[0]); i++) {
    uint32_t immediate = (uint32_t)(page_offsets[i] / 4096) & 0x1fffffu;
    uint32_t word = 0x90000000u | (immediate & 3) << 29 | (immediate >> 2) << 5;
    assert(inst_get_adrp_label(word) == page_offsets[i]);
  }
  assert(inst_get_and_imm_imm(0x927df108u) == -8);   // and x8, x8, #0xfffffffffffffff8
  assert(inst_get_and_imm_imm(0x927f0108u) == 2);    // and x8, x8, #2
  assert(inst_get_and_imm_imm(0x923ffc08u) == -11);  // reserved logical immediate
  puts(
      "shared instruction macros: unsigned imm12 full range, BL signed boundaries, BLR, all memory "
      "sizes/opcodes/modes, ADD extended, MOVZ and ORR: PASS");
}
