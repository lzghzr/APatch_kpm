"""AArch64 instruction decoders, ported 1:1 from kpm_utils.h.

Fidelity to the C macros matters more than fidelity to the ARM ARM: the goal
is for this offline harness to make exactly the same decisions the KPM makes
at runtime on the device.
"""

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def bits32(n, high, low):
    # ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
    n &= M32
    return ((n << (31 - high)) & M32) >> (31 - high + low)


def bit(n, st):
    return (n >> st) & 1


def sign64_extend(n, length):
    # (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
    # condition: bit (length-1) of n; if set the OR fills bits length..63 and the
    # uint64 result is reinterpreted as a negative `long`
    n &= M64
    if (n >> (length - 1)) & 1:
        return (n | ((M64 << length) & M64)) - (1 << 64)
    return n


def ror(elt, size):
    # (((elt) & 1) << ((size) - 1)) | ((elt) >> 1)
    return (((elt) & 1) << (size - 1)) | (elt >> 1)


def _clz32(v):
    v &= M32
    if v == 0:
        return -1  # __builtin_clz(0) is UB in C; caller treats < 0 as error
    return 32 - v.bit_length()


# --- instruction families (abbr, mask, value) --------------------------------

ADD_IMM = (0x7F800000, 0x11000000)
UXTB = (0xFFFFFC00, 0x53001C00)
ADRP = (0x9F000000, 0x90000000)
AND_IMM = (0x7F800000, 0x12000000)
BL = (0xFC000000, 0x94000000)
CBZ = (0x7F000000, 0x34000000)
TBNZ = (0x7F000000, 0x37000000)
LDR_IMM_UINT = (0xBFC00000, 0xB9400000)
LDRH_IMM_UINT = (0xFFC00000, 0x79400000)
STR_IMM_UINT = (0xBFC00000, 0xB9000000)
STRB_IMM_UINT = (0xFFC00000, 0x39000000)
MOV_REG = (0x7FE0FFE0, 0x2A0003E0)
ORR_REG = (0x7F200000, 0x2A000000)
RET = (0xFFFFFC1F, 0xD65F0000)


def _mk_is(mask, val):
    def inst_is(code):
        return (code & mask) == val
    return inst_is


# --- add_imm: __INST_SF_RN_RD_SH_IMM12_FUNCS(add_imm, 0x7F800000u, 0x11000000u)

def inst_is_add_imm(code):
    return (code & ADD_IMM[0]) == ADD_IMM[1]


def inst_get_add_imm_sf(code):
    return bit(code, 31) if inst_is_add_imm(code) else -1


def inst_get_add_imm_rn(code):
    return bits32(code, 9, 5) if inst_is_add_imm(code) else -1


def inst_get_add_imm_rd(code):
    return bits32(code, 4, 0) if inst_is_add_imm(code) else -1


def inst_get_add_imm_sh(code):
    return bit(code, 22) if inst_is_add_imm(code) else -1


def inst_get_add_imm_imm12(code):
    return bits32(code, 21, 10) if inst_is_add_imm(code) else -1


def inst_get_add_imm_imm(code):
    if not inst_is_add_imm(code):
        return -1
    sh = inst_get_add_imm_sh(code)
    imm12 = inst_get_add_imm_imm12(code)
    if sh == -1 or imm12 == -1:
        return -1
    return sign64_extend(imm12 << 12, 14) if sh else sign64_extend(imm12, 14)


# --- uxtb: __INST_SF_RN_RD_FUNCS(uxtb, 0xFFFFFC00u, 0x53001C00u)

def inst_is_uxtb(code):
    return (code & UXTB[0]) == UXTB[1]


def inst_get_uxtb_sf(code):
    return bit(code, 31) if inst_is_uxtb(code) else -1


def inst_get_uxtb_rn(code):
    return bits32(code, 9, 5) if inst_is_uxtb(code) else -1


def inst_get_uxtb_rd(code):
    return bits32(code, 4, 0) if inst_is_uxtb(code) else -1


# --- adrp: __INST_RD_IMMLO_IMMHI_FUNCS(adrp, 0x9F000000u, 0x90000000u)

def inst_is_adrp(code):
    return (code & ADRP[0]) == ADRP[1]


def inst_get_adrp_rd(code):
    return bits32(code, 4, 0) if inst_is_adrp(code) else -1


def inst_get_adrp_immlo(code):
    return bits32(code, 30, 29) if inst_is_adrp(code) else -1


def inst_get_adrp_immhi(code):
    return bits32(code, 23, 5) if inst_is_adrp(code) else -1


def inst_get_adrp_label(code):
    if not inst_is_adrp(code):
        return -1
    immlo = inst_get_adrp_immlo(code)
    immhi = inst_get_adrp_immhi(code)
    if immlo == -1 or immhi == -1:
        return -1
    return sign64_extend((immhi << 14) | (immlo << 12), 33)


# --- and_imm: __INST_SF_RN_RD_N_FUNCS(and_imm, 0x7F800000u, 0x12000000u)

def inst_is_and_imm(code):
    return (code & AND_IMM[0]) == AND_IMM[1]


def inst_get_and_imm_sf(code):
    return bit(code, 31) if inst_is_and_imm(code) else -1


def inst_get_and_imm_rn(code):
    return bits32(code, 9, 5) if inst_is_and_imm(code) else -1


def inst_get_and_imm_rd(code):
    return bits32(code, 4, 0) if inst_is_and_imm(code) else -1


def inst_get_and_imm_n(code):
    return bit(code, 22) if inst_is_and_imm(code) else -1


def inst_get_and_imm_immr(code):
    return bits32(code, 21, 16) if inst_is_and_imm(code) else -1


def inst_get_and_imm_imms(code):
    return bits32(code, 15, 10) if inst_is_and_imm(code) else -1


def inst_get_and_imm_imm(code):
    if not inst_is_and_imm(code):
        return -1
    sf = inst_get_and_imm_sf(code)
    n = inst_get_and_imm_n(code)
    if sf == 0 and n != 0:
        return -10
    immr = inst_get_and_imm_immr(code)
    imms = inst_get_and_imm_imms(code)
    clz = _clz32((n << 6) | (~imms & 0x3F))
    if clz < 0:
        return -11  # C: __builtin_clz(0) is UB; treated as decode failure here
    length = 31 - clz
    size = 1 << length
    r = immr & (size - 1)
    s = imms & (size - 1)
    if s == size - 1:
        return -12
    pattern = (1 << (s + 1)) - 1
    for _ in range(r):
        pattern = ror(pattern, size)
    reg_size = 32 if sf == 0 else 64
    while size != reg_size:
        pattern |= pattern << size
        size *= 2
    # C returns `long` (int64); keep the same two's-complement interpretation
    pattern &= M64
    return pattern - (1 << 64) if pattern >= (1 << 63) else pattern


# --- bl: __INST_FUNCS(bl, 0xFC000000u, 0x94000000u) + __INST_GET_IMM26(bl)

def inst_is_bl(code):
    return (code & BL[0]) == BL[1]


def inst_get_bl_imm26(code):
    return bits32(code, 25, 0) if inst_is_bl(code) else -1


# --- cbz: __INST_SF_RT_FUNCS(cbz, 0x7F000000u, 0x34000000u) + __INST_GET_IMM19(cbz)

def inst_is_cbz(code):
    return (code & CBZ[0]) == CBZ[1]


def inst_get_cbz_rt(code):
    return bits32(code, 4, 0) if inst_is_cbz(code) else -1


def inst_get_cbz_imm19(code):
    return bits32(code, 23, 5) if inst_is_cbz(code) else -1


# --- tbnz: __INST_SF_RT_FUNCS(tbnz, 0x7F000000u, 0x37000000u) + __INST_GET_IMM14(tbnz)

def inst_is_tbnz(code):
    return (code & TBNZ[0]) == TBNZ[1]


def inst_get_tbnz_rt(code):
    return bits32(code, 4, 0) if inst_is_tbnz(code) else -1


def inst_get_tbnz_imm14(code):
    return bits32(code, 18, 5) if inst_is_tbnz(code) else -1


# --- ldr_imm_uint: __INST_SIZE_RN_RT_IMM12_FUNCS(ldr_imm_uint, 0xBFC00000u, 0xB9400000u)

def inst_is_ldr_imm_uint(code):
    return (code & LDR_IMM_UINT[0]) == LDR_IMM_UINT[1]


def inst_get_ldr_imm_uint_size(code):
    return bits32(code, 31, 30) if inst_is_ldr_imm_uint(code) else -1


def inst_get_ldr_imm_uint_rn(code):
    return bits32(code, 9, 5) if inst_is_ldr_imm_uint(code) else -1


def inst_get_ldr_imm_uint_rt(code):
    return bits32(code, 4, 0) if inst_is_ldr_imm_uint(code) else -1


def inst_get_ldr_imm_uint_imm12(code):
    return bits32(code, 21, 10) if inst_is_ldr_imm_uint(code) else -1


def inst_get_ldr_imm_uint_imm(code):
    if not inst_is_ldr_imm_uint(code):
        return -1
    size = inst_get_ldr_imm_uint_size(code)
    imm12 = inst_get_ldr_imm_uint_imm12(code)
    if size == -1 or imm12 == -1:
        return -1
    return sign64_extend(imm12 << size, 14)


# --- ldrh_imm_uint: __INST_SIZE_RN_RT_IMM12_FUNCS(ldrh_imm_uint, 0xFFC00000u, 0x79400000u)

def inst_is_ldrh_imm_uint(code):
    return (code & LDRH_IMM_UINT[0]) == LDRH_IMM_UINT[1]


def inst_get_ldrh_imm_uint_size(code):
    return bits32(code, 31, 30) if inst_is_ldrh_imm_uint(code) else -1


def inst_get_ldrh_imm_uint_rn(code):
    return bits32(code, 9, 5) if inst_is_ldrh_imm_uint(code) else -1


def inst_get_ldrh_imm_uint_rt(code):
    return bits32(code, 4, 0) if inst_is_ldrh_imm_uint(code) else -1


def inst_get_ldrh_imm_uint_imm12(code):
    return bits32(code, 21, 10) if inst_is_ldrh_imm_uint(code) else -1


def inst_get_ldrh_imm_uint_imm(code):
    if not inst_is_ldrh_imm_uint(code):
        return -1
    size = inst_get_ldrh_imm_uint_size(code)
    imm12 = inst_get_ldrh_imm_uint_imm12(code)
    if size == -1 or imm12 == -1:
        return -1
    return sign64_extend(imm12 << size, 14)


# --- str_imm_uint: __INST_SIZE_RN_RT_IMM12_FUNCS(str_imm_uint, 0xBFC00000u, 0xB9000000u)

def inst_is_str_imm_uint(code):
    return (code & STR_IMM_UINT[0]) == STR_IMM_UINT[1]


def inst_get_str_imm_uint_size(code):
    return bits32(code, 31, 30) if inst_is_str_imm_uint(code) else -1


def inst_get_str_imm_uint_rn(code):
    return bits32(code, 9, 5) if inst_is_str_imm_uint(code) else -1


def inst_get_str_imm_uint_rt(code):
    return bits32(code, 4, 0) if inst_is_str_imm_uint(code) else -1


def inst_get_str_imm_uint_imm12(code):
    return bits32(code, 21, 10) if inst_is_str_imm_uint(code) else -1


def inst_get_str_imm_uint_imm(code):
    if not inst_is_str_imm_uint(code):
        return -1
    size = inst_get_str_imm_uint_size(code)
    imm12 = inst_get_str_imm_uint_imm12(code)
    if size == -1 or imm12 == -1:
        return -1
    return sign64_extend(imm12 << size, 14)


# --- strb_imm_uint: __INST_SIZE_RN_RT_IMM12_FUNCS(strb_imm_uint, 0xFFC00000u, 0x39000000u)

def inst_is_strb_imm_uint(code):
    return (code & STRB_IMM_UINT[0]) == STRB_IMM_UINT[1]


def inst_get_strb_imm_uint_size(code):
    return bits32(code, 31, 30) if inst_is_strb_imm_uint(code) else -1


def inst_get_strb_imm_uint_rn(code):
    return bits32(code, 9, 5) if inst_is_strb_imm_uint(code) else -1


def inst_get_strb_imm_uint_rt(code):
    return bits32(code, 4, 0) if inst_is_strb_imm_uint(code) else -1


def inst_get_strb_imm_uint_imm12(code):
    return bits32(code, 21, 10) if inst_is_strb_imm_uint(code) else -1


def inst_get_strb_imm_uint_imm(code):
    if not inst_is_strb_imm_uint(code):
        return -1
    size = inst_get_strb_imm_uint_size(code)
    imm12 = inst_get_strb_imm_uint_imm12(code)
    if size == -1 or imm12 == -1:
        return -1
    return sign64_extend(imm12 << size, 14)


# --- mov_reg: __INST_SF_RM_RD_FUNCS(mov_reg, 0x7FE0FFE0u, 0x2A0003E0u)

def inst_is_mov_reg(code):
    return (code & MOV_REG[0]) == MOV_REG[1]


def inst_get_mov_reg_sf(code):
    return bit(code, 31) if inst_is_mov_reg(code) else -1


def inst_get_mov_reg_rm(code):
    return bits32(code, 20, 16) if inst_is_mov_reg(code) else -1


def inst_get_mov_reg_rd(code):
    return bits32(code, 4, 0) if inst_is_mov_reg(code) else -1


# --- orr_reg: __INST_SF_RM_RN_RD_FUNCS(orr_reg, 0x7F200000u, 0x2A000000u) + __INST_GET_IMM6(orr_reg)

def inst_is_orr_reg(code):
    return (code & ORR_REG[0]) == ORR_REG[1]


def inst_get_orr_reg_sf(code):
    return bit(code, 31) if inst_is_orr_reg(code) else -1


def inst_get_orr_reg_rm(code):
    return bits32(code, 20, 16) if inst_is_orr_reg(code) else -1


def inst_get_orr_reg_rn(code):
    return bits32(code, 9, 5) if inst_is_orr_reg(code) else -1


def inst_get_orr_reg_rd(code):
    return bits32(code, 4, 0) if inst_is_orr_reg(code) else -1


def inst_get_orr_reg_imm6(code):
    return bits32(code, 15, 10) if inst_is_orr_reg(code) else -1


# --- ret: __INST_RN_FUNCS(ret, 0xFFFFFC1Fu, 0xD65F0000u)

def inst_is_ret(code):
    return (code & RET[0]) == RET[1]


def inst_get_ret_rn(code):
    return bits32(code, 9, 5) if inst_is_ret(code) else -1
