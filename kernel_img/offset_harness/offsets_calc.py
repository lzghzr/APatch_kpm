"""Offline port of re_kernel/re_offsets.c `calculate_offsets()`.

Every loop bound, branch condition, delta and fallback mirrors the C code so
that the derived offsets are bit-identical to what the KPM computes at runtime.
"""

from re_insts import (
    inst_is_ret,
    inst_is_bl,
    inst_is_cbz,
    inst_is_tbnz,
    inst_is_adrp,
    inst_is_ldrh_imm_uint,
    inst_is_orr_reg,
    inst_is_strb_imm_uint,
    inst_get_add_imm_imm,
    inst_get_add_imm_rd,
    inst_get_add_imm_rn,
    inst_get_add_imm_sf,
    inst_get_adrp_label,
    inst_get_and_imm_imm,
    inst_get_ldr_imm_uint_imm,
    inst_get_ldr_imm_uint_rn,
    inst_get_ldr_imm_uint_size,
    inst_get_ldrh_imm_uint_imm,
    inst_get_mov_reg_rd,
    inst_get_mov_reg_rm,
    inst_get_str_imm_uint_imm,
    inst_get_str_imm_uint_rn,
    inst_get_str_imm_uint_size,
    inst_get_str_imm_uint_rt,
    inst_get_strb_imm_uint_imm,
    inst_get_uxtb_rn,
)

M64 = 0xFFFFFFFFFFFFFFFF

IZERO = 1 << 0x10
UZERO = 1 << 0x20

# struct struct_offset field names, re_kernel.h order
FIELDS = [
    "binder_alloc_buffer_size",
    "binder_alloc_buffer",
    "binder_alloc_free_async_space",
    "binder_alloc_pid",
    "binder_node_async_todo",
    "binder_node_cookie",
    "binder_node_has_async_transaction",
    "binder_node_lock",
    "binder_node_ptr",
    "binder_proc_alloc",
    "binder_proc_context",
    "binder_proc_inner_lock",
    "binder_proc_is_frozen",
    "binder_proc_outer_lock",
    "binder_proc_outstanding_txns",
    "binder_stats_deleted_transaction",
    "binder_transaction_buffer",
    "binder_transaction_code",
    "binder_transaction_flags",
    "binder_transaction_from",
    "binder_transaction_to_proc",
    "sk_buff_len",
    "sk_buff_transport_header",
    "sk_buff_network_header",
    "sk_buff_tail",
    "sk_buff_head",
    "sk_buff_data",
    "task_struct_group_leader",
    "task_struct_jobctl",
    "task_struct_pid",
    "task_struct_tgid",
]

# anchors consumed by calculate_offsets(); (symbol, required, fallback)
ANCHORS = [
    "binder_transaction_buffer_release",
    "binder_proc_transaction",
    "task_clear_jobctl_trapping",
    "binder_transaction",
    "binder_free_proc",
    "binder_alloc_init",
    "binder_free_transaction",
    "skb_trim",
    "ipv6_find_tlv",
    "binder_stats",
]


class CalcError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


class OffsetCalculator:
    """Mirrors calculate_offsets() on one kernel image + kallsyms table.

    Addresses in the corpus kallsyms dumps are relative to `_text`, i.e. equal
    to file offsets inside the raw Image, so all address arithmetic is done in
    that relative space (identical to the runtime's absolute vaddr math).
    """

    def __init__(self, image, ks, trace_insn=False):
        self.image = image
        self.ks = ks
        self.trace_insn = trace_insn
        self.trace = []
        self.struct_offset = {f: 0 for f in FIELDS}
        self.ver6 = UZERO
        self.ver5 = UZERO
        self.ver4 = UZERO
        self.fallbacks = []
        self.func_addr = {}

    def log(self, fmt, *args):
        # C printf formats: %llx formats an int as hex in Python too
        self.trace.append(fmt.replace("%llx", "%x") % args if args else fmt)

    def dbg(self, tag, i, word):
        # mirrors the per-instruction logkm() dumps under CONFIG_DEBUG
        if self.trace_insn:
            self.log("%s %x %llx", tag, i, word)

    def lookup_name(self, name):
        addr = self.ks.lookup(name)
        self.log("kernel function %s addr: %llx", name, addr if addr else 0)
        if not addr:
            raise CalcError(-21, f"kallsyms_lookup_name({name}) failed")
        return addr

    def lookup_name_continue(self, name):
        addr = self.ks.lookup(name)
        self.log("kernel function %s addr: %llx", name, addr if addr else 0)
        return addr

    def words(self, func_addr, count, before=0, after=8):
        off = func_addr  # kallsyms addrs are _text-relative == file offsets
        if off + (count + after) * 4 > self.image.size:
            count = max(0, (self.image.size - off) // 4 - after)
        return self.image.words32(off - before * 4, count + before + after)

    # --- block 1: binder_transaction_buffer_release version flags ------------

    def calc_buffer_release_version(self, w):
        for i in range(0x100):
            self.dbg("binder_transaction_buffer_release", i, w[i])
            if i < 0x10:
                if (inst_get_str_imm_uint_rt(w[i]) == 4 or inst_get_mov_reg_rm(w[i]) == 4
                        or inst_get_uxtb_rn(w[i]) == 4):
                    self.ver5 = IZERO
                elif (inst_get_str_imm_uint_rt(w[i]) == 3 or inst_get_mov_reg_rm(w[i]) == 3
                        or inst_get_uxtb_rn(w[i]) == 3):
                    self.ver4 = IZERO
            elif self.ver5 == UZERO:
                break
            elif inst_get_and_imm_imm(w[i]) == -8:
                for j in range(1, 0x3):
                    if inst_is_cbz(w[i + j]) or inst_is_tbnz(w[i + j]):
                        self.ver6 = IZERO
                        break
                break
        self.log("binder_transaction_buffer_release_ver6=0x%llx", self.ver6)
        self.log("binder_transaction_buffer_release_ver5=0x%llx", self.ver5)
        self.log("binder_transaction_buffer_release_ver4=0x%llx", self.ver4)

    # --- block 2: binder_proc_transaction ------------------------------------

    def calc_binder_proc_transaction(self, w):
        so = self.struct_offset
        for i in range(0x70):
            self.dbg("binder_proc_transaction", i, w[i])
            if inst_is_ret(w[i]):
                break
            elif not so["binder_node_has_async_transaction"] and inst_is_strb_imm_uint(w[i]):
                offset = inst_get_strb_imm_uint_imm(w[i])
                if offset < 0x6B or offset > 0x7B:
                    continue
                so["binder_node_has_async_transaction"] = offset
                so["binder_node_ptr"] = offset - 0x13
                so["binder_node_cookie"] = offset - 0xB
                so["binder_node_async_todo"] = offset + 0x5
                # 目前只有 harmony 内核需要特殊设置
                if offset == 0x7B:
                    so["binder_node_lock"] = 0x8
                    so["binder_transaction_from"] = 0x28
                else:
                    so["binder_node_lock"] = 0x4
                    so["binder_transaction_from"] = 0x20
            elif (not so["binder_transaction_buffer"]
                  and inst_get_ldr_imm_uint_size(w[i]) == 0b11
                  and inst_get_ldr_imm_uint_rn(w[i]) == 0):
                so["binder_transaction_buffer"] = inst_get_ldr_imm_uint_imm(w[i])
                so["binder_transaction_to_proc"] = so["binder_transaction_buffer"] - 0x20
                so["binder_transaction_code"] = so["binder_transaction_buffer"] + 0x8
                so["binder_transaction_flags"] = so["binder_transaction_buffer"] + 0xC
            elif inst_is_orr_reg(w[i]) and inst_is_strb_imm_uint(w[i + 1]):
                binder_proc_sync_recv_offset = inst_get_strb_imm_uint_imm(w[i + 1])
                so["binder_proc_is_frozen"] = binder_proc_sync_recv_offset - 1
                so["binder_proc_outstanding_txns"] = binder_proc_sync_recv_offset - 0x6
                break
        self.log("binder_transaction_from=0x%x", so["binder_transaction_from"])
        self.log("binder_transaction_to_proc=0x%x", so["binder_transaction_to_proc"])
        self.log("binder_transaction_buffer=0x%x", so["binder_transaction_buffer"])
        self.log("binder_transaction_code=0x%x", so["binder_transaction_code"])
        self.log("binder_transaction_flags=0x%x", so["binder_transaction_flags"])
        self.log("binder_node_lock=0x%x", so["binder_node_lock"])
        self.log("binder_node_ptr=0x%x", so["binder_node_ptr"])
        self.log("binder_node_cookie=0x%x", so["binder_node_cookie"])
        self.log("binder_node_has_async_transaction=0x%x", so["binder_node_has_async_transaction"])
        self.log("binder_node_async_todo=0x%x", so["binder_node_async_todo"])
        self.log("binder_proc_outstanding_txns=0x%x", so["binder_proc_outstanding_txns"])
        self.log("binder_proc_is_frozen=0x%x", so["binder_proc_is_frozen"])
        if (so["binder_node_lock"] <= 0 or so["binder_node_has_async_transaction"] <= 0
                or so["binder_transaction_buffer"] <= 0):
            raise CalcError(-11, "binder_proc_transaction: node/transaction offsets not found")

    # --- block 3: task_clear_jobctl_trapping ----------------------------------

    def calc_task_jobctl(self, w):
        so = self.struct_offset
        for i in range(0x10):
            self.dbg("task_clear_jobctl_trapping", i, w[i])
            if inst_is_ret(w[i]):
                break
            elif (inst_get_ldr_imm_uint_size(w[i]) == 0b11
                  and inst_get_ldr_imm_uint_rn(w[i]) == 0):
                so["task_struct_jobctl"] = inst_get_ldr_imm_uint_imm(w[i])
                break
        self.log("task_struct_jobctl=0x%x", so["task_struct_jobctl"])
        if so["task_struct_jobctl"] <= 0:
            raise CalcError(-11, "task_struct_jobctl not found")

    # --- block 4: binder_transaction ------------------------------------------

    def calc_binder_transaction(self, w):
        so = self.struct_offset
        for i in range(0x20):
            self.dbg("binder_transaction", i, w[i])
            if inst_is_ret(w[i]):
                break
            elif inst_get_ldr_imm_uint_size(w[i]) == 0b11:
                offset = inst_get_ldr_imm_uint_imm(w[i])
                if offset < 0x200 or offset > 0x300:
                    continue
                so["binder_proc_context"] = offset
                so["binder_proc_inner_lock"] = offset + 0x8
                so["binder_proc_outer_lock"] = offset + 0xC
                break
        self.log("binder_proc_context=0x%x", so["binder_proc_context"])
        self.log("binder_proc_inner_lock=0x%x", so["binder_proc_inner_lock"])
        self.log("binder_proc_outer_lock=0x%x", so["binder_proc_outer_lock"])
        if so["binder_proc_context"] <= 0:
            raise CalcError(-11, "binder_proc_context not found")

    # --- block 5: binder_free_proc / binder_proc_dec_tmpref --------------------

    def calc_binder_free_proc(self, w):
        so = self.struct_offset
        for i in range(0x10, 0x100):
            self.dbg("binder_free_proc", i, w[i])
            if inst_get_mov_reg_rd(w[i]) == 29 and inst_get_mov_reg_rm(w[i]) == 0:
                break
            elif (inst_get_add_imm_sf(w[i]) == 1 and inst_get_add_imm_rd(w[i]) == 0
                  and inst_get_add_imm_rn(w[i]) == 19 and inst_is_bl(w[i + 1])):
                so["binder_proc_alloc"] = inst_get_add_imm_imm(w[i])
                if so["binder_proc_alloc"] > so["binder_proc_context"]:
                    continue
                break
        self.log("binder_proc_alloc=0x%x", so["binder_proc_alloc"])
        if so["binder_proc_alloc"] <= 0:
            raise CalcError(-11, "binder_proc_alloc not found")

    # --- block 6: binder_alloc_init --------------------------------------------

    def calc_binder_alloc_init(self, w):
        so = self.struct_offset
        # window starts 0x10 words before the function so that src[i-j] with
        # negative i-j stays in bounds, same as C reading adjacent memory
        base = 0x10
        for i in range(0x20):
            self.dbg("binder_alloc_init", i, w[base + i])
            if inst_is_ret(w[base + i]):
                for j in range(1, 0x10):
                    if inst_get_add_imm_sf(w[base + i - j]) == 1:
                        binder_alloc_buffers_offset = inst_get_add_imm_imm(w[base + i - j])
                        so["binder_alloc_buffer"] = binder_alloc_buffers_offset - 0x8
                        so["binder_alloc_free_async_space"] = binder_alloc_buffers_offset + 0x20
                        so["binder_alloc_buffer_size"] = binder_alloc_buffers_offset + 0x30
                        break
                break
            elif (not so["binder_alloc_pid"]
                  and inst_get_str_imm_uint_size(w[base + i]) == 0b10
                  and inst_get_str_imm_uint_rn(w[base + i]) == 0):
                so["binder_alloc_pid"] = inst_get_str_imm_uint_imm(w[base + i])
            elif (not so["binder_alloc_pid"]
                  and inst_get_ldr_imm_uint_size(w[base + i]) == 0b10):
                so["task_struct_pid"] = inst_get_ldr_imm_uint_imm(w[base + i])
                so["task_struct_tgid"] = so["task_struct_pid"] + 0x4
            elif (not so["binder_alloc_pid"]
                  and inst_get_ldr_imm_uint_size(w[base + i]) == 0b11):
                so["task_struct_group_leader"] = inst_get_ldr_imm_uint_imm(w[base + i])
        self.log("binder_alloc_pid=0x%x", so["binder_alloc_pid"])
        self.log("binder_alloc_buffer_size=0x%x", so["binder_alloc_buffer_size"])
        self.log("binder_alloc_free_async_space=0x%x", so["binder_alloc_free_async_space"])
        self.log("binder_alloc_buffer=0x%x", so["binder_alloc_buffer"])
        self.log("task_struct_pid=0x%x", so["task_struct_pid"])
        self.log("task_struct_tgid=0x%x", so["task_struct_tgid"])
        self.log("task_struct_group_leader=0x%x", so["task_struct_group_leader"])
        if (so["binder_alloc_pid"] <= 0 or so["task_struct_pid"] <= 0
                or so["task_struct_group_leader"] <= 0):
            raise CalcError(-11, "binder_alloc_init: alloc/task offsets not found")

    # --- block 7: binder_free_transaction + binder_stats ------------------------

    def calc_binder_stats(self, w, func_addr):
        so = self.struct_offset
        binder_stats_addr = self.ks.lookup("binder_stats")
        if not binder_stats_addr:
            binder_stats_addr = 0  # runtime: kvar(binder_stats) == NULL
            self.log("binder_stats not found, treat as NULL")
        for i in range(0x100):
            self.dbg("binder_free_transaction", i, w[i])
            if inst_is_adrp(w[i]):
                inst_addr = func_addr + i * 4
                adrp_offset = inst_get_adrp_label(w[i])
                adrp_addr = (inst_addr + adrp_offset) & (M64 ^ 0xFFF)
                if ((adrp_addr - (binder_stats_addr & (M64 ^ 0xFFF))) & M64) <= 0x1000:
                    stats_lo = binder_stats_addr & 0xFFF
                    for j in range(0x10):
                        if inst_get_add_imm_sf(w[i + j]) == 1:
                            adrl_addr = inst_get_add_imm_imm(w[i + j])
                            deleted_offset = (adrl_addr - stats_lo) & 0xFFF
                            if deleted_offset == 0:
                                for k in range(0x10):
                                    if inst_get_add_imm_sf(w[i + j + k]) == 1:
                                        offset = inst_get_add_imm_imm(w[i + j + k])
                                        if 0xC0 < offset < 0xE0:
                                            so["binder_stats_deleted_transaction"] = offset
                                            break
                            elif 0xC0 < deleted_offset < 0xE0:
                                so["binder_stats_deleted_transaction"] = deleted_offset
                                break
                    break
        self.log("binder_stats_deleted_transaction=0x%llx",
                 so["binder_stats_deleted_transaction"] & M64)
        if so["binder_stats_deleted_transaction"] <= 0:
            raise CalcError(-11, "binder_stats_deleted_transaction not found")

    # --- block 8: skb_trim -------------------------------------------------------

    def calc_skb_trim(self, w):
        so = self.struct_offset
        for i in range(0x8):
            self.dbg("skb_trim", i, w[i])
            if inst_is_ret(w[i]):
                break
            elif inst_get_ldr_imm_uint_size(w[i]) == 0b10:
                so["sk_buff_len"] = inst_get_ldr_imm_uint_imm(w[i])
                break
        self.log("sk_buff_len=0x%x", so["sk_buff_len"])
        if so["sk_buff_len"] <= 0:
            raise CalcError(-11, "sk_buff_len not found")

    # --- block 9: ipv6_find_tlv ---------------------------------------------------

    def calc_ipv6_find_tlv(self, w):
        so = self.struct_offset
        for i in range(0x8):
            self.dbg("ipv6_find_tlv", i, w[i])
            if inst_is_ret(w[i]):
                break
            elif inst_get_ldr_imm_uint_size(w[i]) == 0b11:
                so["sk_buff_head"] = inst_get_ldr_imm_uint_imm(w[i])
                so["sk_buff_data"] = so["sk_buff_head"] + 0x8
                so["sk_buff_tail"] = so["sk_buff_head"] - 0x8
            elif inst_is_ldrh_imm_uint(w[i]):
                so["sk_buff_network_header"] = inst_get_ldrh_imm_uint_imm(w[i])
                so["sk_buff_transport_header"] = so["sk_buff_network_header"] - 0x2
        self.log("sk_buff_network_header=0x%x", so["sk_buff_network_header"])
        self.log("sk_buff_tail=0x%x", so["sk_buff_tail"])
        self.log("sk_buff_head=0x%x", so["sk_buff_head"])
        self.log("sk_buff_data=0x%x", so["sk_buff_data"])
        if so["sk_buff_network_header"] <= 0 or so["sk_buff_head"] <= 0:
            raise CalcError(-11, "sk_buff headers not found")

    # --- driver -------------------------------------------------------------------

    def run(self):
        ks = self.ks
        bs_addr = ks.lookup("binder_stats")
        if bs_addr:
            self.func_addr["binder_stats"] = bs_addr

        addr = self.lookup_name("binder_transaction_buffer_release")
        self.func_addr["binder_transaction_buffer_release"] = addr
        self.calc_buffer_release_version(self.words(addr, 0x100))

        addr = self.lookup_name("binder_proc_transaction")
        self.func_addr["binder_proc_transaction"] = addr
        self.calc_binder_proc_transaction(self.words(addr, 0x70))

        addr = self.lookup_name("task_clear_jobctl_trapping")
        self.func_addr["task_clear_jobctl_trapping"] = addr
        self.calc_task_jobctl(self.words(addr, 0x10))

        addr = self.lookup_name("binder_transaction")
        self.func_addr["binder_transaction"] = addr
        self.calc_binder_transaction(self.words(addr, 0x20))

        addr = self.lookup_name_continue("binder_free_proc")
        if not addr:
            self.fallbacks.append("binder_proc_dec_tmpref")
            addr = self.lookup_name("binder_proc_dec_tmpref")
        self.func_addr["binder_free_proc"] = addr
        self.calc_binder_free_proc(self.words(addr, 0x100))

        addr = self.lookup_name("binder_alloc_init")
        self.func_addr["binder_alloc_init"] = addr
        self.calc_binder_alloc_init(self.words(addr, 0x20, before=0x10))

        addr = self.lookup_name_continue("binder_free_transaction")
        if not addr:
            self.fallbacks.append("binder_send_failed_reply")
            addr = self.lookup_name("binder_send_failed_reply")
        self.func_addr["binder_free_transaction"] = addr
        self.calc_binder_stats(self.words(addr, 0x100, after=0x20), addr)

        addr = self.ks.lookup("skb_trim")
        self.log("kernel function skb_trim addr: %llx", addr if addr else 0)
        if not addr:
            raise CalcError(-21, "kallsyms_lookup_name(skb_trim) failed")
        self.func_addr["skb_trim"] = addr
        self.calc_skb_trim(self.words(addr, 0x8))

        addr = self.lookup_name("ipv6_find_tlv")
        self.func_addr["ipv6_find_tlv"] = addr
        self.calc_ipv6_find_tlv(self.words(addr, 0x8))

        return self.struct_offset
