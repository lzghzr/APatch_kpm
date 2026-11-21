#!/usr/bin/env python3
"""Auditor 自有的 KPM 产物解析器（DEV-125 / cgroupv2_freeze 审计用）。

不导入 `tools/identity.py`、`tools/build_candidate.py`，也不调用
`kernel_img/offset_harness`：只按 ELF64 规范读产物字节。

用法::

    python3 Auditor/tools/cfv2_dev125_elf.py <kpm>
    python3 Auditor/tools/cfv2_dev125_elf.py <kpm> --window 0x24e0:0x253c
    python3 Auditor/tools/cfv2_dev125_elf.py <kpm> --strings

输出：文件 sha256/size、节表、符号表（DEF/UND 与所属节）、重定位统计、
关键字面（kf_* / cfv2_* / cg_json_* / run_cmd 等已删除项）、可选指令窗口的
原始 32 位指令字（附热路径判定序列的自解码）。
"""
import hashlib
import struct
import sys

# AArch64 ELF relocation types used by this artifact family.
R_TYPES = {
    257: "ABS64", 258: "ABS32", 259: "ABS16", 260: "PREL64", 261: "PREL32",
    275: "ADR_PREL_PG_HI21", 277: "ADD_ABS_LO12_NC", 278: "LDST8_ABS_LO12_NC",
    284: "LDST16_ABS_LO12_NC", 285: "LDST32_ABS_LO12_NC",
    282: "CALL26", 283: "JUMP26", 286: "LDST64_ABS_LO12_NC",
}
SYM_TYPE = {0: "NOTYPE", 1: "OBJ", 2: "FUNC", 3: "SEC", 4: "FILE"}
SYM_BIND = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}


class Elf:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise SystemExit("not an ELF64 little-endian object")
        self.e_type, self.e_machine = struct.unpack_from("<HH", d, 16)
        self.e_shoff = struct.unpack_from("<Q", d, 40)[0]
        self.e_shentsize = struct.unpack_from("<H", d, 58)[0]
        self.e_shnum = struct.unpack_from("<H", d, 60)[0]
        self.e_shstrndx = struct.unpack_from("<H", d, 62)[0]
        self.sh = [struct.unpack_from("<IIQQQQIIQQ", d, self.e_shoff + i * self.e_shentsize)
                   for i in range(self.e_shnum)]
        s = self.sh[self.e_shstrndx]
        self.shstrtab = d[s[4]:s[4] + s[5]]

    def shname(self, off):
        e = self.shstrtab.find(b"\0", off)
        return self.shstrtab[off:e].decode()

    def section(self, name):
        for i, s in enumerate(self.sh):
            if self.shname(s[0]) == name:
                return i, s
        return None, None

    def sec_bytes(self, name):
        _, s = self.section(name)
        return self.data[s[4]:s[4] + s[5]]

    def symbols(self):
        si, s = self.section(".symtab")
        st = self.data[s[4]:s[4] + s[5]]
        strtab = self.data[self.sh[s[6]][4]:self.sh[s[6]][4] + self.sh[s[6]][5]]
        out = []
        for i in range(len(st) // 24):
            nm, info, _other, shndx, val, size = struct.unpack_from("<IBBHQQ", st, i * 24)
            e = strtab.find(b"\0", nm)
            out.append({"idx": i, "name": strtab[nm:e].decode("utf8", "replace"),
                        "type": info & 0xF, "bind": info >> 4,
                        "shndx": shndx, "val": val, "size": size})
        return out

    def relocs(self, secname):
        _, s = self.section(".rela" + secname)
        if s is None:
            return []
        buf = self.data[s[4]:s[4] + s[5]]
        syms = self.symbols()
        out = []
        for i in range(len(buf) // 24):
            off, info, addend = struct.unpack_from("<QQq", buf, i * 24)
            sym = info >> 32
            out.append({"off": off, "type": info & 0xFFFFFFFF, "addend": addend,
                        "sym": sym, "symname": syms[sym]["name"] if sym < len(syms) else "?"})
        return out


def decode_hotpath(w):
    """Minimal hand decoder for the instructions used in vfs_read_after's prologue."""
    if (w & 0xFFC003FF) == 0xD10003FF or (w & 0xFF8003FF) == 0xD10003FF:
        imm = (w >> 10) & 0xFFF
        return "sub sp, sp, #0x%x" % imm
    if (w & 0xFF000000) == 0x39000000:
        return "ldrb w%d, [x%d, #0x%x]" % (w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF))
    if (w & 0xFF000000) == 0xF9000000:
        return "ldr x%d, [x%d, #0x%x]" % (w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8)
    if (w & 0x7E000000) == 0x34000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & (1 << 18):
            imm -= 1 << 19
        reg = ("x%d" if w & 0x80000000 else "w%d") % (w & 0x1F)
        return "cbz %s, +0x%x" % (reg, imm * 4)
    if (w & 0xFF000010) == 0x54000000:
        imm = (w >> 5) & 0x7FFFF
        if imm & (1 << 18):
            imm -= 1 << 19
        cond = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"][w & 0xF]
        return "b.%s +0x%x" % (cond, imm * 4)
    if (w & 0xFF000000) == 0xEB000000:
        rn = (w >> 5) & 0x1F
        rm = (w >> 16) & 0x1F
        return "subs xzr, %s, %s  (cmp)" % ("xzr" if rn == 31 else "x%d" % rn,
                                            "xzr" if rm == 31 else "x%d" % rm)
    if (w & 0xFFC003FF) == 0x910003FF:
        imm = (w >> 10) & 0xFFF
        rd = "sp" if (w & 0x1F) == 31 else "x%d" % (w & 0x1F)
        rn = "sp" if ((w >> 5) & 0x1F) == 31 else "x%d" % ((w >> 5) & 0x1F)
        return "add %s, %s, #0x%x" % (rd, rn, imm)
    if (w & 0xFFC00000) == 0xA9000000:
        imm = ((w >> 15) & 0x7F) * 8
        return "stp x%d, x%d, [sp, #0x%x]" % (w & 0x1F, (w >> 10) & 0x1F, imm)
    if (w & 0xFFC00000) == 0xA9400000:
        imm = ((w >> 15) & 0x7F) * 8
        return "ldp x%d, x%d, [sp, #0x%x]" % (w & 0x1F, (w >> 10) & 0x1F, imm)
    if (w & 0xFFFFFC1F) == 0xD65F0000:
        return "ret"
    return ""


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    e = Elf(path)
    print("file   : %s" % path)
    print("sha256 : %s" % hashlib.sha256(e.data).hexdigest())
    print("size   : %d" % len(e.data))
    print("elf    : type=%d machine=%d sections=%d" % (e.e_type, e.e_machine, e.e_shnum))

    print("\n[section table]")
    for i, s in enumerate(e.sh):
        print("  %2d %-18s type=%2d flags=0x%02x off=0x%05x size=%-6d link=%d info=%d"
              % (i, e.shname(s[0]) or "<null>", s[1], s[2], s[4], s[5], s[6], s[7]))

    syms = e.symbols()
    print("\n[undefined symbols] (KP loader fills these; DEF in .bss would never be filled)")
    for s in syms:
        if s["shndx"] == 0 and s["idx"] != 0:
            print("  UND  %-32s bind=%s" % (s["name"], SYM_BIND.get(s["bind"], s["bind"])))
    print("\n[kf_* defined locally] (expected for kfunc_def slots filled by kfunc_lookup_name)")
    for s in syms:
        if s["name"].startswith("kf_") and s["shndx"] != 0:
            sec = e.shname(e.sh[s["shndx"]][0]) if s["shndx"] < len(e.sh) else "?"
            print("  DEF  %-32s %-8s val=0x%x" % (s["name"], sec, s["val"]))
    bad = [s["name"] for s in syms
           if s["shndx"] != 0 and s["name"] in
           ("kf_memset", "kf_memcpy", "kf_memmove", "kf_memcmp", "kf_strlen", "kf_strcmp", "kf_snprintf")]
    print("  kf_mem*/kf_str* wrongly DEF: %s" % (bad if bad else "none"))

    print("\n[entry points]")
    for sec in (".kpm.init", ".kpm.ctl0", ".kpm.exit"):
        for r in e.relocs(sec):
            print("  %-10s -> section addend 0x%x" % (sec, r["addend"]))
    print("  .kpm.info: %r" % e.sec_bytes(".kpm.info"))

    print("\n[.text relocations]")
    rel = e.relocs(".text")
    print("  total=%d types=%s" % (len(rel), sorted({R_TYPES.get(r["type"], r["type"]) for r in rel})))
    from collections import Counter
    c = Counter(r["symname"] for r in rel if r["symname"])
    for k in sorted(c):
        print("    %-32s %d" % (k, c[k]))

    if "--strings" in sys.argv:
        print("\n[deleted-item string scan] (all must be 0 occurrences)")
        for pat in (b"run_cmd", b"setup_cgroups", b"do_filp_open", b"call_usermodehelper",
                    b"kthread_create", b"selinux", b"enforcing", b"setup_worker"):
            n = e.data.count(pat)
            print("  %-22s %d" % (pat.decode(), n))

    win = None
    for i, a in enumerate(sys.argv):
        if a == "--window" and i + 1 < len(sys.argv):
            lo, hi = sys.argv[i + 1].split(":")
            win = (int(lo, 0), int(hi, 0))
    if win:
        text = e.sec_bytes(".text")
        print("\n[instruction window 0x%x:0x%x]" % win)
        for a in range(win[0], win[1], 4):
            w = struct.unpack_from("<I", text, a)[0]
            dec = decode_hotpath(w)
            print("  0x%04x  %08x  %s" % (a, w, dec))


if __name__ == "__main__":
    main()
