"""Derive genetlink struct layouts from kernel images (harness prototype).

The KPM cannot hardcode struct genl_family/genl_ops layouts (they differ
across 4.4..6.6, and Android kernels backport mainline changes). Instead the
runtime derives every needed offset from two kallsyms-visible anchors:

  ctrl_fill_info  — dumps the family fields tagged by CTRL_ATTR constants
                    (FAMILY_ID=1, FAMILY_NAME=2, VERSION=3, HDRSIZE=4,
                    MAXATTR=5, OPS=6, MCAST_GROUPS=7). From its machine code:
                      attr 2 + add  x?, fam, #imm -> genl_family.name
                      attr 3 + ldr w?, [fam, #imm] -> .version
                      attr 5 + ldr w?, [fam, #imm] -> .maxattr
                      attr 6 region -> .ops (ldr x), .n_ops (ldr w/ldrb w
                                       gives the width), ops stride (movz)
                                       and genl_ops.cmd (ldrb min imm)
                      attr 7 region -> .mcgrps, .n_mcgrps (+width), stride
  ctrl_ops        — the controller's own genl_ops array; its doit slots hold
                    known function addresses (ctrl_newfamily/ctrl_delfamily/
                    ctrl_getfamily), so the hit positions form an arithmetic
                    progression giving genl_ops.doit and the stride.

This file validates that derivation on the corpus kernels and prints the
derived layouts for eyeballing; the same logic is ported to re_offsets.c.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kernel_image import KernelImage
from kallsyms import Kallsyms
from re_insts import bits32, sign64_extend


def is_movz(code):
    return (code & 0x7F800000) == 0x52800000


def is_ldr_x(code):
    return (code & 0xFFC00000) == 0xF9400000


def is_ldr_w(code):
    return (code & 0xFFC00000) == 0xB9400000


def is_ldrb(code):
    return (code & 0xFFC00000) == 0x39400000


def is_add_x(code):
    return (code & 0xFF800000) == 0x91000000


def movz_imm(code):
    return bits32(code, 20, 5)


def ldr_x_imm(code):
    return sign64_extend(bits32(code, 21, 10) << 3, 14)


def ldr_w_imm(code):
    return sign64_extend(bits32(code, 21, 10) << 2, 14)


def ldrb_imm(code):
    return sign64_extend(bits32(code, 21, 10), 14)


def add_x_imm(code):
    return sign64_extend(bits32(code, 21, 10), 14)


def rn(code):
    return bits32(code, 9, 5)


def rd(code):
    return bits32(code, 4, 0)


def is_bl(code):
    return (code & 0xFC000000) == 0x94000000


def is_cbz_w(code):
    return (code & 0x7F000000) == 0x34000000


def c_next(w, i, d):
    j = i + d
    return w[j] if 0 <= j < len(w) else 0


def _next_const_after(w, i, window):
    for j in range(i + 1, min(i + window, len(w))):
        c = w[j]
        if is_bl(c):
            return -1
        if is_movz(c) and rd(c) == 1 and 1 <= movz_imm(c) <= 7:
            return movz_imm(c)
    return -1


def _next_const(w, i, window):
    for j in range(i + 1, min(i + window, len(w))):
        c = w[j]
        if is_bl(c):
            return -1
        if is_movz(c) and rd(c) == 1 and 1 <= movz_imm(c) <= 7:
            return movz_imm(c)
    return -1


def derive(img, ks, verbose=False):
    for sym in ("ctrl_fill_info",):
        if ks.lookup(sym) is None:
            return None, f"{sym} not found"
    text_base = ks.lookup("_text") or 0

    def foff(sym):
        return ks.lookup(sym) - text_base

    f = foff("ctrl_fill_info")
    w = img.words32(f, 0x240)
    found = {}
    # family base register: first `mov xN, x0` anywhere (arg0 spill)
    fam = None
    for i in range(len(w)):
        c = w[i]
        if (c & 0x7FE0FFE0) == 0x2A0003E0 and rd(c) != 31 and bits32(c, 20, 16) == 0:
            fam = rd(c)
            break
    if fam is None:
        return None, "family register (mov xN, x0) not found"

    # ctrl_fill_info emits fields in source order (stable 4.4 -> 6.6):
    #   name(strlen) -> id -> version -> hdrsize -> maxattr
    #   -> [n_ops guard] ops nest/loop -> [n_mcgrps guard] mcgrps nest/loop
    ldr_w_seq = []   # (imm, width, idx) of ldr w/ldrb w from fam, in order
    ldr_x_seq = []   # (imm, idx) of ldr x from fam, in order
    for i in range(len(w)):
        c = w[i]
        if (is_ldr_w(c) or is_ldrb(c)) and rn(c) == fam:
            imm = ldr_w_imm(c) if is_ldr_w(c) else ldrb_imm(c)
            width = 4 if is_ldr_w(c) else 1
            ldr_w_seq.append((imm, width, i))
        elif is_ldr_x(c) and rn(c) == fam:
            ldr_x_seq.append((ldr_x_imm(c), i))
        elif is_add_x(c) and rn(c) == fam:
            imm = add_x_imm(c)
            if 2 <= imm <= 16 and is_bl(c_next(w, i + 2, 0)) and "name" not in found:
                found["name"] = imm  # strlen(family->name) argument

    if len(ldr_w_seq) < 4:
        return None, "scalar field loads not found (id/version/hdrsize/maxattr)"
    # id, version, hdrsize, maxattr — in source order
    found["id"] = ldr_w_seq[0][0]
    found["version"] = ldr_w_seq[1][0]
    found["hdrsize"] = ldr_w_seq[2][0]
    found["maxattr"] = ldr_w_seq[3][0]

    # n_ops / n_mcgrps: first family load within 8 insns before the
    # `mov w1, #6` / `mov w1, #7` of the nest_start calls
    for want, key in ((6, "n_ops"), (7, "n_mcgrps")):
        for i in range(len(w)):
            c = w[i]
            if is_movz(c) and rd(c) == 1 and movz_imm(c) == want:
                cluster = []
                for j in range(i - 1, max(-1, i - 8), -1):
                    cc = w[j]
                    if (is_ldr_w(cc) or is_ldrb(cc)) and rn(cc) == fam:
                        cluster.append(ldr_w_imm(cc) if is_ldr_w(cc) else ldrb_imm(cc))
                    elif is_bl(cc):
                        break
                if cluster:
                    # adjacent loads (e.g. n_ops+n_small_ops or-ed test) share
                    # the guard; the field itself is the lowest offset
                    found[key] = min(cluster)
                    found[key + "_width"] = 4 if any(
                        is_ldr_w(w[j]) for j in range(max(0, i - 8), i)
                        if rn(w[j]) == fam and (is_ldr_w(w[j]) or is_ldrb(w[j]))) else 1
                break
    # mcgrps pointer: first ldr x from fam after the `mov w1, #7` put region
    for i in range(len(w)):
        c = w[i]
        if is_movz(c) and rd(c) == 1 and movz_imm(c) == 7:
            for j in range(i, min(i + 24, len(w))):
                cc = w[j]
                if is_ldr_x(cc) and rn(cc) == fam:
                    found["mcgrps"] = ldr_x_imm(cc)
                    break
            break
    if verbose:
        print("   " + " ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}"
                               for k, v in found.items()))
    return found, None


derive_cache = {}


def derive_ops(img, ks, verbose=False):
    """genl_ops.doit: genl_rcv_msg 中 `if (ops->doit)` 的 ldr x + cbz + blr 模式;
    net->genl_sock: genl_pernet_init 中 netlink_kernel_create 之后的 str [net, #imm]"""
    from re_insts import inst_is_bl, inst_is_ret, inst_is_cbz
    text_base = ks.lookup("_text") or 0

    def scan(sym, want):
        addr = ks.lookup(sym)
        if addr is None:
            return None
        off = addr - text_base
        w = img.words32(off, 0x400)
        # fam/arg0 register = first mov xN, x0
        arg0 = -1
        for i in range(len(w)):
            c = w[i]
            if (c & 0x7FE0FFE0) == 0x2A0003E0 and (c & 0x1F) != 31 and bits32(c, 20, 16) == 0:
                arg0 = (c & 0x1F)
                break
        if want == "doit":
            # cmd_off 来自 ctrl_fill_info; 在 genl_rcv_msg 中找 `ldrb w?, [xM, #cmd]`
            # (ops 命令匹配), 随后同基址 xM 的 `ldr xN, [xM, #doit]` + cbz xN + blr xN
            CMD = derive_cache.get("cmd", 0)
            hits = []
            for i in range(len(w) - 3):
                c = w[i]
                if (c & 0xFFC00000) == 0x39400000 and bits32(c, 21, 10) == CMD:  # ldrb w?, [xM, #cmd]
                    base = bits32(c, 9, 5)
                    for j in range(i + 1, min(i + 24, len(w))):
                        cj = w[j]
                        if (cj & 0xFFC00000) == 0xF9400000 and bits32(cj, 9, 5) == base:
                            imm = sign64_extend(bits32(cj, 21, 10) << 3, 14)
                            rd = cj & 0x1F
                            if rd != 31 and inst_is_cbz(w[j + 1]) and (w[j + 1] & 0x1F) == rd:
                                for k in range(j + 1, min(j + 16, len(w))):
                                    if (w[k] & 0xFFFFFC1F) == 0xD63F0000 and ((w[k] >> 5) & 0x1F) == rd:
                                        hits.append(imm)
                                        break
                                break
                    if hits:
                        break
            return hits
        if want == "genl_sock":
            # bl netlink_kernel_create 之后的 str x?, [xN, #imm] (xN=arg0)
            for i in range(len(w) - 2):
                if inst_is_bl(w[i]):
                    c = w[i + 1]
                    if (c & 0xFFC00000) == 0xF9000000:  # str x
                        rn = bits32(c, 9, 5)
                        if rn == arg0:
                            return sign64_extend(bits32(c, 21, 10) << 3, 14)
        return None

    out = {}
    base, err = derive(img, ks)
    if base:
        derive_cache["cmd"] = base.get("cmd", 0)
    hits = scan("genl_rcv_msg", "doit")
    if hits:
        out["blr_candidates"] = hits
    gs = scan("genl_pernet_init", "genl_sock")
    if gs:
        out["genl_sock"] = gs
    if verbose:
        print("   " + " ".join(f"{k}={v}" for k, v in out.items()))
    return out, None


def main():
    import bootimg
    import layout

    entries = layout.scan(str(layout.DEFAULT_IMG_ROOT))
    if not entries:
        print("kernel_img/ 下没有镜像；先放 img（见 kernel_img/README.md）")
        return 2
    for entry in entries:
        if entry.image is None:
            continue
        try:
            unpacked = bootimg.unpack_file(entry.image)
        except Exception as exc:
            print(f"{entry.stem}: unpack failed: {exc}")
            continue
        label = entry.label
        if label is None:
            label = (f"{unpacked.major}/{layout.safe_label(layout.short_release(unpacked.release))}"
                     if unpacked.major else layout.safe_label(entry.stem))
        img = KernelImage(unpacked.data, str(entry.image))
        ext = layout.DEFAULT_OUT_ROOT / label / "kallsyms_extracted.txt"
        ks = None
        for path in [ext] + [Path(p) for p in entry.symbols]:
            if not path.exists():
                continue
            cand = Kallsyms.parse(path)
            if sum(1 for a, _t, _n in cand.order if a) > len(cand.order) * 0.5:
                ks = cand
                break
        if ks is None:
            if entry.directory.resolve() == layout.DEFAULT_IMG_ROOT.resolve():
                where = "kernel_img/<大版本>/<小版本>/"
            else:
                where = layout.display_path(entry.directory)
            print(f"{label}: no usable kallsyms（把 kallsyms.txt 放到 {where}）")
            continue
        res, err = derive(img, ks, verbose=True)
        print(f"{label}: {'FAIL ' + err if err else 'derived ^'}")
        ops, err2 = derive_ops(img, ks, verbose=True)
        print(f"{label}: ops-derive {'FAIL ' + str(err2) if err2 else ops}")
    return 0


if __name__ == "__main__":
    main()
