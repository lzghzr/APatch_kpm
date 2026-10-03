"""Extract the kallsyms table embedded in a raw arm64 kernel Image.

The Image always carries the kallsyms structures that /proc/kallsyms serves
from (CONFIG_KALLSYMS), independent of kptr_restrict. Stock layout in
.rodata (relative mode, CONFIG_KALLSYMS_BASE_RELATIVE, 4.6+):

    kallsyms_offsets   u32[num_syms]   (_text-relative offsets)
    kallsyms_relative_base  u64        (vaddr of _text)
    kallsyms_num_syms  u64
    kallsyms_names     [len][token indices]... (token-compressed, first
                       expanded char is the symbol type letter)
    kallsyms_markers   u32[ceil(num_syms/256)]
    kallsyms_token_table  256 NUL-terminated strings
    kallsyms_token_index  u16[256]

    [absolute mode, pre-4.6: kallsyms_addresses u64[num_syms] instead of
     offsets + base]

Real-world images are sometimes repacked/truncated with fields separated by
zero padding and non-standard alignment, so nothing is assumed contiguous:
after each field the parser skips runs of zero bytes, and the offsets array
is bounded by scanning back from the relative_base anchor.
"""

import re
import struct


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _nice_vaddr(v):
    # arm64 kernel virtual addresses; generous band, candidates get validated
    return 0xFFFF000000000000 <= v <= 0xFFFFFFFFF0000000


def _skip_zeros(data, pos, limit=0x400):
    """Position of the first non-zero byte at or after pos (None if none)."""
    end = min(pos + limit, len(data))
    while pos < end:
        if data[pos]:
            return pos
        pos += 1
    return None


def _decode_names_structural(data, off, num_syms):
    """Walk num_syms length-prefixed entries; return end offset or None."""
    if num_syms > 600_000:
        return None
    # cheap pre-check: real name entries have 1 <= len <= 60
    pos = off
    for _ in range(min(num_syms, 256)):
        if pos >= len(data):
            return None
        length = data[pos]
        if not 1 <= length <= 60:
            return None
        pos += 1 + length
    for _ in range(num_syms - 256):
        if pos >= len(data):
            return None
        pos += 1 + data[pos]
    return pos


def _expand_names(data, off, num_syms, tokens):
    """Expand compressed names; returns [(type, name)] or None."""
    out = []
    pos = off
    for _ in range(num_syms):
        if pos >= len(data):
            return None
        length = data[pos]
        pos += 1
        if pos + length > len(data):
            return None
        full = "".join(tokens[data[pos + i]] for i in range(length))
        pos += length
        if len(full) < 2:
            return None
        out.append((full[0], full[1:]))
    return out


UNIVERSAL_SYMS = ("_text", "_stext", "printk", "memcpy", "setup_arch", "init_task")


def _valid_entries(entries):
    """Names must look like kernel symbols AND contain the universal ones —
    a wrong token table decodes into plausible-looking but repetitive
    garbage, which the symbol presence and uniqueness checks reject."""
    if not entries:
        return False
    good = 0
    for _t, n in entries:
        if n and all(c.isalnum() or c in "_.$" for c in n):
            good += 1
    if good < len(entries) * 0.95:
        return False
    names = {n for _t, n in entries}
    if len(names) < len(entries) * 0.90:
        return False
    if "_text" not in names:
        return False
    return sum(1 for s in UNIVERSAL_SYMS if s in names) >= 4


def _vaddr_candidates(data):
    """Yield offsets of u64s whose top bytes look like 0xffff...."""
    needle = b"\xff\xff\xff"
    pos = data.find(needle, 4)
    while pos != -1:
        for q in (pos - 5, pos - 4, pos - 6, pos - 7):
            if q >= 0 and q % 8 == 0:
                yield q
        pos = data.find(needle, pos + 1)


def _find_tokens_near(data, names_end, names_off, num_syms, tokens_window=None):
    """Locate the token table after the names table and validate it by
    expanding the already-located names. Between them sit markers and (5.18+)
    kallsyms_seqs_of_names (u16[num_syms]), so the window scales with
    num_syms. Returns tokens or None."""
    if tokens_window is None:
        tokens_window = 3 * num_syms + 0x20000
    lo = names_end
    hi = min(names_end + tokens_window, len(data))
    off = lo
    while off < hi:
        if data[off - 1] != 0:
            off += 1
            continue
        # density gate: a token table is ~all printable/NUL for the next 64
        # bytes; marker/seq arrays are not
        head = data[off:off + 64]
        if sum(1 for b in head if b == 0 or 0x20 <= b < 0x7F) < 60:
            off += 1
            continue
        toks = _parse_candidate_tokens(data, off)
        if toks is not None:
            # cheap prefix check first: expanding all names is expensive
            prefix = _expand_names(data, names_off, min(num_syms, 32), toks)
            if prefix and all(n and all(c.isalnum() or c in "_.$" for c in n)
                              for _t, n in prefix):
                entries = _expand_names(data, names_off, num_syms, toks)
                if entries and _valid_entries(entries):
                    return toks
        off += 1
    return None


def _parse_candidate_tokens(data, off):
    """Parse 256 NUL-terminated strings at off with a cheap plausibility
    check (real token tables are short fragments)."""
    tokens = []
    pos = off
    total = 0
    for _ in range(256):
        end = data.find(b"\x00", pos, pos + 40)
        if end == -1:
            return None
        s = data[pos:end]
        if any(b > 0x7E or (b < 0x20 and b != 0) for b in s):
            return None
        tokens.append(s)
        total += len(s)
        pos = end + 1
    if sum(1 for t in tokens if t) < 250:
        return None
    if not (1.5 <= total / 256.0 <= 15.0):
        return None
    return [t.decode("ascii") for t in tokens]


def extract(data, verbose=False):
    """Returns (symbols, mode) with symbols = [(reladdr, type, name)], or
    (None, reason). reladdr is _text-relative, i.e. the Image file offset."""
    size = len(data)
    candidates = []
    seen = set()
    for q in _vaddr_candidates(data):
        if q not in seen:
            seen.add(q)
            v = _u64(data, q)
            if _nice_vaddr(v):
                candidates.append((q, v))

    # --- relative mode: offsets[N] ... base | num_syms | names ----------------
    for q, v in candidates:
        npos = _skip_zeros(data, q + 8)
        if npos is None:
            continue
        num_syms = _u32(data, npos)
        if _u32(data, npos + 4) != 0 or not (1000 <= num_syms <= 5_000_000):
            continue
        nstart = _skip_zeros(data, npos + 8)
        if nstart is None:
            continue
        names_end = _decode_names_structural(data, nstart, num_syms)
        if names_end is None or not (2 * num_syms <= names_end - nstart <= 48 * num_syms):
            continue
        tokens = _find_tokens_near(data, names_end, nstart, num_syms)
        if tokens is None:
            if verbose:
                print(f"  base 0x{q:x}: names ok at 0x{nstart:x} but no token table")
            continue
        entries = _expand_names(data, nstart, num_syms, tokens)
        # offsets array: scan back from the base over zero padding
        pos = q - 4
        while pos >= 0 and _u32(data, pos) == 0:
            pos -= 4
        arr_end = pos + 4
        arr_start = arr_end - 4 * num_syms
        if arr_start < 0:
            continue
        offsets = [_u32(data, arr_start + 4 * i) for i in range(num_syms)]
        if offsets[0] > 0x100000 or any(offsets[i] < offsets[i - 1]
                                        for i in range(1, num_syms)):
            continue
        syms = [(offsets[i], entries[i][0], entries[i][1]) for i in range(num_syms)]
        if verbose:
            print(f"  relative mode: base=0x{v:x} num_syms={num_syms} "
                  f"names=0x{nstart:x}..0x{names_end:x} offsets=0x{arr_start:x}..0x{arr_end:x}")
        return syms, "relative"

    # --- absolute mode: addresses[N] | num_syms | names ------------------------
    for q, v in candidates:
        pos = q
        while pos - 8 >= 0:
            prev = _u64(data, pos - 8)
            if not (_nice_vaddr(prev) and prev <= v):
                break
            pos -= 8
        arr_start = pos
        pos = q
        while pos + 8 < size and (pos - arr_start) // 8 < 1_200_000:
            nxt = _u64(data, pos + 8)
            if not (_nice_vaddr(nxt) and nxt >= v):
                break
            pos += 8
        arr_end = pos + 8
        num_syms = (arr_end - arr_start) // 8
        if num_syms < 1000 or num_syms > 600_000:
            continue
        npos = _skip_zeros(data, arr_end)
        if npos is None or _u32(data, npos + 4) != 0 or _u32(data, npos) != num_syms:
            continue
        nstart = _skip_zeros(data, npos + 8)
        if nstart is None:
            continue
        names_end = _decode_names_structural(data, nstart, num_syms)
        if names_end is None or not (2 * num_syms <= names_end - nstart <= 48 * num_syms):
            continue
        tokens = _find_tokens_near(data, names_end, nstart, num_syms)
        if tokens is None:
            continue
        entries = _expand_names(data, nstart, num_syms, tokens)
        addrs = [_u64(data, arr_start + 8 * i) for i in range(num_syms)]
        syms = [(addrs[i] - v, entries[i][0], entries[i][1]) for i in range(num_syms)]
        if verbose:
            print(f"  absolute mode: base=0x{v:x} num_syms={num_syms} "
                  f"names=0x{nstart:x}..0x{names_end:x}")
        return syms, "absolute"

    return None, "no valid kallsyms structure found"


class ExtractedKallsyms:
    """Same lookup interface as kallsyms.Kallsyms, built from extraction."""

    def __init__(self, syms):
        self.order = syms
        self.addr_by_name = {}
        for addr, _t, name in syms:
            self.addr_by_name.setdefault(name, addr)
        self.names_by_addr = {}

    def lookup(self, name):
        return self.addr_by_name.get(name)
