"""Validate typed ARM64 veneers before classifying their KCFI prefixes as data."""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patch_offsets import elf_sections, elf_symbols

ENTRIES = (('compress', 0x6cfa6c9d), ('decompress', 0x6cfa6c9d),
           ('create_zstd', 0x99e4d7cb), ('create_lz4', 0x99e4d7cb), ('create_lz4kd', 0x99e4d7cb),
           ('destroy', 0x719f1be7), ('setup_zstd', 0x819d5c54), ('setup_lz4', 0x819d5c54),
           ('setup_lz4kd', 0x819d5c54), ('release', 0xef7e90ea))


def validate(data):
    sections, names_id = elf_sections(data)
    names = sections[names_id]
    strings = data[names[4]:names[4] + names[5]]
    indices = [i for i, s in enumerate(sections) if strings[s[0]:].split(b'\0', 1)[0] == b'.text.zs_kcfi']
    symbols = elf_symbols(data)
    entries = [s for s in symbols if s[2].startswith(b'zs_native_') and not s[2].endswith(b'_impl') and s[3] & 15 == 2]
    if not indices:
        assert not entries, 'native entries require typed section'
        return set()
    assert len(indices) == 1
    idx = indices[0]
    sec = sections[idx]
    assert sec[1:3] == (1, 6) and sec[5] == 12 * len(ENTRIES) and sec[8] == 4
    funcs = [s for s in symbols if s[4] == idx and s[3] & 15 == 2]
    assert len(funcs) == len(ENTRIES)
    relocs = []
    for s in sections:
        if s[1] in (4, 9) and s[7] == idx:
            assert s[1] == 4 and s[9] == 24 and s[5] % 24 == 0
            for at in range(s[4], s[4] + s[5], 24):
                off, info, addend = struct.unpack_from('<QQq', data, at)
                sym = next(t for t in symbols if t[0] == s[6] and t[1] == info >> 32)
                relocs.append((off, info & 0xffffffff, sym[2], addend))
    expected_relocs = []
    ignored = set()
    for i, (suffix, tag) in enumerate(ENTRIES):
        name = ('zs_native_' + suffix).encode()
        matches = [s for s in funcs if s[2] == name]
        assert len(matches) == 1
        symbol = matches[0]
        symtab = sections[symbol[0]]
        _, info, _, shndx, value, size = struct.unpack_from('<IBBHQQ', data, symtab[4] + 24 * symbol[1])
        assert info == 0x12 and shndx == idx and value == 12 * i + 4 and size == 8
        assert struct.unpack_from('<III', data, sec[4] + value - 4) == (tag, 0xd503245f, 0x14000000)
        worker = name + b'_impl'
        assert any(s[2] == worker and s[3] & 15 == 2 and s[4] for s in symbols)
        expected_relocs.append((value + 4, 282, worker, 0))  # R_AARCH64_JUMP26
        ignored.add(('.text.zs_kcfi', value - 4))
    assert sorted(relocs) == sorted(expected_relocs), 'each tail branch must target its own C worker'
    return ignored


def regression(data):
    """Positive candidate plus byte-corruption negatives; the original candidate is immutable."""
    ignored = validate(data)
    assert len(ignored) == len(ENTRIES)
    sections, names_id = elf_sections(data)
    strings = data[sections[names_id][4]:sections[names_id][4] + sections[names_id][5]]
    sec = next(s for s in sections if strings[s[0]:].split(b'\0', 1)[0] == b'.text.zs_kcfi')
    for offset in (0, 4, 8):  # wrong type ID, missing BTI, wrong branch opcode
        bad = bytearray(data)
        bad[sec[4] + offset] ^= 1
        try:
            validate(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError('corrupt native entry accepted')
    rela = next(s for s in sections if s[1] == 4 and s[7] == sections.index(sec))
    bad = bytearray(data)
    bad[rela[4] + 16] = 4  # nonzero tail relocation addend
    try:
        validate(bad)
    except AssertionError:
        pass
    else:
        raise AssertionError('wrong branch target addend accepted')
    return 5
