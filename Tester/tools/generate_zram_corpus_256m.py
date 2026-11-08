#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate 256 MiB corpus for zram benchmark: 4 classes x 64 MiB each."""
import array
import hashlib
from pathlib import Path
import random
import struct
import sys
import time

REPO = Path(__file__).resolve().parents[2]
OUT_DIR = REPO / "local" / "tester-raw"
OUT_FILE = OUT_DIR / "corpus_256m.bin"

PAGES_PER_CLASS = 16384  # 16384 * 4096 = 67,108,864 bytes (64 MiB)
PAGE_SIZE = 4096
CLASS_BYTES = PAGES_PER_CLASS * PAGE_SIZE  # 64 MiB


def generate_corpus():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    module = REPO / "zram_zstd"
    rng = random.Random(0x16b10c)

    # 1. source_text
    t0 = time.time()
    text_paths = ["zram_zstd.c", "zs_offsets.c", "zs_display.c", "upstream/lz4/lz4.c"]
    text = b"\n".join((module / name).read_bytes() for name in text_paths)
    text_doubled = text + text
    st_buf = bytearray(CLASS_BYTES)
    for page in range(PAGES_PER_CLASS):
        start = (page * 977) % len(text)
        st_buf[page * PAGE_SIZE : (page + 1) * PAGE_SIZE] = text_doubled[start : start + PAGE_SIZE]
    sha_st = hashlib.sha256(st_buf).hexdigest()
    print(f"[+] source_text: {len(st_buf)} bytes, SHA-256: {sha_st} ({time.time() - t0:.2f}s)")

    # 2. integers
    t1 = time.time()
    int_buf = bytearray(CLASS_BYTES)
    for page in range(PAGES_PER_CLASS):
        p17 = page * 17
        arr = array.array(
            "I",
            [
                ((word // 8 + p17) if word % 8 < 3 else (0 if word % 8 < 6 else (word * 31) % 251)) & 0xFFFFFFFF
                for word in range(1024)
            ],
        )
        int_buf[page * PAGE_SIZE : (page + 1) * PAGE_SIZE] = arr.tobytes()
    sha_int = hashlib.sha256(int_buf).hexdigest()
    print(f"[+] integers:    {len(int_buf)} bytes, SHA-256: {sha_int} ({time.time() - t1:.2f}s)")

    # 3. mixed_binary
    t2 = time.time()
    mb_buf = bytearray(CLASS_BYTES)
    for page in range(PAGES_PER_CLASS):
        binary = bytearray(rng.randbytes(PAGE_SIZE))
        for at in range(0, PAGE_SIZE, 256):
            binary[at : at + 40] = bytes(40)
            binary[at + 40 : at + 44] = struct.pack("<I", page * 16 + at // 256)
        mb_buf[page * PAGE_SIZE : (page + 1) * PAGE_SIZE] = binary
    sha_mb = hashlib.sha256(mb_buf).hexdigest()
    print(f"[+] mixed_binary:{len(mb_buf)} bytes, SHA-256: {sha_mb} ({time.time() - t2:.2f}s)")

    # 4. random
    t3 = time.time()
    rnd_buf = bytearray(rng.randbytes(CLASS_BYTES))
    sha_rnd = hashlib.sha256(rnd_buf).hexdigest()
    print(f"[+] random:      {len(rnd_buf)} bytes, SHA-256: {sha_rnd} ({time.time() - t3:.2f}s)")

    # Combined 256 MiB corpus
    corpus = st_buf + int_buf + mb_buf + rnd_buf
    assert len(corpus) == 268435456, f"Expected 268435456 bytes, got {len(corpus)}"
    sha_total = hashlib.sha256(corpus).hexdigest()
    print(f"[+] Combined 256 MiB corpus: {len(corpus)} bytes, SHA-256: {sha_total}")

    OUT_FILE.write_bytes(corpus)
    print(f"[+] Written to {OUT_FILE}")

    return {
        "classes": {
            "source_text": {"bytes": len(st_buf), "sha256": sha_st},
            "integers": {"bytes": len(int_buf), "sha256": sha_int},
            "mixed_binary": {"bytes": len(mb_buf), "sha256": sha_mb},
            "random": {"bytes": len(rnd_buf), "sha256": sha_rnd},
        },
        "combined": {
            "bytes": len(corpus),
            "sha256": sha_total,
            "path": str(OUT_FILE),
        },
    }


if __name__ == "__main__":
    generate_corpus()
