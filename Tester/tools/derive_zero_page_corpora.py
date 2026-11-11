#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Derive Z0 and Z1 corpora from real 256 MiB memory corpus (SHA a1fcc1cf...).

Z0 = first 55,894 pages (natural zero-page constitution preserved).
Z1 = all 55,894 non-zero pages concatenated in original order (0 zero pages).
Both corpora are strictly equal in size: 55,894 * 4096 = 228,941,824 bytes.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

PAGE_SIZE = 4096
TARGET_PAGES = 55894
TARGET_BYTES = TARGET_PAGES * PAGE_SIZE  # 228,941,824 B
EXPECTED_SRC_SHA = "a1fcc1cfaff80b2ab4a7b5158fbeee0e42115bf54f6e78d6d949df6159b26a9d"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def count_zero_pages(pages: list[bytes]) -> tuple[int, int]:
    zero_page = b"\x00" * PAGE_SIZE
    zero_cnt = sum(1 for p in pages if p == zero_page)
    nonzero_cnt = len(pages) - zero_cnt
    return zero_cnt, nonzero_cnt


def main():
    parser = argparse.ArgumentParser(description="Derive Z0 and Z1 zero-page corpora")
    parser.add_argument(
        "--src",
        type=Path,
        default=Path("local/keep/evidence/tester-raw/corpus_real_256m.bin"),
        help="Path to source real corpus (256 MiB)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("local/keep/evidence/tester-raw"),
        help="Output directory for derived corpora",
    )
    args = parser.parse_args()

    if not args.src.exists():
        print(f"[-] Source corpus not found: {args.src}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading source corpus from {args.src}...")
    src_data = args.src.read_bytes()
    src_len = len(src_data)
    src_pages = src_len // PAGE_SIZE
    src_sha = sha256_bytes(src_data)

    print(f"[*] Source size: {src_len} bytes ({src_pages} pages)")
    print(f"[*] Source SHA-256: {src_sha}")

    if src_sha != EXPECTED_SRC_SHA:
        print(f"[-] WARNING: Source SHA-256 does not match expected {EXPECTED_SRC_SHA}!", file=sys.stderr)
    else:
        print(f"[+] Source SHA-256 verified successfully.")

    zero_page = b"\x00" * PAGE_SIZE
    pages = [src_data[i * PAGE_SIZE : (i + 1) * PAGE_SIZE] for i in range(src_pages)]
    src_zero_cnt, src_nonzero_cnt = count_zero_pages(pages)

    print(f"[*] Source zero pages: {src_zero_cnt} / {src_pages} ({src_zero_cnt / src_pages * 100:.2f}%)")
    print(f"[*] Source non-zero pages: {src_nonzero_cnt}")

    if src_nonzero_cnt != TARGET_PAGES:
        print(
            f"[-] Expected exactly {TARGET_PAGES} non-zero pages, got {src_nonzero_cnt}",
            file=sys.stderr,
        )
        sys.exit(1)

    # 1. Derive Z0: first TARGET_PAGES pages
    print(f"\n[*] Deriving Z0 (first {TARGET_PAGES} pages)...")
    z0_pages = pages[:TARGET_PAGES]
    z0_data = b"".join(z0_pages)
    z0_zero_cnt, z0_nonzero_cnt = count_zero_pages(z0_pages)
    z0_sha = sha256_bytes(z0_data)

    assert len(z0_data) == TARGET_BYTES, f"Z0 size mismatch: {len(z0_data)} != {TARGET_BYTES}"
    print(f"[+] Z0 size: {len(z0_data)} bytes ({len(z0_pages)} pages)")
    print(f"[+] Z0 zero pages: {z0_zero_cnt} ({z0_zero_cnt / len(z0_pages) * 100:.2f}%)")
    print(f"[+] Z0 non-zero pages: {z0_nonzero_cnt} ({z0_nonzero_cnt / len(z0_pages) * 100:.2f}%)")
    print(f"[+] Z0 SHA-256: {z0_sha}")

    # 2. Derive Z1: all non-zero pages in original order
    print(f"\n[*] Deriving Z1 (all {TARGET_PAGES} non-zero pages in order)...")
    z1_pages = [p for p in pages if p != zero_page]
    z1_data = b"".join(z1_pages)
    z1_zero_cnt, z1_nonzero_cnt = count_zero_pages(z1_pages)
    z1_sha = sha256_bytes(z1_data)

    assert len(z1_data) == TARGET_BYTES, f"Z1 size mismatch: {len(z1_data)} != {TARGET_BYTES}"
    assert z1_zero_cnt == 0, f"Z1 contains {z1_zero_cnt} zero pages (must be strictly 0)"
    print(f"[+] Z1 size: {len(z1_data)} bytes ({len(z1_pages)} pages)")
    print(f"[+] Z1 zero pages: {z1_zero_cnt} (0.00%) [VERIFIED STRICT ZERO]")
    print(f"[+] Z1 non-zero pages: {z1_nonzero_cnt} (100.00%)")
    print(f"[+] Z1 SHA-256: {z1_sha}")

    # Write output files
    args.out_dir.mkdir(parents=True, exist_ok=True)
    z0_path = args.out_dir / "corpus_z0_228m.bin"
    z1_path = args.out_dir / "corpus_z1_228m.bin"
    manifest_path = args.out_dir / "zero_page_sensitivity_manifest.json"

    print(f"\n[*] Writing {z0_path}...")
    z0_path.write_bytes(z0_data)

    print(f"[*] Writing {z1_path}...")
    z1_path.write_bytes(z1_data)

    manifest = {
        "source": {
            "path": str(args.src),
            "size_bytes": src_len,
            "total_pages": src_pages,
            "sha256": src_sha,
            "zero_pages": src_zero_cnt,
            "nonzero_pages": src_nonzero_cnt,
            "zero_page_pct": round(src_zero_cnt / src_pages * 100, 4),
        },
        "target_pages": TARGET_PAGES,
        "target_bytes": TARGET_BYTES,
        "corpora": {
            "Z0": {
                "description": "First 55,894 pages preserving natural zero-page constitution",
                "filename": z0_path.name,
                "size_bytes": len(z0_data),
                "total_pages": len(z0_pages),
                "zero_pages": z0_zero_cnt,
                "nonzero_pages": z0_nonzero_cnt,
                "zero_page_pct": round(z0_zero_cnt / len(z0_pages) * 100, 4),
                "sha256": z0_sha,
            },
            "Z1": {
                "description": "All 55,894 non-zero pages in original order with 0 zero pages",
                "filename": z1_path.name,
                "size_bytes": len(z1_data),
                "total_pages": len(z1_pages),
                "zero_pages": z1_zero_cnt,
                "nonzero_pages": z1_nonzero_cnt,
                "zero_page_pct": 0.0,
                "sha256": z1_sha,
            },
        },
    }

    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[+] Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
