#!/usr/bin/env python3
"""Android boot 头字段和 kernel 段边界；不把 arm64 内存范围当文件长度。"""
import struct
import unittest

import bootimg


def image(version):
    kernel = bytearray(1024)
    kernel[56:60] = b'ARMd'
    struct.pack_into('<Q', kernel, 16, 8192)
    header = bytearray(4096)
    header[:8] = b'ANDROID!'
    struct.pack_into('<I', header, 8, len(kernel))
    struct.pack_into('<I', header, 40, version)
    if version in (3, 4):
        struct.pack_into('<I', header, 12, 4096)
        struct.pack_into('<I', header, 16, 0x12345678)
        struct.pack_into('<I', header, 20, 1580 if version == 3 else 1584)
    else:
        struct.pack_into('<I', header, 16, 4096)
        struct.pack_into('<I', header, 36, 4096)
    return bytes(header + kernel + b'R' * 16384), bytes(kernel)


class Boundaries(unittest.TestCase):
    def test_versions_keep_declared_kernel(self):
        for version in (0, 1, 2, 3, 4):
            with self.subTest(version=version):
                raw, kernel = image(version)
                result = bootimg.unpack_bytes(raw)
                self.assertEqual(result.data, kernel)
                self.assertFalse(result.warnings)

    def test_v4_fields(self):
        raw, _ = image(4)
        header = bootimg.parse_boot_header(raw)
        self.assertEqual(header['page_size'], 4096)
        self.assertEqual(header['ramdisk_size'], 4096)
        self.assertEqual(header['os_version'], 0x12345678)

    def test_truncated_kernel_rejected(self):
        raw, _ = image(4)
        with self.assertRaises(ValueError):
            bootimg.unpack_bytes(raw[:4100])

    def test_invalid_header_rejected(self):
        raw, _ = image(4)
        raw = bytearray(raw)
        struct.pack_into('<I', raw, 20, 20000)
        with self.assertRaises(ValueError):
            bootimg.unpack_bytes(raw)


if __name__ == '__main__':
    unittest.main()
