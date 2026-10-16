#!/usr/bin/env python3
"""boot kernel 段边界回归：内存声明不能扩大文件段。"""

import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspect_target


class BootSegmentTest(unittest.TestCase):
    def image(self, version):
        kernel = bytearray(256)
        struct.pack_into('<Q', kernel, 16, 65536)
        kernel[56:60] = b'ARM\x64'
        header = bytearray(4096)
        header[:8] = b'ANDROID!'
        struct.pack_into('<I', header, 8, len(kernel))
        struct.pack_into('<I', header, 36, 4096 if version < 3 else 0)
        struct.pack_into('<I', header, 40, version)
        return bytes(header + kernel + bytearray(b'RAMDISK' * 10000)), bytes(kernel)

    def test_kernel_stops_before_ramdisk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'boot.img'
            for version in range(5):
                with self.subTest(version=version):
                    boot, kernel = self.image(version)
                    path.write_bytes(boot)
                    result = inspect_target.unpack_target(path)
                    self.assertEqual(result.data, kernel)
                    self.assertEqual(result.source_sha256, hashlib.sha256(boot).hexdigest())

    def test_truncated_kernel_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'boot.img'
            boot, kernel = self.image(2)
            path.write_bytes(boot[:4096 + len(kernel) - 1])
            with self.assertRaisesRegex(ValueError, 'kernel 段越过文件边界'):
                inspect_target.unpack_target(path)


if __name__ == '__main__':
    unittest.main()
