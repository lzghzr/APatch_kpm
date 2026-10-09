#!/usr/bin/env python3
"""新版 kallsyms 表顺序的构造自检；不是目标镜像的独立解析结论。"""
import struct
import unittest

from kallsyms_extract import _extract_reordered, extract


def fixture(count=1000, big_name=True):
    tokens = ["z" + str(i) for i in range(256)]
    for i in range(10):
        tokens[48 + i] = str(i)
    tokens[84] = "T"
    for i, name in enumerate(("_text", "_stext", "printk", "memcpy", "setup_arch", "init_task")):
        tokens[200 + i] = name
    tokens[210] = "foo"
    data = bytearray(struct.pack("<I", count) + b"\0" * 4)
    markers, expected = [], []
    for i in range(count):
        if i % 256 == 0:
            markers.append(len(data) - 8)
        payload = bytes([84, 200 + i]) if i < 6 else bytes([84, 210] + [48 + int(c) for c in str(i)])
        if i == 6 and big_name:
            payload = bytes([84] + [210] * 128)  # 两字节 ULEB128 长度。
        length = len(payload)
        data.extend(bytes([length]) if length < 128 else bytes([(length & 127) | 128, length >> 7]))
        data.extend(payload)
        full = "".join(tokens[c] for c in payload)
        expected.append((i * 4, full[0], full[1:]))
    data.extend(b"\0" * (-len(data) % 8))
    marker_start = len(data)
    data.extend(struct.pack(f"<{len(markers)}I", *markers))
    data.extend(b"\0" * (-len(data) % 8))
    token_start = len(data)
    indices = []
    for token in tokens:
        indices.append(len(data) - token_start)
        data.extend(token.encode() + b"\0")
    data.extend(b"\0" * (-len(data) % 8))
    index_start = len(data)
    data.extend(struct.pack("<256H", *indices))
    array_start = len(data)
    data.extend(struct.pack(f"<{count}I", *[i * 4 for i in range(count)]))
    data.extend(b"\0" * (-len(data) % 8))
    base_start = len(data)
    data.extend(struct.pack("<Q", 0xffffffc080000000))
    return data, expected, dict(markers=marker_start, index=index_start, array=array_start, base=base_start)


class ReorderedTable(unittest.TestCase):
    def test_even_odd_and_big_name(self):
        for count in (1000, 1001):
            data, expected, _ = fixture(count)
            self.assertEqual(_extract_reordered(data), expected)

    def test_legacy_relative_order(self):
        data, expected, locations = fixture(big_name=False)
        count = len(expected)
        old = (data[locations["array"]:locations["array"] + count * 4]
               + struct.pack("<Q", 0xffffffc080000000)
               + data[:locations["array"]])
        symbols, mode = extract(old)
        self.assertEqual(mode, "relative")
        self.assertEqual(symbols, expected)

    def test_reject_corrupt_fields(self):
        data, _, locations = fixture()
        for position in (0, locations["markers"], locations["index"], locations["array"] + 8,
                         locations["base"] + 7):
            broken = bytearray(data)
            broken[position] ^= 0x40
            self.assertIsNone(_extract_reordered(broken), position)

    def test_reject_truncation(self):
        data, _, locations = fixture()
        for end in (8, locations["markers"], locations["index"] + 511, locations["base"] + 7):
            self.assertIsNone(_extract_reordered(data[:end]), end)

    def test_reject_incorrect_big_name_length(self):
        data, _, _ = fixture()
        length_start = 8 + 6 * 3
        data[length_start + 1] |= 128
        self.assertIsNone(_extract_reordered(data))


if __name__ == "__main__":
    unittest.main()
