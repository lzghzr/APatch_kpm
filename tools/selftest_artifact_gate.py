#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""用独立构造的 ELF 夹具验证产物门禁拒绝损坏字节及错配布局。"""

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from artifact_gate import validate


def fixture(unified=False, debug=False):
    sections = [("", 0, b""), (".shstrtab", 3, b""),
                (".kpm.info", 1, b"name=re_kernel_x\0version=1.6\0license=GPL v3\0author=Fixture\0description=Artifact fixture\0"),
                (".kpm.init", 1, bytes(8)), (".kpm.exit", 1, bytes(8)),
                (".data.re_offsets", 1, struct.pack("<hhh", 16, -1, 6) if unified else struct.pack("<hh", 16, -1)),
                (".rodata.re_abi", 1, struct.pack("<I", 5))]
    if unified:
        sections.pop()
    if debug:
        name, kind, raw = sections[2]
        sections[2] = (name, kind, raw.replace(b"version=1.6\0", b"version=1.6_d\0"))
    strings = b"\0"
    indices = []
    for name, _, _ in sections:
        indices.append(len(strings) if name else 0)
        if name:
            strings += name.encode() + b"\0"
    sections[1] = (".shstrtab", 3, strings)
    table_offset = 64
    content = bytearray(64 + len(sections) * 64)
    content[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                              1, 183, 1, 0, 0, table_offset, 0, 64, 0, 0, 64, len(sections), 1)
    offsets = {}
    for index, ((name, kind, raw), name_index) in enumerate(zip(sections, indices)):
        offset = len(content)
        offsets[name] = offset
        content += raw
        flags = 3 if name == ".data.re_offsets" else 0
        struct.pack_into("<IIQQQQIIQQ", content, table_offset + index * 64,
                         name_index, kind, flags, 0, offset, len(raw), 0, 0, 1, 0)
    data = bytes(content)
    layout = {"schema": 1, "kpm": "re_kernel_x_1.6_abi5.kpm", "sha256": hashlib.sha256(data).hexdigest(),
              "binder_abi": 5, "table_offset": offsets[".data.re_offsets"], "table_size": 4,
              "fields": ["first", "second"], "offsets": {"first": "0x10", "second": -1}}
    if unified:
        layout.update(schema=2, kpm="re_kernel_x_1.6.kpm", binder_abi=6, table_size=6,
                      fields=["first", "second", "binder_release_abi"],
                      offsets={"first": "0x10", "second": -1, "binder_release_abi": 6})
    if debug:
        layout["kpm"] = layout["kpm"].replace(".kpm", "_debug.kpm")
    return data, layout


class ArtifactGateTests(unittest.TestCase):
    unified = False

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data, self.layout = fixture(self.unified)
        self.kpm = self.root / self.layout["kpm"]
        self.sidecar = Path(str(self.kpm) + ".json")
        self.write()

    def write(self):
        self.kpm.write_bytes(self.data)
        self.sidecar.write_text(json.dumps(self.layout))

    def reject(self):
        with self.assertRaises((ValueError, KeyError, OSError, struct.error)):
            validate(self.root, ["re_kernel_x"])

    def test_valid_product_and_layout(self):
        result = validate(self.root, ["re_kernel_x"])
        self.assertEqual(result[0]["sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertEqual(result[0]["layout"]["sha256"], hashlib.sha256(self.sidecar.read_bytes()).hexdigest())

    def test_empty_output(self):
        self.kpm.unlink()
        self.reject()

    def test_missing_selected_module(self):
        with self.assertRaises(ValueError):
            validate(self.root, ["re_kernel_x", "another_module"])

    def test_wrong_architecture(self):
        data = bytearray(self.data)
        struct.pack_into("<H", data, 18, 62)
        self.kpm.write_bytes(data)
        self.reject()

    def test_truncated_product(self):
        self.kpm.write_bytes(self.data[:100])
        self.reject()

    def test_out_of_bounds_section(self):
        data = bytearray(self.data)
        struct.pack_into("<Q", data, 64 + 2 * 64 + 24, len(data) + 100)
        self.kpm.write_bytes(data)
        self.reject()

    def test_required_info_missing(self):
        self.kpm.write_bytes(self.data.replace(b"version=", b"unknown="))
        self.reject()

    def test_required_entry_missing(self):
        self.kpm.write_bytes(self.data.replace(b".kpm.init", b".kpm.none"))
        self.reject()

    def test_filename_identity_mismatch(self):
        self.kpm.rename(self.root / "other_1.6.kpm")
        self.reject()

    def test_filename_version_mismatch(self):
        self.kpm.rename(self.root / "re_kernel_x_1.7_abi5.kpm")
        self.reject()

    def test_filename_abi_mismatch(self):
        name = "re_kernel_x_1.6_abi3.kpm"
        self.kpm.rename(self.root / name)
        self.sidecar.unlink()
        changed = dict(self.layout, kpm=name)
        (self.root / (name + ".json")).write_text(json.dumps(changed))
        self.reject()

    def test_missing_layout(self):
        self.sidecar.unlink()
        self.reject()

    def test_tampered_product_hash(self):
        self.kpm.write_bytes(self.data + b"changed")
        self.reject()

    def test_mismatched_layout(self):
        for key, value in (("sha256", "0" * 64), ("binder_abi", 3), ("table_offset", 0),
                           ("table_size", 2), ("fields", ["first", "first"]),
                           ("schema", True), ("binder_abi", True), ("table_size", True),
                           ("offsets", {"first": "0x11", "second": -1})):
            with self.subTest(key=key):
                changed = dict(self.layout, **{key: value})
                self.sidecar.write_text(json.dumps(changed))
                self.reject()

    def test_orphan_layout(self):
        (self.root / "missing.kpm.json").write_text("{}")
        self.reject()


class UnifiedArtifactGateTests(ArtifactGateTests):
    unified = True

    def select_abi(self, abi):
        data = bytearray(self.data)
        struct.pack_into("<h", data, self.layout["table_offset"] + self.layout["table_size"] - 2, abi)
        self.data = bytes(data)
        self.layout.update(sha256=hashlib.sha256(self.data).hexdigest(), binder_abi=abi)
        self.layout["offsets"]["binder_release_abi"] = abi
        self.write()

    def test_all_release_abis(self):
        for abi in (3, 4, 5, 6):
            with self.subTest(abi=abi):
                self.select_abi(abi)
                validate(self.root, ["re_kernel_x"])

    def test_invalid_release_abis(self):
        for abi in (-1, 0, 2, 7, 32767):
            with self.subTest(abi=abi):
                self.select_abi(abi)
                self.reject()

    def test_release_value_mismatch(self):
        self.select_abi(3)
        self.layout["binder_abi"] = 6
        self.write()
        self.reject()

    def test_missing_release_field(self):
        self.layout["fields"][-1] = "third"
        self.layout["offsets"]["third"] = self.layout["offsets"].pop("binder_release_abi")
        self.write()
        self.reject()

    def test_fixed_schema_on_unified_product(self):
        self.layout["schema"] = 1
        self.write()
        self.reject()

    def test_unified_schema_on_fixed_product(self):
        self.kpm.unlink()
        self.sidecar.unlink()
        self.data, self.layout = fixture()
        self.layout.update(schema=2, kpm="re_kernel_x_1.6.kpm", binder_abi=6,
                           fields=["first", "binder_release_abi"], offsets={"first": "0x10", "binder_release_abi": 6})
        data = bytearray(self.data)
        struct.pack_into("<h", data, self.layout["table_offset"] + 2, 6)
        self.data = bytes(data)
        self.layout["sha256"] = hashlib.sha256(self.data).hexdigest()
        self.kpm = self.root / self.layout["kpm"]
        self.sidecar = Path(str(self.kpm) + ".json")
        self.write()
        self.reject()

    def test_debug_product(self):
        directory = self.root / "debug"
        directory.mkdir()
        data, layout = fixture(unified=True, debug=True)
        (directory / layout["kpm"]).write_bytes(data)
        (directory / (layout["kpm"] + ".json")).write_text(json.dumps(layout))
        validate(directory, ["re_kernel_x"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
