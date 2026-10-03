"""Raw arm64 kernel Image loader with transparent decompression."""

import gzip
import io
import struct


class KernelImage:
    def __init__(self, data, path):
        self.data = data
        self.path = path

    @property
    def size(self):
        return len(self.data)

    def word32(self, file_off):
        if file_off < 0 or file_off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, file_off)[0]

    def words32(self, file_off, count):
        out = []
        for i in range(count):
            w = self.word32(file_off + 4 * i)
            if w is None:
                w = 0  # mirror C reading past end (adjacent memory)
            out.append(w)
        return out

    def read(self, file_off, n):
        if file_off < 0:
            return b""
        return self.data[file_off:file_off + n]

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            head = f.read(4)
            f.seek(0)
            if head == b"\x1f\x8b":
                data = gzip.decompress(f.read())
            else:
                data = f.read()
        return cls(data, path)
