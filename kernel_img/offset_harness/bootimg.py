#!/usr/bin/env python3
"""内核镜像解包：从 Android boot image / 压缩镜像里取出裸 arm64 Image。

支持（按识别顺序）:
  * Android boot image v0~v2：`ANDROID!` 头，kernel 在 page_size 偏移处；
  * Android boot image v3/v4：4096 字节头，page_size 固定 4096；
  * `UNCOMPRESSED_IMG` 包装：16 字节 magic + u32 未压缩大小 + 裸 Image；
  * 裸 arm64 Image（`ARM\\x64` 魔数在 0x38）与 Image.gz / .xz / .zst / .lz4；
  * 兜底：在页对齐偏移上扫描上述签名（厂商头字段不规范时使用）。

只提取裸 kernel，不处理 ramdisk / dtb / vendor_boot / recovery。
"""

import gzip
import hashlib
import lzma
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ANDROID_MAGIC = b"ANDROID!"
UNCOMPRESSED_MAGIC = b"UNCOMPRESSED_IMG"
ARM64_MAGIC_OFF = 0x38
ARM64_MAGIC = b"ARM\x64"
PAGE_CANDIDATES = (0x1000, 0x800, 0x2000, 0x10000, 0x400, 0x8000, 0x200, 0x4000)
MAX_SCAN = 8 << 20
VERSION_RE = re.compile(rb"Linux version (\d+\.\d+\.\d+[^\s\x00]*) \(([^\x00)]{0,96})\)")


@dataclass
class UnpackResult:
    data: bytes
    format: str
    detail: str
    source_sha256: str = ""
    kernel_sha256: str = ""
    extracted: bool = False      # True = 需要另存裸 kernel 到 local/；False = 源文件本身就是裸 Image
    release: str = ""            # 内嵌内核版本（Linux version 的具体值）
    major: str = ""              # 4.4 / 5.15 之类
    warnings: list = field(default_factory=list)

    @property
    def size(self):
        return len(self.data)


def _u32(data, off):
    if off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def is_raw_image(data):
    return data[ARM64_MAGIC_OFF:ARM64_MAGIC_OFF + 4] == ARM64_MAGIC


def _compression_of(blob):
    if blob[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if blob[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if blob[:4] == b"\x02\x21\x4c\x18":
        return "lz4"
    return None


def decompress(blob, kind=None):
    """按魔数解压（只解第一个流，容忍尾部附加数据）。"""
    kind = kind or _compression_of(blob)
    if kind is None:
        return None, "not compressed"
    try:
        if kind == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob), "gzip"
        if kind == "xz":
            return lzma.decompress(blob), "xz"
        if kind == "zstd":
            try:
                import zstandard  # noqa: F401
            except ImportError:
                return None, "zstd 需要 pip install zstandard"
            return zstandard.ZstdDecompressor().decompressobj().decompress(blob), "zstd"
        if kind == "lz4":
            try:
                import lz4.frame
            except ImportError:
                return None, "lz4 需要 pip install lz4"
            return lz4.frame.decompress(blob), "lz4"
    except Exception as exc:  # 解压失败不致命，交由上层报错
        return None, f"{kind} 解压失败: {exc}"
    return None, f"unsupported: {kind}"


def _image_header_size(blob):
    """arm64 Image 头里的 image_size（+0x10，u64）；不是 Image 或字段为空则返回 0。"""
    if not is_raw_image(blob) or len(blob) < 0x18:
        return 0
    size = struct.unpack_from("<Q", blob, 0x10)[0]
    return size if 1 << 20 <= size <= (1 << 30) else 0


def _inner(blob, notes):
    """处理 kernel 段自身的包装（压缩 / UNCOMPRESSED_IMG）。"""
    if blob[:len(UNCOMPRESSED_MAGIC)] == UNCOMPRESSED_MAGIC:
        declared = _u32(blob, len(UNCOMPRESSED_MAGIC)) or 0
        body = blob[len(UNCOMPRESSED_MAGIC) + 4:]
        want = _image_header_size(body)
        take = max(declared, want) if want else declared
        if take and take <= len(body):
            body = body[:take]
            if want > declared:
                notes.append(f"UNCOMPRESSED_IMG 声明 0x{declared:x}，arm64 头声明 image_size=0x{want:x}，按较大者截取")
        elif declared:
            notes.append(f"UNCOMPRESSED_IMG 声明大小 0x{declared:x} 超出可用数据 0x{len(body):x}，按实际截取")
        return body, f"UNCOMPRESSED_IMG(0x{take:x})"
    kind = _compression_of(blob)
    if kind:
        out, how = decompress(blob, kind)
        if out is None:
            notes.append(how)
            return blob, f"未解压({how})"
        return out, f"{how} 解压"
    return blob, ""


def _looks_like_kernel_start(blob):
    if not blob:
        return False
    if _compression_of(blob) or blob[:len(UNCOMPRESSED_MAGIC)] == UNCOMPRESSED_MAGIC:
        return True
    if is_raw_image(blob):
        return True
    # 裸 Image 的第一条指令是 b/br 分支
    word = _u32(blob, 0) or 0
    return (word & 0xFC000000) == 0x14000000


def _find_kernel_offset(data, kernel_size):
    """在页对齐偏移上找 kernel 段起点。"""
    tried = []
    for off in PAGE_CANDIDATES:
        if off + 4 > len(data):
            continue
        tried.append(off)
        if _looks_like_kernel_start(data[off:off + 0x40]):
            return off, tried
    step = 0x200
    for off in range(step, min(len(data), MAX_SCAN), step):
        if off in tried:
            continue
        if _looks_like_kernel_start(data[off:off + 0x40]):
            return off, tried + [off]
    return None, tried


def parse_boot_header(data):
    """解析 ANDROID! 头；返回 dict 或 None。"""
    if data[:len(ANDROID_MAGIC)] != ANDROID_MAGIC:
        return None
    kernel_size = _u32(data, 8)
    ramdisk_size = _u32(data, 16)
    page_size = _u32(data, 36)
    header_version = _u32(data, 40)
    os_version = _u32(data, 44)
    if page_size is None or page_size < 512 or page_size > (1 << 20) or (page_size & (page_size - 1)):
        page_size = None
    if header_version is not None and header_version > 4:
        header_version = None
    if page_size is None:
        pass  # 头不规范：交由 _find_kernel_offset 扫描定位
    return {
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "page_size": page_size,
        "header_version": header_version,
        "os_version": os_version,
    }


def unpack_bytes(data, name="<bytes>"):
    """把任意输入（boot image / 压缩 Image / 裸 Image）解成裸 kernel 字节。"""
    notes = []
    source_sha = hashlib.sha256(data).hexdigest()
    header = parse_boot_header(data)
    if header is None:
        body, how = _inner(data, notes)
        extracted = bool(how) or not is_raw_image(body)
        result = UnpackResult(body, "raw-or-compressed", how or "按裸 kernel 处理", source_sha,
                              extracted=extracted, warnings=notes)
        if not is_raw_image(body):
            notes.append("解出的数据没有 ARM\\x64 魔数（可能不是 arm64 Image）")
        result.kernel_sha256 = hashlib.sha256(body).hexdigest()
        result.release, _builder = detect_version(body)
        result.major = major_of(result.release) or ""
        return result

    version = header["header_version"]
    page = header["page_size"]
    fmt = f"android-boot v{version if version is not None else '?'}"
    if page is None:
        notes.append("头的 page_size 非法（可能是厂商自定义头），改用页对齐扫描定位 kernel")
    off = page if page else None
    if off is None or not _looks_like_kernel_start(data[off:off + 0x40]):
        found, tried = _find_kernel_offset(data, header["kernel_size"] or 0)
        if found is None:
            raise ValueError(f"{name}: 找不到 kernel 段起点（试过 {[hex(x) for x in tried[:8]]}…）")
        if off is not None and found != off:
            notes.append(f"头的 page_size={page} 指向 0x{off:x}，但 kernel 实际在 0x{found:x}，按实际偏移提取")
        off = found
    size = header["kernel_size"] or 0
    blob = data[off:off + size] if size else data[off:]
    want = _image_header_size(blob)
    if want and want > len(blob) and off + want <= len(data):
        notes.append(f"arm64 头声明 image_size=0x{want:x} > boot 头 kernel_size=0x{size:x}，按 image_size 扩展")
        blob = data[off:off + want]
    body, how = _inner(blob, notes)
    detail = f"{fmt} kernel@0x{off:x} size=0x{size:x}" + (f" {how}" if how else "")
    if not is_raw_image(body):
        notes.append("解出的数据没有 ARM\\x64 魔数（可能不是 arm64 Image）")
    release, _builder = detect_version(body)
    return UnpackResult(body, fmt, detail, source_sha, hashlib.sha256(body).hexdigest(),
                        extracted=True, release=release or "", major=major_of(release) or "", warnings=notes)


def unpack_file(path):
    data = Path(path).read_bytes()
    return unpack_bytes(data, name=str(path))


def detect_version(data):
    """返回 (release, 括号里的构建者)，找不到返回 (None, None)。

    注意：内核里 `Linux version %s (%s)` 这种 format string 也会命中，
    因此必须要求版本号是具体数字。
    """
    pos = 0
    while True:
        i = data.find(b"Linux version ", pos)
        if i < 0:
            return None, None
        m = VERSION_RE.match(data, i)
        if m:
            return m.group(1).decode("utf-8", "replace"), m.group(2).decode("utf-8", "replace")
        pos = i + 1


def major_of(release):
    """4.4.192-perf+ -> 4.4；5.15.189-android13-... -> 5.15。"""
    if not release:
        return None
    parts = release.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return f"{parts[0]}.{parts[1]}"


def safe_label(text, fallback="unknown"):
    text = re.sub(r"[^A-Za-z0-9._+-]+", "_", (text or "").strip())
    text = text.strip("._-")
    return text or fallback
