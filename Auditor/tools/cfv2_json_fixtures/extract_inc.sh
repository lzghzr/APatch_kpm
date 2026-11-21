#!/bin/sh
# 从冻结源码重新生成 cg_json_extract.inc，并核对与被测 .inc 的哈希。
#
# 用法: sh extract_inc.sh <冻结提交的 cgroupv2_freeze.c> [输出路径]
#
# 提取范围：源码行 404-544（CG_JSON_MAX/CG_JSON_KEY/CG_JSON_PATH* 宏 +
# cg_json_dentry/applied/bound/too_big 状态 + cg_find/cg_object_end/cg_field/
# cg_replace/cg_json_patch）。这些函数只依赖 strlen/memcmp/memcpy/memmove，
# 在宿主 libc 下语义与内核侧一致，因此可原样编译成宿主夹具。
set -e
SRC=${1:?usage: sh extract_inc.sh <frozen cgroupv2_freeze.c> [out.inc]}
OUT=${2:-cg_json_extract.inc}
sed -n '404,544p' "$SRC" > "$OUT"
echo "source : $SRC"
echo "sha256(source) : $(sha256sum "$SRC" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$SRC" | cut -d' ' -f1)"
echo "sha256($OUT) : $(sha256sum "$OUT" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$OUT" | cut -d' ' -f1)"
echo "expect        : d84431246449917f2e0d35d5304fb1542d1148f5e33c0aa53a5cbc52d67e78b1"
