# 自检参考来源

`linux-6.6-zstd-compress-module.c` 来自主线 Linux v6.6：
[lib/zstd/zstd_compress_module.c](https://github.com/torvalds/linux/blob/v6.6/lib/zstd/zstd_compress_module.c)，
Git blob `04e1b5c01d9b645741699951d5c19b892ca6c277`，访问日期 2026-11-06。
文件内保留 GPL-2.0+ OR BSD-3-Clause 标记和版权声明，本仓库采用 GPL；全文见根目录 LICENSE。

`test_codecs.py` 从该参考文件提取 `zstd_cctx_init()` 及错误转发宏，只改函数名和类型别名，
与本模块相同的新版 ZSTD core 链接。它验证原生参数协议与模块批量参数 API 的等价性，
不比较 Linux 6.6 旧版 ZSTD core，也不构成独立审计或设备证据。

压缩级别与未知输入参数入口来自
[crypto/zstd.c](https://github.com/torvalds/linux/blob/v6.6/crypto/zstd.c)。
LZ4 库的 `-O3` 基准来自
[lib/lz4/Makefile](https://github.com/torvalds/linux/blob/v6.6/lib/lz4/Makefile)；
`acceleration=1` 的原生入口见
[lib/lz4/lz4_compress.c](https://github.com/torvalds/linux/blob/v6.6/lib/lz4/lz4_compress.c)。

本目录既有 JSON 继续作为其绑定镜像的布局参考，不因这次参数对齐变更。
