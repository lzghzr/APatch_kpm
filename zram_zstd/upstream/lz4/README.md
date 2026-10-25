# LZ4 block codec

原始文件来自官方 [LZ4 v1.10.0](https://github.com/lz4/lz4/releases/tag/v1.10.0)，
提交 `ebb370ca83af193212df4dcbadcc5d87bc0de2f0`。2026-10-25 查询官方 latest release，
该版本为最新稳定版；没有引入 HC、frame、CLI 或线程实现。

`lz4.c`、`lz4.h`、`LICENSE` 保留上游字节。库以 BSD-2-Clause 授权，见 LICENSE。
构建配置在 `zs_lz4_config.h`，使用 freestanding 纯 C block API；ARM64 编译仅用通用寄存器。
