# 上游源码

- `zstd/`：Git 子模块，固定提交；准备脚本核对 gitlink 与工作树。构建需要上游 freestanding 生成器及配套源码树。
- `lz4/`：保留 vendoring，仅取 block 编解码需要的 `lz4.c`、`lz4.h` 和许可证；加本地来源说明共四文件，约 172 KiB。
  不需要完整仓库中的 HC、frame、CLI、测试和构建系统，因此不增加子模块初始化与无关源码。ZSTD 需要完整生成工具树；NoMount 需要一起保留内核、CLI、WebUI 上游参考，两者采用完整子模块。

## LZ4 provenance

来源为官方 [LZ4 v1.10.0 固定提交](https://github.com/lz4/lz4/tree/ebb370ca83af193212df4dcbadcc5d87bc0de2f0)：
`ebb370ca83af193212df4dcbadcc5d87bc0de2f0`。

| 本地文件 | 上游文件 |
| --- | --- |
| `lz4/lz4.c` | `lib/lz4.c` |
| `lz4/lz4.h` | `lib/lz4.h` |
| `lz4/LICENSE` | `lib/LICENSE`（BSD-2-Clause） |

三份原始文件保持上游字节；目录内 README 是本仓库的来源记录。升级时整体替换上述固定提交的文件并复核编解码、许可证及产物指令检查。
库配置与 KPM 适配保留在模块根目录，不修改上游原文件。共享 KernelPatch SDK 仍在仓库根目录。
