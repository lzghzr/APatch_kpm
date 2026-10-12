# 独立审计报告：zram_zstd 0.1.0 全量产物、代码风格与安全评估

角色：Auditor（独立审计）。  
审计类型：重跑轮首次完整独立审计（覆盖初始候选 4 份与修复候选 4 份共 8 份在册实例）。  
依据：[审计请求](../../docs/records/2026-10-10-zram-zstd-audit-request.md)、[候选登记记录](../../docs/records/2026-10-10-zram-zstd-registration.md) 与 [模块元数据](../../metadata/modules/zram_zstd.json)。

---

## 1. 身份与审计对象

| 项 | 值 |
| --- | --- |
| 初始候选源码 commit | `e6ca482ecd40f4415d17acd349bd9875c6b64356` |
| 修复候选源码 commit | `a5e1615bdb715257b167483e3e3a6f019b4a15f0`（`[zram_zstd] 修复 AUD-008 控制入口与工作区释放`） |
| 声明版本 | `0.1.0`（Makefile `MYKPM_VERSION`） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9） |
| 编译工具链 | `ndk26.3.11579264`（Clang `aarch64-linux-android31-clang`） |
| 审计工具版本 | `Auditor/tools/*` 在当前工作树状态 |
| 语料与符号表 | 本地内核镜像 `kernel_img/B2N-416G_boot.img`（SHA-256 `ea919143cb1f057f3d35d726294166d5186f376e9751941b83940e75d48a288c`）、解压裸内核 `Image`（SHA-256 `7633fbac5ce30b726a1acdbf57f730aa847a9510984a25bc23f9ddcdb0956e1c`）及本地符号快照 `local/kernel_offset/` |

### 审计对象完整身份清单（8 个在册候选实例）

| 轮次 | 变体 | instance_id（Build ID + 实例号） | 产物文件名 | 产物 sha256 | 字节大小 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 初始 | `base` | `zram_zstd-0.1.0+gc330fe19c6d2.r4f8aafd2.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0.kpm` | `e77e43f1194020a625b1895fa9699e078b96c2593c844a21638b8c291e9614ac` | 228,552 B |
| 初始 | `baselines` | `zram_zstd-0.1.0_baselines+gc330fe19c6d2.r96a59ed2.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_baselines.kpm` | `64b5a23163a4f0283b409647fe1303b3b911c2d889b3db2f4dc9f63ee696df10` | 221,792 B |
| 初始 | `baselines_debug` | `zram_zstd-0.1.0_baselines_debug+gc330fe19c6d2.r4fa063b1.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_baselines_debug.kpm` | `4ce9a938c695eb92ba9753c75374d3c93fe8ac52f90f6df824eedcfbb0a888e7` | 221,792 B |
| 初始 | `debug` | `zram_zstd-0.1.0_debug+gc330fe19c6d2.r627503cf.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_debug.kpm` | `7a7d18b9f7c9bfff89f0b2e7a440b4f4a79afbb273efb6fe3e3c5d6e83a7a279` | 228,552 B |
| 修复 | `base` | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0.kpm` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` | 229,312 B |
| 修复 | `baselines` | `zram_zstd-0.1.0_baselines+gd464ad07ccb0.rf876d2a6.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_baselines.kpm` | `d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f` | 222,536 B |
| 修复 | `baselines_debug` | `zram_zstd-0.1.0_baselines_debug+gd464ad07ccb0.r8985a06f.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_baselines_debug.kpm` | `455426a2352a95586fdc05ff360d689377fd1061c9547d79a38d8b25435ae98d` | 222,536 B |
| 修复 | `debug` | `zram_zstd-0.1.0_debug+gd464ad07ccb0.rf04090a6.kpb51197a.ndk26.3.11579264#1` | `zram_zstd_0.1.0_debug.kpm` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` | 229,312 B |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 复现命令 / 证据 | 来源归属 | 是否独立复现 |
| :--- | :--- | :--- | :--- |
| **8 份产物独立重编译哈希 100% 吻合** | 在 `local/auditor-scratch/` 沙箱对 `e6ca482` 与 `a5e1615` 源码分别自建命令调用 NDK Clang 执行构建，复算 SHA-256 | Auditor 独立重编译 | 是 |
| **初始 4 份候选缺失 `.kpm.ctl0`** | `python3 Auditor/tools/artifact_audit.py --module zram_zstd` 自解析 ELF 节区 | Auditor 自有工具 | 是 |
| **修复 4 份候选导出合法 `.kpm.ctl0`** | `python3 Auditor/tools/artifact_audit.py --module zram_zstd --build-id <id>`，自解析 8 字节节区与 `R_AARCH64_ABS64` 重定位 | Auditor 自有工具 | 是 |
| **代码风格符合规范** | `clang-format --dry-run --Werror zram_zstd/zram_zstd.c zram_zstd/zs_offsets.c zram_zstd/zs_runtime.c`（退出码 0） | Auditor 独立运行 | 是 |
| **Oracle 基线断言完整保留且单测通过** | `local/auditor-scratch/selfcheck_audit <image> <libzstd>`，全部 32 项断言通过（含 21 项原有用例），ASan/UBSan 零告警 | Auditor 独立重构运行 | 是 |
| **卸载路径存在 Use-After-Free 风险** | 走查 `KernelPatch/kernel/patch/module/module.c:540-546` 及 `zram_zstd.c:177`，确认 KP 忽略 exit 返回值并无条件释放内存 | Auditor 源码审查 | 是 |
| **元数据与候选登记状态校验** | `python3 tools/check_repository.py`（提及该脚本仅用于定位，未作依据） | 维护者门禁 | 是 |

---

## 3. 结论摘要

- **独立复现通过的检查**：
  - 8 份在册产物独立重编译，8 份 SHA-256 与登记记录 100% 逐字节吻合；
  - 修复候选 4 份产物全部包含必需节区 `.kpm.info`、`.kpm.init`、`.kpm.ctl0`、`.kpm.exit`，入口指针重定位（`R_AARCH64_ABS64`）合法；
  - 静态基线配套布局文件（2 份初始 + 2 份修复）哈希与内嵌 `kpm_sha256` 逐份对应，五项字段初始模板值均为 `-1`；
  - 项目代码风格检查（Clang-Format 22.1.8）0 告警，命名结构清晰；
  - Oracle 测试驱动（`selfcheck.py`）21 项既有断言未被弱化或删除，11 项新增断言通过，ASan/UBSan 零异常。
- **问题单流转**：
  - `AUD-008`（中低，Developer）：在初始候选 4 份实例中缺失 `.kpm.ctl0` 且释放未清空指针；已在提交 `a5e1615` 修复并由 Auditor 独立复核确认，判定为 **CLOSED（独立复核关闭）**；
  - `AUD-009`（高，Developer）：模块注册算法后无法阻止 KernelPatch 卸载释放内存，卸载将引发 Use-After-Free 内核 Panic；按仓库影响定级规则定为 **高**，状态为 **OPEN**，处置建议由维护者作出书面风险接受（`RA-001`）。
- **阻塞性结论**：存在未闭环高风险问题单 `AUD-009`（等待维护者出具书面风险接受）；无真机验证证据前不得外推为设备可用。

---

## 4. 独立复现（Auditor 自己重算）

### 4.1 独立重编译哈希校验

Auditor 在隔离沙箱 `local/auditor-scratch/` 内，分别基于两轮冻结源码提交执行全量构建，不污染共享工作树，不调用 `tools/build_candidate.py`（提及仅用于定位，未作依据）：

```bash
# 初始候选重编译（commit e6ca482ecd40f4415d17acd349bd9875c6b64356）
make -C local/auditor-scratch/initial/zram_zstd all debug \
  ANDROID_NDK_LATEST_HOME=<ndk_path> KP_DIR=<repo>/KernelPatch

# 修复候选重编译（commit a5e1615bdb715257b167483e3e3a6f019b4a15f0）
make -C local/auditor-scratch/fixed/zram_zstd all debug \
  ANDROID_NDK_LATEST_HOME=<ndk_path> KP_DIR=<repo>/KernelPatch
```

**重编译产物 SHA-256 比对矩阵**：

| 变体 / 轮次 | 归档候选 SHA-256 | Auditor 独立重编译 SHA-256 | 比对结果 |
| :--- | :--- | :--- | :--- |
| 初始 `base` | `e77e43f1194020a625b1895fa9699e078b96c2593c844a21638b8c291e9614ac` | `e77e43f1194020a625b1895fa9699e078b96c2593c844a21638b8c291e9614ac` | **PASS (100% 吻合)** |
| 初始 `baselines` | `64b5a23163a4f0283b409647fe1303b3b911c2d889b3db2f4dc9f63ee696df10` | `64b5a23163a4f0283b409647fe1303b3b911c2d889b3db2f4dc9f63ee696df10` | **PASS (100% 吻合)** |
| 初始 `baselines_debug` | `4ce9a938c695eb92ba9753c75374d3c93fe8ac52f90f6df824eedcfbb0a888e7` | `4ce9a938c695eb92ba9753c75374d3c93fe8ac52f90f6df824eedcfbb0a888e7` | **PASS (100% 吻合)** |
| 初始 `debug` | `7a7d18b9f7c9bfff89f0b2e7a440b4f4a79afbb273efb6fe3e3c5d6e83a7a279` | `7a7d18b9f7c9bfff89f0b2e7a440b4f4a79afbb273efb6fe3e3c5d6e83a7a279` | **PASS (100% 吻合)** |
| 修复 `base` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` | **PASS (100% 吻合)** |
| 修复 `baselines` | `d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f` | `d0c28ea484c38ecd7b13e39e13f2566a5719e9feceb99dd7fb425f733241ca7f` | **PASS (100% 吻合)** |
| 修复 `baselines_debug` | `455426a2352a95586fdc05ff360d689377fd1061c9547d79a38d8b25435ae98d` | `455426a2352a95586fdc05ff360d689377fd1061c9547d79a38d8b25435ae98d` | **PASS (100% 吻合)** |
| 修复 `debug` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` | **PASS (100% 吻合)** |

### 4.2 产物结构与 ELF 节区自解析

运行自有 ELF 解析工具 `Auditor/tools/artifact_audit.py`：
- **初始 4 份候选**：报告 `[error] missing_section: 缺少必需节 .kpm.ctl0`，阻断通过；
- **修复 4 份候选**：
  - 均含 8 字节 `.kpm.info`、`.kpm.init`、`.kpm.ctl0`、`.kpm.exit` 必需节区；
  - 重定位类型为 `R_AARCH64_ABS64`（257），分别精准指向 `zram_zstd_init`、`zram_zstd_ctl0` 与 `zram_zstd_exit`；
  - 导入符号表：动态版包含 9 项（`compat_copy_to_user`, `kallsyms_lookup_name_by_suffix`, `kf_memcmp`, `kf_memcpy`, `kf_memmove`, `kf_memset`, `kf_strcmp`, `kf_strncmp`, `printk`），基线版包含 8 项（不含 `kf_strncmp`），全部在 KernelPatch SDK 与内核导出白名单之内；
  - 未使用 x18 保留寄存器，未引入 SIMD/FP 指令。

---

## 5. 代码风格检查（独立运行）

| 项目 | 记录 |
| :--- | :--- |
| **源码提交** | `a5e1615bdb715257b167483e3e3a6f019b4a15f0` |
| **规范与配置** | `.clang-format`（SHA-256 `68b59d9972332152ee4b889ea8f95c0293623fa52a97f26f2824cf48f8a1928a`） |
| **工具版本** | `clang-format version 22.1.8` |
| **文件范围** | `zram_zstd/zram_zstd.c`, `zram_zstd/zs_offsets.c`, `zram_zstd/zs_runtime.c` |
| **运行命令与退出码** | `clang-format --dry-run --Werror zram_zstd/zram_zstd.c zram_zstd/zs_offsets.c zram_zstd/zs_runtime.c`（退出码：`0`） |
| **人工复核** | 命名遵守 Linux 内核小写下划线风格；宏与常量大写（`CRYPTO_ALG_TYPE_COMPRESS`）；错误处理严格采用 fail-fast 负整数错误码（`-EINVAL`, `-ENOMEM`, `-ENOENT`, `-EFAULT`）；注释结构清晰 |
| **第三方源码单列说明** | `zram_zstd/vendor/` 包含来自 Android common 4.19 的 18 项内核原生 zstd 与 xxhash 源码文件（见 `vendor/SOURCES.json`）。为保持与上游内核追溯哈希一致，对该目录豁免重排版 |
| **结果与结论** | **PASS**（无风格违规，无规范例外） |

---

## 6. Oracle 合规与测试驱动审计

依据 [.agents/skills/respect-the-oracle/SKILL.md](../../.agents/skills/respect-the-oracle/SKILL.md)，基准测试套件 `zram_zstd/tools/selfcheck.py` 视为只读 Oracle：

1. **断言守恒审计**：
   - 比较初始提交 `e6ca482` 与修复提交 `a5e1615` 中的测试驱动：
   - 初始版本包含 21 条核心断言（含结构体偏移基准、256 个真实内核页面与独立 `libzstd` 双向互解）；
   - 修复版本包含 32 条断言，原 21 条断言**全部逐字保留、未被弱化、未被删除、相对执行次序未变**；
   - 新增 11 条断言均用于针对 `AUD-008` 修复项增加单测覆盖（验证 `ping` -> `pong` 回复、`NULL` 参数、未知命令、短缓冲、负长度边界、用户态拷贝故障 `-EFAULT` 模拟、以及部分分配失败时的防御性重复释放）。
2. **ASan / UBSan 独立验证**：
   - Auditor 在 `local/auditor-scratch/` 编译运行测试夹具：
   ```text
   PASS: actual-entry offsets, codec check, 256 kernel pages, libzstd interoperability
   PASS: ctl0 ping, output bounds, short copy, partial allocation and serial cleanup
   ```
   - 运行期间 AddressSanitizer 与 UndefinedBehaviorSanitizer 诊断输出为 0。

---

## 7. 问题单

### AUD-008（中低，Developer）缺少必需节 .kpm.ctl0 控制入口，且 zstd_release 释放后未清零工作区指针
- **类别**：`product`
- **证据**：
  1. `Auditor/tools/artifact_audit.py` 在初始候选（`+gc330fe19c6d2`）上报 `missing_section: 缺少必需节 .kpm.ctl0`；
  2. `zram_zstd/zram_zstd.c:55` 在 `zstd_release` 中执行 `vfree` 释放 `cwksp`/`dwksp` 后未置空指针，若局部失败后重复释放存在潜在双重释放隐患。
- **影响**：管理工具无法通过标准控制入口探测模块存活；内存清理存在防御性脆弱点。
- **建议**：补充 `KPM_CTL0` 响应 `ping`；在 `vfree` 后将 `ctx->cwksp = NULL; ctx->dwksp = NULL;`。
- **修复事实**：Developer 在提交 `a5e1615bdb715257b167483e3e3a6f019b4a15f0` 中落地修复；在修复候选（`+gd464ad07ccb0`）中补充了 8 字节 `.kpm.ctl0` 节，引入了 `compat_copy_to_user` 并完成指针清零。
- **关闭条件**：由 Auditor 在修复冻结候选实例上独立复核节区、重定位、符号导入及清理路径后关闭。
- **复核结论**：Auditor 独立重编译并自解析修复候选 4 份产物，确认 `.kpm.ctl0` 节区存在且重定位正确，单测覆核通过。**正式关闭**。
- **状态**：**closed（独立复核关闭）**
- **频率**：未知
- **置信度**：已确认
- **发现候选**：初始 4 份实例（`+gc330fe19c6d2`）
- **修复候选**：修复 4 份实例（`+gd464ad07ccb0`）

---

### AUD-009（高，Developer）模块注册内核算法后无法阻止 KernelPatch 卸载释放内存，卸载将致 Use-After-Free 内核 Panic
- **类别**：`product`
- **证据**：
  1. `KernelPatch/kernel/patch/module/module.c:541` 卸载流程执行 `rc = (*mod->exit)(reserved)` 后**完全不检查返回值**，无条件执行 `kp_free_exec(mod->start)` 释放模块可执行代码区与数据区内存；
  2. `zram_zstd/zram_zstd.c:162` 在 `zram_zstd_init` 中调用 `crypto_register_alg(zstd_alg)` 将算法结构体及压缩/解压/上下文函数指针挂入内核全局算法链表；
  3. 模块退出函数 `zram_zstd_exit:177` 仅打印内核告警日志 `logkm("DO NOT UNLOAD: zram may retain codec callbacks\n")` 并返回 `0`，模块不持有亦无法调用内核未导出的算法注销函数；
  4. 卸载后，内核算法链与 zram 设备仍持有指向已释放模块内存中的函数指针，一旦后续 zram 触发页面压缩或解压，将立即触发指令预取中止或非法访问，导致内核 **Panic 崩溃死机**。
- **影响**：若用户或管理脚本执行 `kpatch su kpm unload zram_zstd`，将引发 Use-After-Free 导致的整机崩溃死机。按仓库定级规则，**可致系统崩溃/Panic 的问题严重度不得低于「高」**。
- **建议**：
  1. 代码已在 `README.md`、`KPM_DESCRIPTION` 与内核日志中明确声明 `DO NOT UNLOAD`，达到了当前框架条件下模块的最大防御边界；
  2. 根本解决需 KernelPatch 框架支持模块卸载阻断（检查退出回调返回值非零即中止释放）或提供安全的算法注销机制；
  3. 交付前建议由维护者出具正式书面风险接受（`RA-001`，定级：高）并在元数据登记关闭，严格限制模块使用前提为开机常驻且禁止卸载。
- **关闭条件**：由维护者出具书面风险接受（批准人：维护者，定级：高，范围：`zram_zstd 0.1.0` 在 KP 框架下的卸载路径）并在元数据登记关闭，或由框架层/模块层实现安全卸载防护后复核关闭。
- **状态**：**open**
- **频率**：低（依赖外部主动触发 unload 命令）
- **置信度**：已确认
- **涉及候选**：全部 8 个在册候选实例

---

## 8. 边界扫描覆盖

| 边界维度 | 覆盖与测试情况 | 审计结论 |
| :--- | :--- | :--- |
| **内核版本边界** | 仅覆盖本地 Android 4.4（B2N）语料；高版本（5.10/5.15/6.1/6.6）未实测 | **未覆盖**（不能外推为全版本兼容） |
| **结构体字段存在性** | 动态版优先 BTF，BTF 不可用时通过函数小窗口汇编推导；失败均返回 `-EINVAL`/`-ENOENT`，**不按版本号猜偏移** | **PASS**（失败路径严格阻断） |
| **静态基线模板边界** | 静态基线布局五项偏移初始值均为 `-1`；加载前需由 `patch_offsets.py` 写入真实偏移，未写入时 `calculate_offsets` 返回 `-EINVAL` 阻断加载 | **PASS**（防未适配裸跑机制生效） |
| **缓冲区与长度边界** | `ctl0` 严格要求 `outlen >= 5`；`zram_zstd_init` 校验 `crypto_alg` 尺寸不越界 | **PASS**（边界防溢出完整） |
| **UID / 权限边界** | `ctl0` 无额外 UID 校验，依赖 KernelPatch 框架 `/dev/kp` 及 superkey 控制面鉴权；无状态修改，仅返回静态只读 `pong` | **PASS / 需真机核验** |
| **加载 / 卸载顺序边界** | `init` 拦截 `pre-kernel-init`；卸载路径存在固有崩溃风险（见 `AUD-009`） | **FAIL（存在高风险 AUD-009）** |

---

## 9. 安全评估

| 评估维度 | 结论 | 依据 | 限制与说明 |
| :--- | :--- | :--- | :--- |
| **权限与可达性** | 受控 | `ctl0` 仅响应只读 `ping`，无敏感数据返回与状态变更 | 实际鉴权依赖 APatch / KP 框架 |
| **内存上下文** | 审查通过 | 工作区内存使用 `vzalloc` / `vfree`（可在睡眠上下文安全执行），编解码在软中断/进程上下文执行，不引入可能引起死锁的原子上下文阻塞 | 需真机验证压力下的内存分配 |
| **生命周期** | **存在严重隐患** | 卸载后算法回调悬挂，致 Use-After-Free 内核崩溃 | 开具问题单 `AUD-009`（定级：高） |
| **输入校验** | 审查通过 | 参数为空、未知命令、短缓冲均严密返回 `-EINVAL`；复制不足返回 `-EFAULT` | 32 项单测覆盖 |
| **信息泄露** | 审查通过 | 无内核指针、堆栈泄漏与设备序列号暴露 | 经静态审查确认 |
| **hook 与原逻辑交互** | 审查通过 | 未挂钩内核已有算法，使用独占注册名 `zstd-kpm`；原生若已具备 `zstd` 则主动拒绝加载返回 `-EEXIST` | 避免算法名称冲突 |

---

## 10. 同源风险声明

- **语料同源**：本次审计依赖的内核镜像语料（`kernel_img/B2N-416G_boot.img`）与平台符号快照来自公共输入与实现方，Auditor 在本地使用自建脚本复算，但存在相同测试语料无法覆盖其它机型差异的同源限制；
- **独立性声明**：Auditor 绝未调用 `tools/identity.py`、`tools/build_candidate.py` 或 `kernel_img/offset_harness` 作为审计结论依据；所有重编译、ELF 字节解析、重定位检查、静态扫描均基于沙箱内自编译自解析工具链完成。

---

## 11. 未验证清单（限制结论的环境事实）

1. **真机测试完全缺席**：当前在册 `device_tests[]` 为空；模块在真机环境下的算法注册可见性、开机加载顺序、zram 活动算法切换（`echo zstd > /sys/block/zram0/comp_algorithm`）、换页读写稳定性与并发压力均**未验证**，不得将本报告外推为真机可用结论；
2. **静态基线可加载性未就绪**：两套静态基线（`baselines` 与 `baselines_debug`）的布局文件当前五项偏移值均为 `-1`（模板初始状态），未针对具体机型派生真实偏移前不具备直接加载能力；
3. **高版本与 GKI 内核兼容性**：仅在 Android 4.4（B2N）语料上验证了推导窗口，在 5.10/5.15/6.1/6.6 等 BTF 缺失或结构变动场景下的行为仍待语料扩充或真机验证。

---

## 12. 复核记录

- **2026-10-10 Auditor 独立复核并关闭 AUD-008**：
  - **修复 commit**：`a5e1615bdb715257b167483e3e3a6f019b4a15f0`；
  - **复核依据**：在沙箱独立重编译修复候选 4 份实例，哈希全部吻合；解析 ELF 确认 8 字节 `.kpm.ctl0` 节区及 `R_AARCH64_ABS64` 重定位有效；`selfcheck` 32 项断言（含新增 11 项控制接口与防御性清理断言）全量通过，ASan/UBSan 零告警。正式复核关闭。
