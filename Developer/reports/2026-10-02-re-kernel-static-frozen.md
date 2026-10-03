# re_kernel_static 8.0.0 基准候选冻结报告

角色：Developer。状态：源码与基准候选冻结，等待独立审计。此次冻结由用户明确授权，Git 提交不签名、不推送；维护者验收与签名交付尚未执行。

## 身份

- 完整源码 commit：`3eed8952fcbaa3107ed8cc0aa429631af53d5bed`。
- KernelPatch commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`（SDK 0.13.9）；隔离检出依赖干净，使用已有本地仓库初始化，没有下载远程仓库。
- 源树 SHA-256：`85406787a3ba53b06b9b3996e67c04819d4dfe0a0067d2e73c8e4cdb6aa9c586`；17 个输入全部纳入提交，`source_dirty=false`、`source_blob_missing=[]`。
- 工具链：NDK 26.3.11579264；实际编译器字节哈希与有效参数逐实例记录在 [候选清单](handoffs/2026-10-02-re-kernel-static-frozen-candidate.json)。
- 构建事务：统一入口在干净隔离工作树执行 `make -B -C re_kernel_static baselines`，前后输入/依赖/参数一致，返回码 0，八份产物分别归档到新的实例目录。
- 验证输出：[实现方身份与产物自检](selfchecks/2026-10-02-re-kernel-static-frozen-selfcheck.json)。每个清单条目调用 `tools/identity.py` 的 `verify_build(profile="candidate")`，8/8 通过；未通过伪造 metadata 或放宽档位取得结果。

| 变体 | instance_id | 产物 SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g85406787a3ba.r6f82ad1c.kpb51197a.ndk26.3.11579264#1` | `b3cee82601fd89a8ccfc908830b522d52871cc3000e9b6c3280909a084a2e9e3` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g85406787a3ba.r2c5dfe3a.kpb51197a.ndk26.3.11579264#1` | `ec42d6b3e94d17fe1805e366425a510a64a089e661727404f85a84314c05aaa7` |
| abi4 | `re_kernel_static-8.0.0_abi4+g85406787a3ba.r427685b8.kpb51197a.ndk26.3.11579264#1` | `b1e7e8a47d81ba0bb292dedf616ad226e2d72e27390fa2079392bb6b1a887fe6` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g85406787a3ba.r5f37025a.kpb51197a.ndk26.3.11579264#1` | `20b1bbe19f29c0ce4d59419b88d89e2c0fe374313e1d60a212ba6e2b454fb3fe` |
| abi5 | `re_kernel_static-8.0.0_abi5+g85406787a3ba.r899a936d.kpb51197a.ndk26.3.11579264#1` | `b40f556e38305d8dec46a8322aa9df063c40e6f405a927f48dbc302acda345d6` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g85406787a3ba.re0df8c2a.kpb51197a.ndk26.3.11579264#1` | `9a42e3b6886542188f652927e419a627d14e65768b44bf10ce3228bf8f59dbc0` |
| abi6 | `re_kernel_static-8.0.0_abi6+g85406787a3ba.ra8963763.kpb51197a.ndk26.3.11579264#1` | `d8c33f1a407bd03c3353054800b4c783eb4d0f82cd7d5d32554d7494a0eef8da` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g85406787a3ba.rf4400d60.kpb51197a.ndk26.3.11579264#1` | `99ba2818a0dd495d74b61e6e74d3a9ae8ed3abff3ff2082bc51855d430a1b6e1` |

## 本轮冻结范围

汇总此前未提交的静态移植实现、生产函数主机测试、中文项目技能和开发记录；保留旧探索清单与报告的原始身份及限制，不升级旧探索实例为候选。源码汇总提交依据用户授权完成，未改 Auditor/Tester 报告、metadata 或共享门禁工具。

功能包括 Generic Netlink family 注册、三类事件发送、UID 增删、RPC/code 清理规则的增删与匹配、SKIP/BY_CODE/BY_DATA、Binder 队列去重与释放、旧 Binder 内核映射 data 读取，以及按实际 Binder 函数签名准备的 ABI3/4/5/6 release/debug 基准。偏移表 44 项、88 字节，布局由同名 JSON 绑定。

原来被 Git 忽略的 `re_kernel_static/vmlinux.h` 是偏移生成器的 BTF 头文件输入，且此前身份工具已把它列入 17 个输入；本轮将其原字节纳入源码提交以补齐按 commit 复算条件。没有删除该输入或缩小自检范围。它是既有模板来源，不能据此外推其它目标布局。

依据用户指令删除活动 `get_task_ext_probe/`。原探针报告、交接清单与两份归档 KPM 保留并复算哈希；旧源码提交 `06b1d95db7ba6a4dc51aa3eb9c1452b1a1f10f8a` 通过本地 `codex/archive-get-task-ext-probe` 历史引用保存。退役状态已追加到原开发报告。

## 构建与自检

```bash
python3 tools/build_candidate.py re_kernel_static --toolchain ndk26.3.11579264 --target baselines --handoff Developer/reports/handoffs/2026-10-02-re-kernel-static-frozen-candidate.json --env NDK_PATH=<NDK-bin> --env LAYOUT_DIR=../local/baselines
python3 re_kernel_static/tools/test_static.py --baselines local/baselines
```

从上述源码 commit 的新干净检出复现；清单名和输出位置使用新的未占用位置。构建器已归档产物，不使用 `--allow-dirty` 或 `--no-archive`。

- 冻结工作树预检：`freeze_check.py --json` 没有阻塞项；未将签名提示当作实际签名执行。
- 构建：八个变体完成；五类警告仍来自既有 SDK cmpxchg 与 READ_ONCE/WRITE_ONCE 定义，未新增模块警告。
- candidate 核验：8/8；源码、配方指纹、编译器哈希、构建事务与产物一致。原清单、归档 MANIFEST 与复制到主工作目录的字节完全相符。
- 全部 KPM 导入在当前 SDK 导出集合中找到，无裸 C 内存函数导入、task_ext 依赖、FP/SIMD/SVE 指令。
- 实际 JSON/blob 往返仅改变静态表；ABI/布局/哈希不匹配、无效输入及覆盖已有输出被拒绝。
- 生产函数 ASan/UBSan：事件与调用上下文、Genl 收发/回滚/规则与随机输入、四种 ABI 的异步清理、旧 data 读取、长度与跨页边界、所有原生读取失败、共享预算、对象/FD 保留、最早消息保留及八线程并发通过。
- 新候选字节逐一与最后的 binder-read 探索产物一致；此次升级的是干净源码与严格构建身份，历史探索条目保持原状。
- 镜像范围：本轮没有新镜像分析或全量回归。之前 B2N 的局部读取证据继续保留，不能充当完整目标配置。

自检与构建日志放在 `local/static-freeze-20261002-01/`。归档位置：

- `artifacts/re_kernel_static-8.0.0_abi3+g85406787a3ba.r6f82ad1c.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi3.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi3_debug+g85406787a3ba.r2c5dfe3a.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi3_debug.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi4+g85406787a3ba.r427685b8.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi4.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi4_debug+g85406787a3ba.r5f37025a.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi4_debug.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi5+g85406787a3ba.r899a936d.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi5.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi5_debug+g85406787a3ba.re0df8c2a.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi5_debug.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi6+g85406787a3ba.ra8963763.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi6.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。
- `artifacts/re_kernel_static-8.0.0_abi6_debug+g85406787a3ba.rf4400d60.kpb51197a.ndk26.3.11579264/re_kernel_static_8.0.0_abi6_debug.kpm`；同目录 `MANIFEST.json` 与同名 `.kpm.json`。

## 交接与下一步范围

Developer 已提供候选清单，尚未导入维护者所有的 metadata。由维护者建档/导入后，按具体 instance_id 再执行 CLI candidate 核验。此处清单核验不冒充 metadata 登记、独立审计、验收或签名交付。

下一步交 Auditor：使用上述完整源码 commit 与八份实际归档字节，独立重编译/自解析，不采用 Developer/维护者脚本的输出作审计结论。重点复核：

1. 函数 ABI 与偏移表二进制替换边界、全部导入及 CFI 后缀查找。
2. Binder 调用上下文、模块短临界区、node/inner_lock、事务/proc 生命期与释放顺序。
3. RPC 匹配和 BY_DATA 去重的全字节比较、预算/失败保留、对象/FD 排除，以及解冻后旧消息仍能继续消费的条件。
4. Genl 控制入口的发送方权限、长度/命名空间/错误返回、UID 与规则并发更新及 skb 所有权。

以上是建议复核范围，不替 Auditor 定结论或关闭问题。

这些产物是用于离线替换的通用基准，当前偏移是模板。真机前必须选择目标镜像、核对完整 44 字段并生成单独绑定身份的目标 KPM；不能直接把 ABI 编号当作 Linux 大版本。当前 B2N 仅确认读取相关字段，包括 data=0x58、alloc.buffer=0x38。

已有 DEV-001/DEV-002/DEV-003/DEV-004 记录及修复响应继续保留，未由 Developer 自行关闭。卸载 RCU/回调生命期按用户此前约定暂缓；旧 KP 缺少 suffix 导出的加载问题按更新 KP 的约定处理，SDK CFI 查找疑点仍需独立复核。完整目标偏移、真实锁与映射、Generic Netlink ACK/订阅和应用响应均未真机验证。

## 边界声明

本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），不是独立审计，也不是实机结论。此处离线语料为此前已保存的 B2N 局部证据，没有新增全量语料覆盖。

主工作目录仍有本轮范围外的未跟踪 `.github/workflows/repository-gate.yml`，保留未提交。源码冻结及候选从干净隔离检出执行，不能把 scoped 冻结写成主工作目录整体门禁通过。
