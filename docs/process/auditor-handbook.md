# Auditor 手册：独立审计 / 代码风格 / 静态测试 / 边界扫描 / 安全评估

Auditor 的产出是**绑定身份的结论**。独立性不等于另写一份代码，而在于**不共享结论来源**。

## 0. 运行边界

写范围为 `Auditor/**`、`local/auditor-scratch/**` 与 `local/kallsyms_audit/**`；不在共享工作树里 `make`（避免覆盖 Developer 的
在树产物），不执行 `checkout/restore/reset/stash/clean`，不做 git 写操作。需要改别人文件时提补丁建议。
读取权是开放的（任何角色的工具、报告、原始证据都能读），但**读取不等于把它的输出当结论**：
用到 `tools/identity.py`、`tools/build_candidate.py`、`kernel_img/offset_harness` 时必须在报告里写明
「仅用于定位，未作依据」（门禁 `auditor_report_sources` 会检查这一点）。

报告必须有一张**证据来源表**（结论 → 命令 → 归属角色），模板已给出；同源风险与未验证清单不可省。
完整约束见 [02-roles.md](02-roles.md) 的「Auditor 运行约束」。

## 1. 独立性要求

| 必须 | 禁止 |
| --- | --- |
| 用自己的编译命令重编译 | 复用 Developer 的构建脚本产物当审计对象（审计对象应是交付字节，重编译用于交叉验证） |
| 用自己的解析器解析产物字节 | 调用 `tools/identity.py`、`kernel_img/offset_harness` 的结论 |
| 自己构造夹具与输入 | 引用 Developer 的断言输出作为「已验证」 |
| 声明同源风险 | 用「与实现一致」当作「正确」 |

本仓库中：

```bash
python3 Auditor/tools/kp_symbols_extract.py                 # 平台符号快照（来源：KernelPatch submodule）
python3 Auditor/tools/artifact_audit.py --module re_kernel  # 产物字节独立解析
python3 Auditor/tools/static_scan.py re_kernel              # 边界扫描 + 安全评估（启发式）
```

`Auditor/tools/` 与 `tools/identity.py` 是**两份独立的 ELF 解析实现**：这是刻意的重复，门禁会检查审计工具不导入实现方/维护方模块。

## 2. 静态测试（产物层）

| 检查 | 判据 |
| --- | --- |
| ELF 结构自洽 | 段表/节表在文件范围内；符号表与字符串表索引合法；重定位指向存在的符号与节 |
| 入口齐全 | `.kpm.init`、`.kpm.ctl0`、`.kpm.exit` 存在且非空；`.kpm.info` 五个字段齐全 |
| 内嵌元信息 | `name/version/license/author/description` 与模块源码宏一致；version 与 Makefile/README/元数据一致 |
| 未定义符号可解析 | 每个 `UND` 符号都在平台导出符号表（`kp_runtime_symbols*.json`）内 |
| 内核符号依赖存在 | 代码通过 `kallsyms_lookup_name_by_suffix` 查找的符号名，在每个语料内核的符号表里都存在（跨版本矩阵） |
| 重定位类型白名单 | 只出现预期的 AArch64 重定位类型；出现未预期类型要解释 |

## 2.1 代码风格检查（源码层）

对本轮绑定的冻结源码独立运行格式检查。C/头文件使用该提交的 `.clang-format`，例如对明确选定的文件运行 `clang-format --dry-run -Werror <文件列表>`；同时用 `git diff --check <审计基线> <源码提交> -- <文件列表>` 检查本轮差异。其他语言使用项目约定的检查器。外部 SDK、生成文件和第三方代码单列范围及处理理由。

格式检查后，人工复核命名是否一致、函数和条件结构是否清晰、注释是否解释必要约束，以及错误处理是否易于审查。报告记录完整源码提交、规范/配置 SHA-256、检查器版本、命令、文件范围、退出码、输出与例外；缺少工具或规范时说明未覆盖，不能记 PASS。Developer 自检输出只作参考，Auditor 必须独立运行。

检查使用只读模式，发现问题交 Developer 在新提交中修复，Auditor 再复核；不得在共享源码中自动格式化。严重度按实际影响定级，格式通过只说明风格检查范围。

## 3. 边界扫描

| 边界 | 检查什么 |
| --- | --- |
| 内核版本边界 | 最老/最新（如 4.4 与 6.6）与每个大版本的分界；字段在哪些版本存在、不存在的版本走什么路径 |
| 字段存在性 | 结构体字段缺失/为 0/为负偏移时的行为（是否降级而不是误用） |
| 哨兵值 | `IZERO`/`UZERO` 等哨兵的正反语义；「未设置」与「全部/最强」是否被混淆 |
| 长度/索引 | 固定缓冲与拷贝长度、`snprintf` 截断、循环上下界、数组下标、`doff << 2` 之类的算术 |
| UID/权限 | uid 比较的上下界（`MIN_USERAPP_UID`/`MAX_SYSTEM_UID`）、uid=0 与哨兵冲突、过滤表满时的行为 |
| 时间/顺序 | 加载/卸载顺序、重复加载、init 半失败、卸载后再加载 |
| 语料边界 | 只有符号表没有镜像的条目（SKIP）、内嵌提取失败的条目，是否会让结论过度泛化 |

方法：先用 `static_scan.py` 得到**审查点**（不是结论），再逐个人工确认；确认不了的写进「未验证清单」，并给出在目标内核/真机上的验证方法。

## 4. 安全评估

按「谁能到达 → 会发生什么 → 后果」写：

1. **权限与可达性**：netlink 协议号、`/proc` 节点权限、ioctl、supercall 是否要求特权；Android SELinux 是否限制非特权域。若结论依赖 SELinux 策略，必须标为待真机验证的环境事实。
2. **内存上下文**：hook/tracepoint 回调里的可睡眠操作（`GFP_KERNEL`、`memdup_user`、`proc_*`、`netlink_kernel_create`）与调用路径的锁状态。离线无法判定锁状态时，写清验证方法（目标内核源码或 `CONFIG_DEBUG_ATOMIC_SLEEP` 真机日志）。
3. **生命周期**：全局/静态指针在 `kfree`/`proc_remove`/`netlink_kernel_release` 后是否置空；重复卸载、先移除子节点再卸载的路径。
4. **输入校验**：用户可控长度/类型/uid 的校验是否完整；错误路径是否返回而不是继续。
5. **信息泄露**：内核地址、uid、路径、payload 内容是否被发给用户态；`/proc` 内容是否含敏感信息。
6. **hook 交互**：hook 是否改变原函数语义（返回值、参数、副作用）、与其他模块 hook 同一函数时的链式行为、卸载时是否恢复。

**允许结论「无法从离线证据判定」**，但必须给出：判定需要什么证据、在哪个环境取、谁去取。

## 4.5 门禁能查什么、不能查什么

`tools/check_repository.py` 的 `report_conformance` **只检查必需章节/字段是否出现**（身份、commit、Build ID、
sha256、同源风险、未验证……）：它是**格式门槛**，不构成结论有效性，也不能证明结论被独立复现。
同理 `auditor_independence` 只查工具代码的依赖，`auditor_report_sources` 只查"引用了维护方/实现方脚本却
没声明仅用于定位"。真正的独立性由 Auditor 自己负责，并在报告的「证据来源表」与同源风险一节里交代。

## 5. 报告

用 [../templates/auditor-report.md](../templates/auditor-report.md)，必须包含：

- 身份三要素与审计对象哈希；
- 代码风格检查的规范/配置、工具版本、范围、命令、结果与例外；
- 独立复现 vs 按报告采信的**分节区分**；
- 问题单（[../templates/issue-ticket.md](../templates/issue-ticket.md)）；
- 同源风险声明 + 未验证清单 + 限制结论的环境事实。

## 6. 关闭问题单

实现方修复的审计问题由 Auditor 独立复核关闭；Auditor 自有工具的问题由另一角色复核。修复归属方在自己的响应中声明 fixed，维护者同步元数据；关闭记录写明完整 commit、instance_id、工具 hash 与证据。
