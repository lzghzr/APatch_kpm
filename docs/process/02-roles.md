# 角色、职责与所有权

## 硬规则

1. **不替别人写结论**。审计发现的问题交回 Developer 修复；测试发现的实现缺陷交回 Developer；测试脚本自身的缺陷由 Tester 修。任何角色都不改写别人的报告。
2. **保留原始证据**。更正通过追加「后续状态 / 维护者记录」实现，不改写已有结论。
3. **维护者只改自己拥有的文件**（元数据、流程文档、门禁、根目录交付物）。确需动角色文件时，必须明确标注为维护者记录并说明范围。

## 授权与边界

| 事项 | 授权 | 边界 |
| --- | --- | --- |
| 身份登记 | Developer 通过 `tools/build_candidate.py` 构建并受控追加 `builds[]`（同时更新登记人/时间）；直接 `record` 用于探索留痕；也可用 `--handoff` 只产出交接清单，由维护者 `import-manifest` 导入 | 维护者维护当前版本声明与结论字段；旧构建条目永不修改（见 [01-identity.md](01-identity.md)） |
| 修复反馈 | Developer 在 `Developer/reports/responses/` 追加**修复响应**（模板 [developer-response.md](../templates/developer-response.md)）：问题编号 + 修复 commit + Build ID + 证据 | 不改发现方报告；不写验收/审计结论；问题单由发现方复核关闭 |
| Tester 修复反馈 | Tester 在 `Tester/reports/responses/` 追加修复响应（模板 [tester-response.md](../templates/tester-response.md)）：问题编号、工具 commit/冻结状态、逐文件 SHA-256、验证层级与证据；使用产物时附完整产物身份 | 修复响应由 Tester 编写，维护者同步状态；未冻结修复以工作树哈希留痕，独立复核通过后按问题单条件关闭 |
| 工作树 | 探索阶段允许工作树不干净；候选交接必须**从冻结提交构建**，推荐 `git worktree add ../<repo>-dev <sha>`；构建产物归档到 `artifacts/<build_id>[#n]/`（不可覆盖） | 不得用未提交源码交接；不得覆盖已归档产物 |
| 归属未明的路径 | `.agents/`（技能与流程类文档）归维护者；镜像输入 `kernel_img/` 的镜像/符号表与 `local/` 的运行产物属本地数据（不进 git）；`kernel_img/offset_harness/` 是 Developer 源码 | 技能内容变更由 Developer 提建议、维护者落地 |
| 跨角色改动 | 任何角色都可以提交**补丁建议**（`git format-patch`/diff + 说明）给所有者 | 由所有者落地；不得直接改别人的结论性文件 |
| 共享门禁调整 | 维护者拥有 `tools/` 门禁及维护者自检；Tester/Auditor/Developer 提交补丁建议与复现证据，由维护者落地 | 调整检查范围需记录理由与正反回归；各类报告和修复响应中的产物身份引用统一核验 |
| 读取权 | **所有角色都可以读任何角色的工具、报告与原始证据**（用于本地诊断、复现问题、准备修复） | 读取不等于修改：修改权、结论权、真机设备操作权仍分别归属；引用他人结论时必须标注来源与是否独立复现 |
| Auditor 隔离构建 | 可在 `local/auditor-scratch/`（已被 `.gitignore` 覆盖）或仓库外工作树里独立重编译 | 不在共享工作树内 `make`；产物不回写 `re_kernel/` 与 `artifacts/`；不清理 `local/stale/` |
| Auditor 自建语料 | 可自建**独立**的 kallsyms 提取（不得调用 `kernel_img/offset_harness`），用于降低「语料由 Developer 提供」的同源风险 | 提取产物放 `local/kallsyms_audit/`；报告里要说明提取器与实现方无关、并声明残余同源风险 |
| 语料范围 | 以使用者当前放在 `kernel_img/` 的镜像/符号表为准；harness 取不到符号表时按 **SKIP（未覆盖）** 记录，不算失败、也不算缺陷 | **不得把"本 harness 提取失败"写成"内核不含 kallsyms"**，定性需独立提取器；结论要写明实际语料清单 |
| Auditor 只读网络 | 可以为上游核对（KernelPatch 导出符号、内核源码）拉取公开仓库与文档 | 仅读；不上传、不外发语料/设备数据；引用外部结论要标 URL 与访问时间 |
| Auditor 版本控制 | 需要改他人文件时走 `git format-patch` 补丁建议 | 不做 `git add/commit/tag/push`（签名交付是维护者动作）；不执行 `checkout/restore/reset/stash/clean` |
| Auditor 设备与密钥 | 真机操作与 superkey 属 Tester/维护者域 | 不碰设备、不读取或落盘密钥/设备标识 |

## 所有权表（本仓库路径）

| 角色 | 拥有 | 明确不拥有 |
| --- | --- | --- |
| Developer | 各模块目录（`re_kernel/`、`hosts_redirect/`、`cgroupv2_freeze/`、`dont_kill_freeze/` …）、`kpm_utils.h`、`kernel_img/offset_harness/`（离线偏移 harness）、`Developer/`（含 `reports/handoffs/`、`reports/responses/`）；`kernel_img/` 里的镜像与 `local/` 中开发运行产物是本地数据（不入库），角色专属子目录按表内边界分配 | `Auditor/`、`Tester/`、`metadata/` 的结论字段、`docs/`、`tools/` |
| Auditor | `Auditor/`（独立工具、快照、报告） | 模块源码（发现问题只提问题单，不代改）、`Tester/` |
| Tester | `Tester/`（真机脚本、实机报告） | 模块源码、`Auditor/` |
| 维护者 | `metadata/`、`docs/`、`tools/`、`AGENTS.md`、`README.md`、`.github/`、`.gitignore`、`.agents/`（技能与流程类文档）、根目录交付物 | 角色目录内的结论性内容 |

CI 构建规则（`.github/workflows/build-kpm.yml`）：**只构建「有 Makefile 且未被 `archive` 标记」的顶层目录**。
没有 Makefile 的目录（`docs/`、`tools/`、`metadata/`、`Auditor/`、`Tester/`、`Developer/`、`kernel_img/`、`local/`、子模块…）
天然跳过，**不需要任何标记文件**；`archive` 空文件只用于「有 Makefile 但不想让 CI 构建」的模块目录（如 `lmkd_dont_kill/`）。
因此新增文档/工具目录时什么都不用加；要归档某个模块才放 `archive`。

### Auditor 运行约束

| 约束 | 内容 |
| --- | --- |
| C1 写范围 | 仅 `Auditor/**`、`local/auditor-scratch/**`、`local/kallsyms_audit/**`；其余路径只读 |
| C2 版本控制 | 不 `git add/commit/tag/push`；改他人文件走 `format-patch` 补丁建议 |
| C3 共享工作树 | 不在共享树内构建；不执行 `checkout/restore/reset/stash/clean`；不清 `local/stale/` |
| C4 结论来源自律 | `tools/identity.py`、`tools/build_candidate.py`、`kernel_img/offset_harness` 的输出不得进结论；运行过必须在报告标注「仅用于定位，未作依据」 |
| C5 不替别人写结论 | 不写 `metadata/` 结论字段、不改他人报告；可复核并关闭自己发现且由其他角色修复的问题，状态由维护者同步 |
| C6 设备与密钥 | 不碰真机、不读取/落盘 superkey |
| C7 不可覆盖 | `artifacts/**` 与 `MANIFEST.json` 只读；自有报告只追加，引用他人报告时保留原文 |
| C8 公开文件卫生 | 报告不写本机绝对路径、设备序列号、superkey、抓包内容 |

### Tester 授权与边界

| 编号 | 授权 / 约束 | 内容与边界 |
| --- | --- | --- |
| A1 | 设备操作**白名单** | `adb shell/push/pull/getprop/dmesg/reboot`、`adb reboot bootloader`、`fastboot devices/getvar`、`fastboot reboot` |
| A1 | 设备操作**黑名单**（禁止） | `fastboot flash/erase/-w`、`adb shell rm -rf`、清 pstore、改 superkey、卸载/重装 APatch、刷机、进 recovery 清数据 |
| A2 | 自主 `adb reboot` 作为死机恢复 | **有条件批准**：① 已记录四项基线且基线 pstore 为空，仅用于无响应类异常；② **只允许一次**，之后停止重试并升级；③ 当前出现崩溃特征或发现 pstore 非空时保留现场交维护者；④ 先尽力采集可读证据并通知维护者，记录恢复时间、动作与结果；⑤ 重启可能改变现场，恢复后立即采证 |
| A3 | superkey 一次性提供 | 经会话/环境变量传入，**只读、不落盘、不进报告、不进 git**；未提供时 `module list/load/unload` 不可执行，按 A6 记为未执行 |
| A4 | 原始证据落库位置 | 原始 dmesg/pstore 全文（可能含序列号）放 `local/tester-raw/`（已 gitignore）：入库只放**脱敏摘要**，序列号一律换成设备指纹哈希 |
| A5 | 物理动作请求单 | 需要人手时用 [escalation 模板](../templates/escalation.md) 的「需要维护者执行的物理动作」发起，维护者按「动作回执」回填（时间/动作/结果） |
| A6 | 「无设备 / 未授权 ⇒ 未执行」 | 是**合法状态**（沿用 `not-run` 先例），不算失败；但必须写明未执行的原因与未覆盖清单 |
| C1 | 崩溃判据改**存活判据** | 主判据 = `boot_id` 不变 + `uptime` 单调 + adb 持续响应；`dmesg` 无崩溃特征标注为**弱证据**，只能写"未观察到" |
| C1.1 | **退出码语义** | **看门狗超时或被信号杀死（rc=124 或 ≥128）= 设备无响应 → 退出码 90**，走 07 升级；**KP 控制命令按状态返回非 0（如"已加载/已卸载"）或判据失败 = 判据 FAIL → 退出码 1**，不是设备无响应。两者不得混用 |
| C1.2 | dmesg 崩溃特征的处理 | **出现即升级**（不自动卸载、保现场）；**缺席不算通过**，只能记"未观察到" |
| C2 | 结论上限 | 只能写"该字节在该机型/该内核/该次加载下存活 N 秒且 X/Y 判据通过"，禁止外推到其它机型或内核 |
| C3 | 加载人在环 + 零重试 | 加载类操作必须维护者在线；死机后**零重试**，含脚本之外与跨会话的重试 |
| C4 | 加载前基线 | 必录 `boot_id`、`uptime`、**pstore 是否残留旧崩溃**、当前已加载模块；pstore 非空先停下问维护者 |
| C5 | 判据脚本绑定 | 判据脚本的路径 + hash（或脚本 commit）必须写进报告；脚本变更后旧结论不自动继承 |
| C6 | 写范围 | 仅 `Tester/**` 与 `local/tester-raw/**`；`docs/`、`metadata/`、`tools/`、模块源码只提补丁建议 |
| C7 | 「采不到」必须写原因 | 未采集项逐项写原因，不允许留空或空格占位 |

## Developer

**拥有**：目标内核分析、结构体偏移推导与验证、模块代码、构建器、自检断言、开发报告。

**必须产出**

1. 可复现候选：从**冻结提交**构建，登记 commit + Build ID + 实例号 + 每个产物 SHA-256
   （`tools/build_candidate.py`，或其 `--handoff` 交维护者导入）。
2. 变更说明：改了哪些 hook 点/偏移/数据结构，为什么。
3. 自检结果：构建命令、编译器警告、断言语义、离线语料回归结论。
4. **边界声明**：写明「这是实现方自检，不是独立审计，也不是实机结论」。
5. 未解决项与降级行为：偏移推导失败的版本、功能降级路径。

**DoD**：统一候选构建事务通过；指定实例通过 `verify --profile candidate --instance-id <id>`；开发报告含完整 commit、instance_id、产物 SHA-256 与自检边界。

## Auditor

**拥有**：独立工具、独立复现、代码风格检查、审计报告、问题单。

**必须产出**

1. 独立复现：自己重编译（自己的编译命令）、自己重解析产物字节（自己的 ELF 解析器），不调用实现方与维护方脚本。
2. 代码风格检查：对冻结提交中的本轮源码独立运行项目格式检查，并人工复核命名、结构与可读性；记录规范/配置哈希、工具版本、命令、文件范围、结果与例外。风格问题交 Developer 修复，Auditor 复核。
3. 静态测试与边界扫描：跨内核版本边界、结构体字段存在性边界、哨兵值边界、缓冲/长度边界、UID 与权限边界。
4. 安全评估：权限与可达性、内存上下文（可否睡眠）、对象生命周期（释放后使用/双重释放）、输入校验、信息泄露、hook 与原逻辑的交互。
5. 收集问题单：编号、严重度、归属、证据、影响、建议、关闭条件。
6. **同源风险声明**：明确哪些结论依赖了与实现方同源的来源（例如同一份源码、同一个内核镜像语料）。
7. **未验证清单**与限制结论的环境事实。

**DoD**：报告绑定身份三要素；包含独立代码风格检查及规范例外；每条结论有可复现命令与实测输出；未覆盖部分写清。

## Tester

**拥有**：真机脚本、实机报告、设备环境事实。

**必须产出**

1. 判据（可量化，如「module list 含模块且 boot_id 不变、uptime 单调、adb 持续响应」）、成功/失败计数、尝试次数。
2. 环境事实：内核版本、机型（脱敏）、APatch/KernelPatch 版本、模块清单、SELinux 状态。
3. 未覆盖清单：没测到的功能、机型、内核版本。
4. 失败归属：区分**实现缺陷**与**测试缺陷**（例如脚本权限不足、路径不对是测试缺陷，不是产品缺陷）。
5. 设备异常时：按 [07-escalation-device.md](07-escalation-device.md) 立即停止重试、采集证据、**通知维护者**。

**DoD**：报告含身份三要素、判据与计数、环境事实、结果与未覆盖清单；每次只加载一个变体。

## 维护者

**拥有**：`metadata/`、`docs/`、`tools/`、根目录交付物、版本与发布。

**必须产出**：身份记录、版本一致性、验收结论（复算哈希，不采信报告）、签署的交付提交、覆盖矩阵更新。
清单见 [05-maintainer-acceptance.md](05-maintainer-acceptance.md)。
