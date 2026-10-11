# 身份与可追溯性

每份报告、问题单与交接包都绑定同一对象：**完整 source_commit + instance_id + 每个产物 SHA-256**。
`instance_id` 是 Build ID 与实例号的组合。引用实例时使用这个规范字符串；commit 与产物哈希仍须逐项列出。

## 配方与实例

- `build_id`：可读配方标签，覆盖模块、版本、变体、源树、KernelPatch commit、工具链与有效编译参数。
- `fingerprint_sha256`：完整配方指纹；Build ID 里的短摘要用于阅读，核验使用完整指纹。
- `instance_id = <build_id>#<n>`：一次具体构建。统一候选入口每次构建都追加新实例。
- `build_id_aliases`：历史目录与旧标签映射。报告的对象栏使用规范实例名。

```text
build_id = <module>-<version><variant>+g<src12>.r<fp8>.kp<kp7>.<toolchain>
fingerprint = sha256(module, version, variant, source_tree_sha256, toolchain, kernelpatch_commit, flags_sha256)
instance_id = <build_id>#<n>
```

同 Build ID 不同指纹、同指纹不同产物都拒绝登记；需要调查复现性或改变真实构建输入，不能靠改标签绕过冲突。

## 完整构建输入

| 类别 | 登记内容 |
| --- | --- |
| 模块源码与构建配置 | `.c .h .hpp .S .s .ld .lds .mk .py .sh .json .yml .yaml`、Makefile、Kbuild、CMakeLists.txt |
| 共享输入 | `kpm_utils.h`；其它依赖用 `--extra-input <仓库相对路径>` 明确加入 |
| 统一构建工具 | `tools/build_candidate.py`、`tools/identity.py` 自动作为输入登记 |
| 平台依赖 | KernelPatch 完整 commit；候选要求依赖工作树干净 |
| 编译器 | 工具链标签、实际编译器路径的脱敏表示、编译器文件 SHA-256 |
| 有效参数 | `make -n -B` 输出与编译器 SHA-256 合成参数指纹；记录实际命令与整数返回码 0 |
| 构建事务 | 构建前后源码、输入集合、配方与依赖一致；构建成功返回码与输入未变标记 |

参数捕获成功要求 `captured` 为布尔 true、`returncode` 为整数 0。`make -n` 按 Makefile 语义处理递归或
带 `+` 的命令，不能当成任意 Makefile 的只读沙箱；在隔离工作树使用已审阅的构建配置。
路径落盘前脱敏，原始日志放 `local/build_logs/`。

## 候选构建事务

```bash
export ANDROID_NDK=<本地 NDK 路径>
python3 tools/build_candidate.py <module> --toolchain <tag> --target "all debug"
# 可用 --handoff Developer/reports/handoffs/<唯一文件名>.json 生成交接清单
```

模块锁覆盖以下全过程：

1. 在干净的冻结提交取输入快照，捕获参数，检查 KernelPatch 依赖。
2. 把旧中间产物移到唯一的 `local/stale/` 目录；构建输入与 Git 已跟踪文件受到保护。
3. 默认 `make -B` 强制重建，保存构建日志。
4. 重新枚举输入，核对文件内容、HEAD、依赖 commit 与有效参数，检查受保护文件和产物时间戳。
5. 追加新实例并归档；任何校验失败都不写构建记录。

直接 `identity.py record --kind exploration` 可对现有字节作探索登记；候选登记由统一构建入口完成。
`--allow-dirty` 自动产生 exploration，`--no-archive` 只允许探索使用。构建事务记录是可复核证据，
还需要 Auditor 独立重编译与产物解析，才能形成独立审计结论。

## 只追加与写权限

- Developer 可通过受控工具追加 `builds[]`，同时更新 `updated_at/updated_by` 登记归属。
- `version_declared/version_sources/status/audits/device_tests/issues/acceptances/deliveries` 由维护者维护。
  模块元数据首次建档、当前版本提升由维护者完成；交接清单可在首次建档前生成。
- `builds[]` 的既有条目、归档字节与 `MANIFEST.json` 永不覆盖。
- `record` 对完全相同的已登记字节可幂等返回；新的实际构建由 `build_candidate.py` 自动申请新实例。
- 交接清单使用唯一文件名，已存在则拒绝覆盖。维护者 `import-manifest` 保留实例身份，并复核源码、指纹、事务与产物。
- `acceptances[]` 与 `deliveries[]` 只追加。已有 `acceptance` 单项记录继续保留，核验一并读取。

模块锁位于 `local/locks/`；元数据通过临时文件与原子替换写回。失败不会留下半截 JSON；归档遇到中断可能
留下尚未登记的目录，保留现场，由维护者核对后处理。登记工具不等同于文件系统权限隔离，角色仍须遵守所有权表。

## 按提交核验与档位

```bash
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile candidate
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile delivery
python3 tools/identity.py verify --module <module> --profile exploration
```

| 档位 | 用途与判据 |
| --- | --- |
| exploration | 保留探索事实与历史产物；缺参数或脏树会提示，源码/产物不一致仍报告问题 |
| candidate | 指纹可复算、非空输入和产物清单、完整可用 commit、严格参数与编译器指纹、干净源码、完整构建事务、产物在场且一致 |
| delivery | candidate 的全部判据，加对应交付绑定、交付源码一致与实际签名复验 |

探索实例在 candidate/delivery 档位明确失败；无匹配实例同样失败。未指定实例时，严格档位只选择 candidate；
验收与交付建议始终指定实例。历史探索实例留在登记表中，不因后来出现新候选而成为候选。
常规门禁检查历史一致性；`check_repository.py --strict` 对 candidate 执行候选判据，且所有登记产物必须在场。
门禁通过仍需审核具体实例的审计、实机覆盖和未决问题。

核验默认读取 `source_commit`，逐文件记录工作树 SHA-256 与提交 blob SHA-256；跨机器按提交表示比对，
用于适配换行过滤。`--worktree` 是显式的本地诊断模式。
`--check-build-args` 在对应冻结工作树、相同环境中重新捕获参数；捕获失败直接报错。

## 验收与交付绑定

验收条目绑定 `instance_id + source_commit + fingerprint_sha256 + artifacts{name:sha256} + accepted_by/accepted_at`。
维护者确认独立报告、风险处置与覆盖范围后追加到 `acceptances[]`。修复者不能独立关闭自己的问题。

```bash
python3 tools/identity.py bind-delivery <module> --instance-id '<build_id>#<n>' \
    --delivery-commit <完整签名提交 SHA> --tag <模块-版本> --by 维护者
```

交付条目保存实例身份、指纹、产物哈希、交付 commit、标签、签名结果、绑定人/时间。
绑定入口、门禁与 delivery 核验共用判据：

- 绑定的 source_commit、build_id、instance_id、指纹与产物哈希必须与实例一致。
- 源码提交为交付提交祖先，交付提交的模块树与各共享构建输入仍与候选相同。
- `signature_verified` 必须是布尔 true，并重新运行 `git verify-commit`；字段本身不能代替签名验证。
- 标签存在时必须指向交付提交；本仓库交付另由维护者核验签名标签。
- 同一实例的所有交付绑定都需校验；探索实例不可交付。

签名验证需要配置可信签署者（SSH 签名使用 `gpg.ssh.allowedSignersFile`）。没有可信配置或签名验证失败即停止交付。
交付绑定在交付 commit 之后产生，由后续签名记录提交保存；完整顺序见 [03-round-flow.md](03-round-flow.md)。

## 版本与产物目录

当前版本声明由维护者核对模块 Makefile、模块 README、元数据与发布说明；历史产物的内嵌版本按其所属构建核对。

```text
artifacts/<build_id>/          第 1 次实例
artifacts/<build_id>#2/        第 2 次实例
    <产物>.kpm
    <产物>.kpm.json           静态基线变体的布局（随实例归档，不改 MANIFEST.json）
    MANIFEST.json             写入一次的构建清单
local/                        日志、锁、隔离工作区、临时证据；不入库
```

使用实例记录中的 `artifacts[].path` 定位字节。`.kpm` 在交付包或 release 分发，仓库保存身份记录与可重建源码。

**静态基线布局的归档约定**：`baselines` 变体的 `.kpm.json` 由 `LAYOUT_DIR` 输出，它属于该实例的交付证据，
不是可丢弃的中间产物。

- 构建期 `LAYOUT_DIR` 必须指向模块目录之外（`.json` 被统一构建入口计为构建输入，写进模块目录会在构建期间新增输入，
  触发「构建期间构建输入发生变化」而拒绝登记）；默认落在模块目录的写法只适用于不入库的探索。
- 归档期必须把布局 JSON 复制进该实例的 `artifacts/<instance_id>/`，与 `.kpm` 同目录，**不覆盖**已封存的
  `MANIFEST.json` 与既有字节。
- 登记期由维护者在 `maintainer_records[].baseline_layouts` 记录 `instance_id`、归档 `path`、文件 `sha256`/`size`
  与布局内嵌的 `kpm_sha256`。布局内嵌目标 `.kpm` 的 SHA-256，是它与实例对应的独立判据。
- 布局缺失或与实例哈希不对应时，该实例的静态移植能力视为未覆盖，不得由其它变体的布局代填。
