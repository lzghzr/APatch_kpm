# Developer 请求：zram_zstd 的 4.4 legacy-kp 在册候选（2026-10-10）

> **【已作废 · 2026-10-11】** 用户明确要求「完全按最新版 KP 构建，源码与 Makefile 不含任何低版本兼容内容，兼容只在二进制 KPM 上做修改」。本文关于「Makefile 增加 legacy 目标 / 转换必须落在构建事务内 / 不得先 make 再转接」的要求与之冲突，**不再对 Developer 有约束力**；请以 [纯净构建 + 二进制适配](2026-10-11-clean-build-binary-adaptation.md) 为准。

角色：维护者。本文是**请求**，不含实现结论。请求依据：用户决定「4.4 需要可交付产物 → 由 Developer 产出在册
legacy 候选后由 Tester 按在册哈希复测」；legacy 形态**只随 artifacts 交付、不进 Releases**。
相关问题单：[`MNT-015`](../../metadata/modules/zram_zstd.json)（中，`owner=Developer`，`open`）。
规则依据：[AGENTS.md](../../AGENTS.md) 的「旧 KP（legacy）形态」段与
[metadata/identity.json](../../metadata/identity.json) 的 `kp_compat_rule`。

## 一、背景（为什么必需）

- KernelPatch `0.13.9` **不兼容 4.4 内核**；4.4 上只能运行旧 KP（测试机实测 `d04`，按编码 0.13.4）。
- 旧 KP 未导出 `kallsyms_lookup_name_by_suffix`，模块加载即报 `unknown symbol`；
  经 `patch_offsets.py legacy-kp` 转接后可加载（Tester 已在 `b754dad7` 上实测通过 9 项强判据）。
- 该派生件目前**未登记**，导致设备证据无法绑定在册身份；且转接工具仍是工作树探索状态，
  历史上曾因「只改导入名称、把直接调用指向函数指针变量的数据地址」在同一台 4.4 设备上造成一次内核 Oops。

## 二、请求产出（新的独立实例）

以修复冻结源码 `a5e1615bdb715257b167483e3e3a6f019b4a15f0` 为源，产出 **legacy 形态候选**：

| 变体 | 建议命名 | 说明 |
| --- | --- | --- |
| `base`（动态）legacy | `zram_zstd_0.1.0_legacy.kpm` | 4.4 上实际使用的形态 |
| `debug`（动态）legacy | `zram_zstd_0.1.0_legacy_debug.kpm` | 建议一并产出，便于对照 |

静态基线（`baselines`）形态是否同时转接由 Developer 判断：其五项偏移仍为模板 `-1`、当前不可加载，
若产出请附带对应 `.kpm.json` 布局。

## 三、硬性要求

1. **受控构建**：必须经统一候选构建入口（`tools/build_candidate.py zram_zstd --toolchain ndk26.3.11579264
   --target "..."`）完成，使转换步骤落在**构建事务**覆盖范围内：
   - `patch_offsets.py` 与转换命令（`legacy-kp`）必须计入**构建输入与配方指纹**（参考 `--extra-input`）；
   - 构建前后输入集合必须一致、`captured=true`、`returncode=0`，产物归档到 `artifacts/<新 instance_id>/`；
   - 实现方式（Makefile 增加 legacy 目标，或构建入口支持后处理步骤）由 Developer 决定，但**不得**用「先 make 再手工转接再 `record`」绕过事务。
2. **自检回执**：除模块自身宿主自检外，必须提供 legacy 转换的自检回执（JSON），且**覆盖历史 Oops 的契约**：
   - 正例：含 suffix 导入且需要原名指针导入的模块 → 转接后直接调用指向**函数指针变量**、经其取值调用；
   - 反例：不含 suffix 导入、或符号表结构异常 → 工具应明确拒绝（`ValueError`），不得产出可疑二进制；
   - 断言现有 Oracle 未被弱化（`respect-the-oracle`）。
3. **自识别**：产物内嵌元信息应能区分形态（例如 description 标注 legacy，或新增字段）；元数据侧由维护者登记
   `kp_compat=legacy`。
4. **不覆盖既有**：初始候选与修复候选的产物、`MANIFEST.json`、已冻结资产一律不动；新实例用新输出目录。
5. **CI/产物门禁**：若 CI 会构建该变体，请确认 `tools/artifact_gate.py` 对 `_legacy` 命名与新增元信息字段的接受规则；
   如需门禁调整，按流程提交补丁建议给维护者（`tools/` 归维护者）。

## 四、交接与后续

- 交接：`--handoff Developer/reports/handoffs/<唯一文件名>.json`，维护者 `import-manifest` 导入并逐条 `--profile candidate` 核验；
- 之后由维护者发出**复测请求**：Tester 按**在册 instance_id + 产物哈希**在 4.4 设备上复测（`incremental` 档，
  范围=该 legacy 候选；判据复用本轮已通过的 9 项强判据，**仍严禁 `module unload`**，遵守 `RA-001`）；
- 复测通过且 `MNT-015` 关闭后，维护者再做验收与签名交付。

## 五、参考身份（本轮实测所依据的在册实例）

| 变体 | instance_id | 在册产物 SHA-256 |
| --- | --- | --- |
| `base` | `zram_zstd-0.1.0+gd464ad07ccb0.r21df036f.kpb51197a.ndk26.3.11579264#1` | `f48f3155f6ada61803ace3cd627772ea595681489f3be6305ac192557f0ab7d2` |
| `debug` | `zram_zstd-0.1.0_debug+gd464ad07ccb0.rf04090a6.kpb51197a.ndk26.3.11579264#1` | `2490abcfc0ed4497c3f2e4462c4608de57d46f41e1c5eede349f2b35805d18ad` |

（Tester 实机推送的是由 `debug` 实例经 legacy-kp 转接的派生件 `f6d25190…`（245056 B），非上表字节。）
