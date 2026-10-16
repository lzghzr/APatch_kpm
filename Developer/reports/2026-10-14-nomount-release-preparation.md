# NoMount 2.1.1-20261014 发布准备

版本以冻结上游的 2.1.1 加本轮日期，与 rek/rekx 的格式一致。KPM 保持 NoMount 注册名，配套显示名为 NoMount-kpm，ZIP 文件为 `NoMount-kpm_2.1.1-20261014.zip`。安装 ID 和控制类型保持 nomount，可覆盖已有安装。上游 gitlink 仍为 `7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`，本轮未更新内核业务实现。

两份用户 README 统一为用途、选择文件、安装、使用／更新及简短更新记录。构建约定、身份和验证细节保留在 AGENTS／本报告。

## 发布候选身份

source_commit：`e9ab619ea75e7fd611c28dcc0328dbb99ebf1dfb`。工具链 `ndk26.3.11579264`，KernelPatch `b51197aaba8f2272dd8a3e30c85698a29aa928c9`。

| instance_id | SHA-256 |
| --- | --- |
| `nomount-2.1.1-20261014+gba09058a01e9.r72c71e2f.kpb51197a.ndk26.3.11579264#1` | `d78b11a936b7781909118a66bdc104cee2925b5db8d6288c9137e08d1e7f41c0` |
| `nomount-2.1.1-20261014_baselines+gba09058a01e9.r6d832369.kpb51197a.ndk26.3.11579264#1` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |

ZIP 实例：`nomount-zip-2.1.1-20261014+g5fbf6fec42ef.ndk26.3.11579264#1`。ZIP SHA-256：`42c5b64458b73dcb202efb2cd6a1a82c604ba3c94698bd1d49085c752b045a44`，大小 80003 字节。

- [KPM 交接清单](handoffs/2026-10-14-nomount-2.1.1-20261014.json)：统一候选构建事务，target=all，从干净冻结提交生成，两个实例均通过 candidate 核验。
- [目标件交接](handoffs/2026-10-14-nomount-2.1.1-20261014-target.json)：复用七份已有配置，8 条记录／6 份唯一字节，含 B2N 可选旧 KP 二进制转换；参数和旧 KP 适配均不进入内核源码或 Makefile。
- [ZIP 构建清单](data/2026-10-14-nomount-2.1.1-20261014-zip.json)：独立实例，冻结输入、编译工具、ZIP 及全部条目哈希。

## 与已完成审计测试的 0.5.2 比较

依据 [Auditor 0.5.2 审计](../../Auditor/reports/2026-10-14-nomount-0.5.2-module-audit.md) 及 [Tester Sony 5.15 报告](../../Tester/reports/runs/2026-10-14-nomount-0.5.2-5.15-boot-live%231.md)，此前 0.5.2 已完成独立审计与 20/20 主判据冒烟；4.4／4.19 按在册轻量差异范围绑定，6.1 无实机覆盖。以下为 Developer 对新发布身份的差异自检，供独立角色复核绑定：

- 内核源码只改 Makefile 和 NM_KPM_VERSION 的版本文字，46 项偏移、VFS／锁／权限／生命周期和协议结构保持原样。
- 两变体 .text 的字节大小、指令数量、指令顺序和助记符一致；每件只有 5 条 cmp/mov 的立即数变化。版本长度由 5 变 14，版本响应长度及状态回复的拷贝／缓冲界限均增加 9。完整差异和节列表在验证数据中，未把它称为 .text 全字节一致。
- .data.re_offsets 完全相同。目标派生 JSON/blob 两种输入相同，恢复基线相同，配置改动限于 92 字节；旧 KP 额外变换限于回执区间。
- 新 ZIP 相对 0.5.2 只有 README.md、customize.sh 的安装标题、module.prop 变化，并增加 CHANGELOG.md。用户态 nm、WebUI、metamount 和规则／权限处理脚本保持逐字节相同。
- 已冻结的所有旧测试脚本保留原样，含首轮发布准备的 7 个发布用例；另追加 3 个更新 JSON 用例。没有修改或弱化已有断言。

## 自动构建与发布

用户本轮明确要求增加 ZIP 自动发布任务，因此同步实现所需工作流配置；正式签名及发布操作仍由维护者执行。

1. Build-on-Ubuntu 沿用 KPM 编译和筛选，上传普通发布副本；debug 仍只留构建产物。
2. Build-NoMount-zip 固定 NDK 26.3.11579264／linux-x86_64，从同次干净提交和冻结 gitlink 编译用户态、打包版本化 ZIP。上传 ZIP 单件，以及清单／哈希身份包。module、tools、README 和子模块输入变化均会触发。
3. Publish-release 依赖两个构建成功。下载后校验各自 SHA256SUMS；合并器核对完整 source_commit 和 NoMount 版本，保留 KPM 清单并追加 companion 引用，复算最终全部资产哈希。
4. 新 Release 先以草稿上传全部文件，上传错误使任务失败，完成后公开。commit 指向 github.sha；allowUpdates=false，已公开标签不做资产覆盖。维护者每轮填写新的发布标签。

版本化 ZIP 附带本轮 CHANGELOG.md。module.prop 的 updateJson 为 `https://github.com/lzghzr/APatch_kpm/releases/latest/download/NoMount-kpm.json`。发布任务从 ZIP 的 version/versionCode/CHANGELOG 生成 NoMount-kpm.json 与 NoMount-kpm-changelog.md，zipUrl 和 changelog 均绑定实际发布标签；versionCode 为整数 20261014。首次发布后该更新入口可用，旧安装需先安装含此入口的新 ZIP。

规范：[KernelSU module.prop](https://kernelsu.org/zh_CN/guide/module.html)、[通用更新 JSON 格式](https://topjohnwu.github.io/Magisk/guides.html)。NDK 安装使用 [SDK Manager 的固定 NDK 包](https://developer.android.com/tools/sdkmanager)；发布草稿／上传顺序依据 [release-action 官方输入](https://github.com/ncipollo/release-action)。

## 自检结果与范围

- ZIP 发布用例 7/7、更新元数据 3/3；原有发布筛选 4/4、偏移模式 9/9、产物门禁 49/49、共享工具 35/35 通过。YAML 解析、任务依赖、源码格式和空白检查通过。
- 两个 KPM 候选及派生件通过真实 ELF、布局、SDK 未定义导入及指令寄存器扫描，未见 FP/SIMD/SVE 或 x18 操作数。编译仅有 SDK 既有 READ_ONCE／WRITE_ONCE 重定义警告。
- 常规仓库门禁 14 项、0 项失败、2 项警告；警告涉及历史交接字段及未登记实例，本轮候选等待维护者追加导入。
- 从工作流提取真实“Verify and combine release assets” shell，用本轮实际 NoMount KPM、ZIP 本地回放，原下载哈希、来源／版本核对、更新 JSON 生成及最终全部文件哈希通过。[预览](data/2026-10-14-nomount-update-preview.json) 的标签只是本地样例，未发布。

完整证据见 [验证数据](data/2026-10-14-nomount-release-preparation.json)。这是 Developer 自检，不是独立审计或新身份的真机结论；本轮未操作设备、未触发远程 Actions、未签名或上传 Release。Linux runner 的端到端执行仍待实际 CI；本地编译主机为 macOS，不能把本地回放称为远程发布成功。

## 复核决定（Decision）

**保留（Retain，按 Modify 意见修正后）**。

### 有效性

实际版本化 ZIP 的属性、来源和更新 JSON 对齐，下载链接指向指定发布标签；实际 KPM/ZIP 合并回放通过。旧安装 ID 不变，现有安装可以覆盖更新。

### 简洁性

复用现有 ZIP 构建器和 KPM 筛选，只增加独立 ZIP 构建、统一发布及一个发布副本工具。更新说明由冻结 README 提取，不维护第二份手写更新日志；更新 JSON 只在正式发布副本生成。

### 后果

只读反例复核发现原有 allowUpdates/replacesArtifacts 在公开 Release 中逐件替换会暴露未就绪 ZIP 的更新入口。最终配置每轮新标签、草稿上传齐后公开，上传失败保持失败。旧测试断言和归档保持原样，版本变更交由独立差异复核后绑定已有证据。

## 维护者交接

[登记补丁](../proposals/2026-10-14-nomount-release/README.md) 仅更新两个当前版本字段；新候选由清单追加导入，旧 0.5.2 审计、测试及验收保持原样。请逐字节复核本轮展示性差异、CI 发布规则及新实例，再按现有流程验收和签名发布。本轮不代写独立角色结论。
