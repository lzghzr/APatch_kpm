# APatch_kpm 三方角色交付流程

本目录是仓库的标准交付流程。目标：让「改动是否真的可用」不由实现者自证，而由**独立证据**与**不可变身份**支撑。

- 角色分工与所有权：[process/02-roles.md](process/02-roles.md)
- 身份：三要素（commit + Build ID + 产物 SHA-256）+ 配方指纹 + 构建实例 + 只追加规则：[process/01-identity.md](process/01-identity.md)
- 一轮完整流程（含本仓库实际命令）：[process/03-round-flow.md](process/03-round-flow.md)
- 问题单格式与关闭规则：[process/04-issue-ticket.md](process/04-issue-ticket.md)
- 维护者验收清单与签名交付：[process/05-maintainer-acceptance.md](process/05-maintainer-acceptance.md)
- 反模式：[process/06-antipatterns.md](process/06-antipatterns.md)
- **真机死机/卡死升级流程（Tester 必读）**：[process/07-escalation-device.md](process/07-escalation-device.md)
- 角色手册：[Developer](process/developer-handbook.md) / [Auditor](process/auditor-handbook.md) / [Tester](process/tester-handbook.md)
- 报告与问题单模板：[templates/](templates/)
- 覆盖矩阵（模块 × 内核 × 验证层级）：[coverage.md](coverage.md)

## 角色与产出

| 角色 | 拥有 | 必须产出 |
| --- | --- | --- |
| Developer | 目标内核分析与偏移推导、模块源码、构建器、自检 | 从冻结提交构建的可复现候选（完整 commit + instance_id + 严格指纹 + 产物哈希）+ 开发报告；修复响应放 `Developer/reports/responses/`，交接清单可放 `Developer/reports/handoffs/`；并写明「这不是独立审计或实机结论」 |
| Auditor | 独立工具与审计报告 | 绑定身份的代码风格检查、静态结论、边界扫描与安全评估、带严重度与归属的问题单、覆盖边界与同源风险声明 |
| Tester | 真机测试脚本与实机报告 | 判据、成功/失败计数、环境事实、未覆盖清单；设备异常时按升级流程通知维护者；自有工具修复响应放 `Tester/reports/responses/` |
| 维护者 | 元数据、流程文档、门禁、根目录交付物 | 身份记录、版本一致性、验收结论、签名交付 |

本项目是通用流程在本仓库的落地实现：

- 模块源码与构建器：`re_kernel/`、`hosts_redirect/`、`cgroupv2_freeze/` 等各模块目录（Developer）
- 离线内核镜像与 offset harness：`kernel_img/`（用户放置 img；工具在 `kernel_img/offset_harness/`；提取产物在 `local/`）（Developer）
- 独立审计工具与报告：`Auditor/`（Auditor）
- 真机工具与实机报告：`Tester/`（Tester）
- 身份与归属元数据：`metadata/`（维护者）
- 流程文档与模板：`docs/`（维护者）
- 门禁入口：`python3 tools/check_repository.py`（结构、链接、身份哈希、版本一致性、验收/交付绑定、
  工具判据自检、公开文件卫生）
- 工具判据自检：`python3 tools/selftest_tools.py`（把历轮发现过的判据漂移做成常驻回归）
- 冻结就绪检查：`python3 tools/freeze_check.py`（回答「现在能不能冻结一轮」，并给出签名提交命令）
- **可移植版本**：本流程另有一份与项目解耦的技能文档 `~/.agents/skills/tri-role-delivery-process/SKILL.md`
  （角色分工、身份与实例、授权与边界、问题单格式、判据强度、判据漂移回归、维护者清单、反模式）。
  它使用通用规则；进入项目时先映射该项目的路径所有权、身份字段、工具入口与设备授权；
  两边若出现分叉，**以本仓库 `docs/` 为准**并在技能里同步。

## 一轮的最短闭环

```text
Developer 分析内核 → 推导偏移 → 编码/移植 → 构建候选（commit + instance_id + SHA-256）→ 开发报告
        ↓
Auditor 独立重编译/重解析产物 → 代码风格检查 + 静态测试 + 边界扫描 + 安全评估 → 审计报告 + 问题单
        ↓
Developer 按问题单修复 → 新 Build ID（旧产物保留）
        ↓
Tester 真机预检 → 端到端测试 → 实机报告（异常则走 07 升级流程并通知维护者）
        ↓
维护者 复算哈希 → 核对版本声明 → 更新元数据与覆盖 → 签名提交 → 交付
```

详细步骤、每一步的命令与退出条件见 [process/03-round-flow.md](process/03-round-flow.md)。

## 本地验收门禁

```bash
python3 tools/check_repository.py            # 常规：结构/链接/身份/版本/卫生
python3 tools/check_repository.py --strict   # 验收/发布：另要求产物在场且哈希可复算
```

门禁只检查「可机检的事实」。它不代替审计、不代替实机测试，也不产生交付结论。

## 远程编译与产物门禁

GitHub Actions 的 [Build CI](../.github/workflows/build-kpm.yml) 构建当前提交中有 Makefile 且未归档的模块，随后运行
`python3 tools/artifact_gate.py target --modules target/modules.txt`。检查当次 KPM 的 ELF64/AArch64 可重定位格式、
必需元信息、初始化与退出入口，以及 ReKernel-X 配套布局的产物哈希、ABI、表范围与偏移值。

CI 产物附带 `BUILD_MANIFEST.json` 与 `SHA256SUMS`，记录当次源提交、KernelPatch 提交、文件大小、模块信息及文件哈希。
下载到后续作业后再次核对哈希；发布目录生成与实际发布资产对应的清单。编译或产物检查失败时停止上传和发布。

远程检查范围为当次编译产物。本地验收继续核对历史构建身份、审计与测试报告、问题关闭及签名交付条件。
CI 的编译和字节一致性结果不能外推为设备兼容性或实机结论。

## 与既有项目技能的关系

- 偏移获取方法论见仓库技能 `.agents/skills/kernel-offset-derivation/SKILL.md`（Developer 的偏移分析必须遵循）。
- KPM 编码规范见 `.agents/skills/kpm-development/SKILL.md`。
- 本流程不重复上述内容，只规定「谁来做、用什么证据、结论如何绑定身份」。

## 流程版本与维护记录

当前流程版本为 1.1.0。当前模块登记与审计要求见 [ReKernel-X 1.6 工程记录](records/2026-10-02-re-kernel-x-1.6-registration.md)；问题与历史身份保存在模块元数据中。
