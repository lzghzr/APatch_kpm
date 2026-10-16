# NoMount 当前候选登记与 DEV-044 独立确认

角色：维护者。依据 Auditor 已提交的尾部锚点审计提案与追加更正，补齐当前候选登记。正式签名及发布仍由用户执行。

## 对象

源码提交：`ebad05883bcd6173d5e2a867559aa6bcb3e45810`。

| 实例 | KPM SHA-256 |
| --- | --- |
| `nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264#1` | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` |
| `nomount-2.1.1-20261014_baselines+g9f323cd3deaa.r98bc011c.kpb51197a.ndk26.3.11579264#1` | `b45ea0e0f0dca680fe33430f12b0006ce473c5bf25bb5a3a15a7a96fdba4dc43` |

## 登记

- 采纳 [Auditor 提案](../../Auditor/proposals/2026-10-15-nomount-tail-anchors/README.md)，追加两条审计索引、三份报告及数据的版本索引。
- 逐版读取提交 blob，核对完整哈希、长度、原文前缀与追加段哈希。当前报告与 Auditor 修正提交的 blob 一致；历史验收引用的旧版报告哈希仍在版本链中。
- 沿用用户已批准的 RA-002 常驻约束，显式列入上述两个实例及其 17 条在册派生记录（13 组唯一派生字节）；逐件复算 SHA-256。支持目标与允许操作范围保持既有验收口径。
- 既有构建、验收、测试和旧登记逐项比较保持原样；只追加本轮登记。当前仍是候选阶段，正式交付绑定在签署后追加。

## DEV-044：维护者独立确认关闭

修正提交：`f9336cbe043d400bc2762fc84f5504257b561725`。

依据 [Auditor 追加更正 §8](../../Auditor/reports/2026-10-15-nomount-tail-anchors-audit.md)：

- `192 % 128 = 64`，原整除表述有误；`192 % 64 = 0`。
- 独立读取 `nomount/nm_directory.c`：代理表头为 `aligned(128)`；第二表位移按 `(size + 63U) & ~63U` 计算，192 字节目标得到 192，保证第二表 64 字节对齐。
- 表指针反查减去第二表位移和代理头偏移：`128 + 192 - 192 - 128 = 0`，不要求 192 是 128 的整数倍。
- 维护者重新执行以下宿主夹具，int/bool 两种 ABI 均 PASS；原有 Oracle 未修改。

```bash
python3 nomount/tools/test_proxy_alignment.py --oracle-output local/nomount-memory-20261014-01/contracts-final-01 --output local/session-handoff/proxy-alignment-review-20261016-01
```

宿主复跑回执 SHA-256：`eb8fc2032e8c79e7c86cabfa629c0a252ff21cd9a6af562445e04a10dc92e440`；原始回执保存在本地续接证据中。

采纳 Auditor「更正不影响 5.15 Delta 绑定」的裁定。维护者独立确认范围是算式、代理定义、寻址关系和宿主夹具；目标内核 ABI 与完整 Delta 分析引用 Auditor，真机结论引用 Tester，本次没有新增设备结论。

`DEV-044` 为记录类：Auditor 更正，维护者独立确认关闭，满足 `closed_by != owner`。

## DEV-043：修复待独立复核

当前候选的审计索引、版本链与 RA-002 范围已补齐。维护者为修复归属方，状态登记为 `fixed`，由 Developer 或 Auditor 独立确认后关闭。未签名预览阶段的 `deliveries=[]` 不单独作为缺陷。

报告存储优化另见 [证据分层提案](2026-10-16-evidence-storage-proposal.md)；本轮登记继续使用当前完整证据与现有判据。

## DEV-043 后续独立关闭

Developer 响应提交 `799fc07436538b745864914b96f932f3e49e9601` 已独立逐项复核并确认关闭，原件 SHA-256：`7f50bdd4dca90cec509f69c2864cd305e54ccae8f673a93d18657e4a9a0a9cdb`。维护者据[响应](../../Developer/reports/responses/2026-10-16-DEV-043-044.md)同步为 `closed`，关闭角色记 Developer；原修复记录与提案保留。
