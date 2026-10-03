# 交接包模板

角色之间（Developer → Auditor → Tester → 维护者）交接时使用。交接包是**索引**，不是结论：列出对象、身份、证据位置与未决事项。

```text
交接：<from 角色> → <to 角色>
模块 / 版本：<module> <version>
对象：commit <sha> + instance_id <build_id>#<n> + 产物 <文件名> sha256=<64 hex>
源树哈希：<source_tree_sha256>
工具链：<toolchain_tag>
KernelPatch：<submodule sha>
```

## 本轮范围

- 做了什么：
- 未覆盖项及原因：

## 证据位置

| 内容 | 路径 |
| --- | --- |
| 开发报告 | `Developer/reports/<文件>` |
| 审计报告 | `Auditor/reports/<文件>` |
| 实机报告 | `Tester/reports/runs/<文件>` |
| 环境事实 | `Tester/reports/environments/<文件>` |
| 升级单 | `Tester/reports/escalations/<文件>`（如有） |
| 身份记录 | `metadata/modules/<module>.json` |
| 归档报告 | `artifacts/<build_id>/` |

## 未决事项

| 编号 | 内容 | 状态 | 期望接收方做什么 |
| --- | --- | --- | --- |
| | | | |

## 接收方须知

- 已知可疑点：
- 复现命令：
- 不要做的事（例如「不要再加载这个 build」）：
