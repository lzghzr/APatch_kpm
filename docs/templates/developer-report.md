# 开发报告：<module> <版本>

## 身份

| 项 | 值 |
| --- | --- |
| commit | `<40 位 sha>` |
| KernelPatch commit | `<submodule sha>` |
| Build ID / instance_id | `<build_id>#<n>` |
| 配方指纹 | `<fingerprint_sha256>` |
| 构建事务 | `tools/build_candidate.py` 的记录与日志摘要 |
| 工具链 | `<编译器与版本>` |
| 产物 | `<文件名>` `sha256=<64 hex>` `size=<bytes>` |

## 变更点

- 目标内核范围：
- 改了哪些 hook 点 / 偏移字段 / 数据结构：
- 为什么这样改：
- 本轮覆盖范围与未覆盖原因：

## 自检

```text
<命令 1>
<输出摘要>
```

- 构建：`make -C <module> ...`（警告变化：新增 <n> 条，均为 <说明>）
- 离线镜像回归：`cd kernel_img/offset_harness && python3 extract_kernel.py --image <目标镜像> && python3 run.py --image <目标镜像>`（PASS <n>/<m>，SKIP/FAIL <列表与原因>）
- 代码走查结论：

## 边界声明

> 本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），**不是独立审计，也不是实机结论**。
> 跨版本正确性、权限与生命周期安全、真机可用性分别由 Auditor 与 Tester 出具。

## 未解决项与降级行为

| 项 | 影响内核 | 当前行为 |
| --- | --- | --- |
| | | 降级为 <安全默认值> / 跳过该功能 |

## 已知可疑点（请 Auditor 重点看）

- 
