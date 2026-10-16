# DEV-033 实机报告追加更正与补测元数据提案

依据 [`Developer/reports/2026-10-13-nomount-round-followup.md`](../../../Developer/reports/2026-10-13-nomount-round-followup.md) 与维护者请求 [`docs/records/2026-10-13-nomount-0.1.0-cfi-evidence-request.md`](../../../docs/records/2026-10-13-nomount-0.1.0-cfi-evidence-request.md)。

Tester 已在以下两份实机报告尾部追加第 6 节更正与现场补测记录，并在 [`Tester/reports/responses/2026-10-13-DEV-033.md`](../../reports/responses/2026-10-13-DEV-033.md) 出具修复响应：
1. [`Tester/reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#1.md`](../../reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#1.md)
2. [`Tester/reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#2.md`](../../reports/runs/2026-10-13-nomount-0.1.0-4.19-boot-live#2.md)

本目录 [report_versions.json](report_versions.json) 提供结构化版本追加条目，供维护者在核对 Tester 检查点提交后，同步追加至 `metadata/modules/nomount.json` 的 `report_versions`。

- 报告 #1：
  - 原入库基线：`db2e02b077302caef00cac0b9fe4249f862285c9b024751b12c99b9eed5dbc4c`（8,582 字节）
  - 追加段哈希：`f3e42153673b81fadabb0e92458c36aa2460a0e278c26e926f3256dd09847398`（4,748 字节）
  - 新整份哈希：`a53902b45302d9738177ce0c48115ccb7a2f09e4073c40eeb2749005208c6c2d`（13,330 字节）
  - 字节前缀匹配：`True`（基线前缀完全保持）

- 报告 #2：
  - 原入库基线：`0b8f5d4b2de5dc36621713cd7d73a306ae8fdc281e7abeff7c1161d445d1b71b`（8,491 字节）
  - 追加段哈希：`f17fde477a81e887f8eb467cc2aabb25ec002875ff00750506b696e2472757c0`（4,750 字节）
  - 新整份哈希：`6c7855fa0c1785c0bd5c4d7433b89f997bfec02f142df45f5a54f0d02ca69200`（13,241 字节）
  - 字节前缀匹配：`True`（基线前缀完全保持）

Tester 严格遵循所有权规则，不直接改写他人拥有的元数据结论或提交 `metadata/` 文件。
