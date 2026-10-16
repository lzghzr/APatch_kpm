# NoMount 证据分层本轮试行

角色：维护者。用户已批准本轮试行[分层提案](2026-10-16-evidence-storage-proposal.md)。本轮先完成并行归档和恢复对照，原始角色文件与既有门禁继续保留；封包工具及转移契约需经独立复核后，才进入移出交付树的阶段。

## 契约与范围

- `tools/evidence_archive.py` 从明确的冻结提交收集本模块角色报告、提案、元数据精确引用的文本与登记的历史报告版本；读取一次 `git cat-file --batch`，不逐文件启动 Git 进程。
- 相同文件字节按 SHA-256 去重。封包保留原字节、相对路径、文件权限、完整提交、Git blob 身份、逐文件 SHA-256、长度及原报告版本链。
- 清单在包内，清单哈希和包哈希在独立索引中；包落在忽略的 `artifacts/evidence/<包哈希>/`，索引入库。固定 gzip 时间戳和 tar 元信息，使相同输入产生相同字节；既有封包和索引不覆盖。
- 包中带所需的原始 Git commit 与路径层级的 tree 对象。验包可离线重算 Git 对象身份，并沿 commit → tree → blob 确认文件确属于登记提交及路径，避免仅自报一个 source_commit。
- 路径树证明只证明选中文件的归属，不是完整 Git 仓库备份，也不证明作者身份、实测执行或全部候选源码已归档。现有冻结源码对象、产物归档及原始现场继续保留。
- 验包拒绝缺包、包/清单/成员哈希不符、长度不符、缺项、重复项、额外成员、路径穿越、符号链接、伪造的 Git 路径、报告版本或追加段不匹配；恢复仅写新的独占目录。
- `parallel-trial` 模式还要求当前角色原件与包内快照逐字节一致。当前不支持删除原件后仅凭链接通过门禁。

## 门禁与自检

归档声明记录在模块 `evidence_archives[]`，由既有 `report_integrity` 条目核验；缺包在常规与 strict 模式都失败。其余报告、身份、验收、签名与产物检查保持原判据。

`tools/selftest_evidence_archive.py` 使用独立临时仓库与合成报告，测试确定性、历史原文恢复、拒绝覆盖和损坏反例；通过 `tools/selftest_tools.py` 接入现有工具自检。没有删除或放宽原有断言，不接触设备。

## 操作入口

```bash
python3 tools/evidence_archive.py pack --module nomount --commit <冻结提交> --reference metadata/evidence/<本轮索引>.json
python3 tools/evidence_archive.py verify --reference metadata/evidence/<本轮索引>.json
python3 tools/evidence_archive.py restore --reference metadata/evidence/<本轮索引>.json --output <新的恢复目录>
```

本轮不上传附件、不复制私有原始现场。原始 commit/tree 对象及历史报告可能包含当前树扫描范围之外的信息，公开附件前需对包内完整成员做卫生复核，不能把当前树脱敏通过当成历史包可公开的证明。

## 独立复核请求

请 Developer 或 Auditor 独立检查封包/验包实现、Git 路径证明、恶意包拒绝、版本前缀及原件恢复的一致性；复核记录归原角色，维护者不代写。正式移出 Git 的清单与覆盖契约在独立复核后确定，历史冻结对象与旧身份保持可恢复。

试行索引、实测体积、恢复与门禁比较结果在冻结运行后追加。

## 本轮实测

冻结快照：`6d538d4b44d8065c35d01c1f8cab4a95c3308f88`。

- [封包索引](../../metadata/evidence/nomount-20261016-trial-01.json)：405 个文件版本，344 组唯一文件字节；含登记的历史报告原文与 commit/tree 路径证明。
- 展开成员总量 22,696,226 字节（21.64 MiB），gzip 包 2,993,544 字节（2.85 MiB）；这是证据封包比例，不是源码仓库实际缩减量。
- 包 SHA-256：`f65273516ac3384559bcccfc333d4632800c3c38f08fd4e82165261cf69b90f1`。
- 清单 SHA-256：`6afa01e6ec745e4a0edc0917a5e43ff90e1c699f9ba6b53dc89474b5332938c3`。
- 恢复至新的本地目录后，405 个版本逐字节吻合；[试行回执](../../metadata/evidence/nomount-20261016-trial-01.receipt.json)登记工具身份和结果。
- 归档自检 28/28 正反用例通过；包内文件及 Git 证明按现有卫生模式扫描为 0 命中，该扫描不代替完整人工审阅。
- 当前仍保留原件，源码仓库删除文件数为 0；包未上传，独立复核未完成。

## 门禁前后对照

使用 `799fc07` 的旧 gate 代码与本轮新 gate 在同一当前树、同一工具自检和证据状态上运行 strict：两者均 14 项、0 失败、2 项警告，失败与警告集合一致。单次测得旧入口 12.722 秒、新入口 13.362 秒；仅记录本次成本，不外推为稳定性能。工具自检 36/36，通过新增归档组内的 28 项正反用例。

[对照回执与工具身份](../../metadata/evidence/nomount-20261016-trial-01.gate.json)。现有两个警告仍为 developer_artifacts 与 handoff_registration。相对 Developer 复核基线，角色报告、生产代码及既有构建/审计/测试/验收/派生记录未改写。DEV-043 已按 Developer 独立确认关闭。

## 后续处置：按用户决定取消

同组证据对象的 Git pack 实测 1,836,965 字节，完整封包为 2,993,544 字节。用户据此取消封包路线：撤回活动声明、工具与附加自检，报告继续保留在 Git；已有原件、身份及试行回执保留。[新生成数据复用](2026-10-16-generated-data-reuse.md)作为后续优化方向。原文为试行时记录，本节为当前状态。
