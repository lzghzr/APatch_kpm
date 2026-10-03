# 一轮完整流程

一轮从冻结源码开始，到具体实例的独立证据、维护者验收和签名交付结束。

## 0. 冻结输入

维护者确认本轮范围与文件清单，运行 `python3 tools/freeze_check.py`，处理源码、流程文件和未提交删除项。
冻结提交须包含本轮源码及采用的流程工具。角色后续报告在各自目录追加；候选构建在冻结 commit 的独立工作树执行，
使输入不受共享工作树交流影响。

```bash
git status --short
git rev-parse HEAD
git submodule status
git worktree add ../APatch_kpm-dev <完整冻结 SHA>
```

探索阶段可使用脏树；交接对象必须通过 candidate 核验。角色只能在自己拥有的路径写入，维护者负责签名提交。

## 1. Developer 实现与交接

确认目标镜像与所需字段，按偏移方法论实现和自检。点名镜像只处理指定目标；多镜像且未指定时先列出候选并询问。

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list
python3 extract_kernel.py --image <目标镜像>
python3 run.py --image <目标镜像>
```

无选择器的命令仅用于用户要求的全量回归。harness 的结果作为实现方自检，跨版本正确性由独立审计复核。
构建前回到仓库根，在冻结工作树执行：

```bash
python3 tools/build_candidate.py <module> --toolchain <tag> --target "all debug" \
    --handoff Developer/reports/handoffs/<唯一文件名>.json
# 维护者先建模块元数据，再导入
python3 tools/identity.py import-manifest Developer/reports/handoffs/<唯一文件名>.json
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile candidate
```

交接归档产物、清单与开发报告；报告包含完整 commit、instance_id、产物 SHA-256、输入/参数/工具链和未解决项。
采用 [开发报告模板](../templates/developer-report.md)，标明实现方自检边界。

**退出条件**：构建事务通过，实例已在册，candidate 核验通过，开发报告完整。

## 2. Auditor 独立审计

从相同 commit 在隔离目录用自己的构建命令重编译，自解析产物字节、平台导出符号和内核语料。
`tools/identity.py`、`tools/build_candidate.py`、`kernel_img/offset_harness` 只可用于定位，不作结论来源。

在相同冻结提交上独立检查代码风格，使用项目格式配置并人工复核命名、结构与可读性。报告列出配置哈希、工具版本、命令、文件范围、结果与例外；发现问题交 Developer 修复后复核。具体方法见 [Auditor 手册](auditor-handbook.md)。

```bash
python3 Auditor/tools/kp_symbols_extract.py
python3 Auditor/tools/artifact_audit.py --module <module>
python3 Auditor/tools/static_scan.py <module>
```

报告写明实际审计的实例与字节、独立复现命令、边界/安全覆盖、同源风险和未覆盖原因。
自己的工具缺陷交独立角色复核关闭；实现缺陷交 Developer。

**退出条件**：报告绑定身份，每项结论有证据，正式问题单有归属和独立关闭条件。

## 3. 修复与复核

归属方修复，在自己的响应目录追加问题编号、修复 commit、新实例与证据。维护者同步 `fixed(待复核)`。
独立复核者重跑关闭条件并给出关闭记录，维护者同步元数据；发现方与归属方相同时另指定复核者。
旧实例与旧结论保留，功能/参数变化重新冻结和构建候选。

## 4. Tester 真机验证

维护者在线，先确认 candidate 核验、独立审计和目标用例的风险处置。Tester 对照登记表复算待推送产物哈希，
确认 source_commit 与 instance_id 后才加载；工具自动骨架中的身份和结论须人工核对。

```bash
export SUPERKEY=<本地 superkey>
bash Tester/tools/preflight.sh
bash Tester/tools/run_test.sh --kpm <登记的 artifacts.path> --module <module> \
    --instance-id '<build_id>#<n>' --timeout 120
```

加载前四项基线为 boot_id、uptime、pstore 与当前模块清单。按强/弱证据分别记录量化结果。
退出码 1 记录判据失败，2 记录用法/环境问题，3 停在前置条件检查，90 立即停止重试、采证并通知维护者。
恢复动作见 [异常升级流程](07-escalation-device.md)。报告存入新的运行文件，已有报告与日志保留；
同一天同产物多次运行时 Tester 必须指定新的 `RUNDIR/ESCDIR`，避免自动文件名重用。

无设备或未授权时记录 `not-run`、原因与未覆盖项；该状态限制验收范围。
**退出条件**：实机报告绑定真实字节和脚本身份，判据/计数/环境/未覆盖项完整。

## 5. 维护者验收

按 [验收清单](05-maintainer-acceptance.md) 复算输入、产物和关键证据，确认未决问题的处理与风险接受范围。
将绑定具体实例的验收记录追加到 `acceptances[]`；新记录不覆盖旧验收。

## 6. 签名交付与保存回执

1. 将角色报告、问题状态、验收与覆盖矩阵纳入签名的交付提交 **D**。其模块树与登记的构建输入必须仍与候选一致。
2. 创建指向 D 的签名标签，记录完整 D SHA，核验提交和标签签名。
3. `bind-delivery` 追加指向 D 的交付绑定；实例、源码、指纹、产物、祖先关系和签名均复验通过后才落盘。
4. 针对指定实例执行 delivery 核验与 strict 门禁，保存输出到新的回执位置。
5. 用后续签名的记录提交 **E** 保存绑定与回执索引。E 的父链包含 D；交付标签继续指向 D。
6. 从干净 E 再核验记录，按发布授权推送 D 的标签与包含 E 的分支，并复核主工作副本的对象和标签一致。

```bash
git commit -S -m "<module>: <版本> <交付行为>"    # D；只提交已核对的本轮文件
git tag -s <module>-<版本> <D> -m '<instance_id> / <产物 SHA-256>'
git verify-commit <D>
git verify-tag <module>-<版本>
python3 tools/identity.py bind-delivery <module> --instance-id '<build_id>#<n>' \
    --delivery-commit <D> --tag <module>-<版本> --by 维护者
python3 tools/identity.py verify --module <module> --instance-id '<build_id>#<n>' --profile delivery
python3 tools/check_repository.py --strict
# 核对后仅提交新增绑定和回执索引，签名产生 E，再按发布授权推送
```

绑定引用已存在的 D，记录提交 E 保存该绑定，避免让提交引用自身 SHA 的循环。
签名不可验证则停止发布；未覆盖能力逐项写入交付范围。
