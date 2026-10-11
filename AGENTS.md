# AGENTS.md — 本仓库的工作规则

本仓库（APatch_kpm）采用**三方角色交付流程**：Developer 实现、Auditor 独立审计、Tester 真机测试、维护者验收与签名交付。
流程全文见 [docs/README.md](docs/README.md)。

## 动手前的第一步

1. 读 [docs/README.md](docs/README.md) 与 [docs/process/02-roles.md](docs/process/02-roles.md)，确认自己这一轮扮演哪个角色。
2. 只改自己拥有的路径（所有权表见 [docs/process/02-roles.md](docs/process/02-roles.md)）。
3. 结论必须绑定身份三要素：**完整 commit + instance_id（Build ID + 实例号）+ 产物 SHA-256**（见 [docs/process/01-identity.md](docs/process/01-identity.md)）。

## 每个角色的一句话职责

| 角色 | 一句话 |
| --- | --- |
| Developer | 分析目标内核、推导/验证结构体偏移、写代码、移植功能，产出**可复现的候选**与自检报告（自检不是结论） |
| Auditor | 用自己的工具独立重编译/重解析/重构造，检查代码风格，做静态测试、边界扫描与安全评估，产出**绑定身份的审计结论与问题单** |
| Tester | 在真机上跑端到端，记录判据、计数、环境事实与未覆盖清单 |
| 维护者 | 元数据、统一文档、版本一致性，复算身份哈希后验收并签名交付 |

## 目标镜像（`kernel_img/`）

需求里点名了镜像（如"为 `B2N-416G_boot.img` 移植 `dont_kill_freeze`"）→ **只处理那一个**：

```bash
cd kernel_img/offset_harness
python3 extract_kernel.py --list                       # 先看有什么：文件名 → 标签
python3 extract_kernel.py --image B2N-416G_boot.img    # 只提取它（也认标签/子串：--image 4.14）
python3 run.py --image B2N-416G_boot.img               # 只对它跑偏移推导
```

- 没点名而 `kernel_img/` 下有**多个**镜像时：**先把候选列出来问用户要用哪一个**（`--list` 的输出就是候选），
  不要默认"全跑一遍"或自己挑一个。只有做全量回归时才不加选择器。
- 选择器支持文件名、去扩展名的 stem、标签（`4.14/4.14.356-Liberty`）、以及大小写不敏感子串；
  匹配到多个会报错并列出候选（`--pick` 可在 TTY 下交互挑一个）。

## 硬规则（违反即返工）

- **不替别人写结论**：发现问题交回对应角色修复；修复者不能自己关闭问题单（由发现方复核关闭）。
  关闭者必须独立于归属方（门禁强制 `closed_by != owner`），`DEV-*` 自检问题也要另一位角色复核。
- **身份只追加**：构建登记只追加 `builds[]` 与登记人/时间（Developer 通过统一候选构建入口运行；直接 `record` 用于探索）；旧构建记录、已归档产物与
  `MANIFEST.json` 一律不可覆盖。Developer 也可以 `--handoff` 只产清单，由维护者 `import-manifest` 导入。
  核验按记录绑定的 `source_commit`（`verify`），不要用当前工作树。
- **严重度按影响定级**，频率与置信度分别记 `frequency`/`confidence`；确认可致崩溃/提权的问题不许因为"不知道频率"而降级。
- **交接必须从冻结提交构建**：探索期允许脏树，候选交接用冻结提交或 `git worktree add ../<repo>-dev <sha>`；
  构建候选统一走 `python3 tools/build_candidate.py <module> --toolchain TAG --target "all debug"`
  （冻结输入 → 移走旧产物 → 构建 → 复核输入未变 → 登记）；脏树会被拒，只能 `--allow-dirty` 记为 exploration。
- **核验要按档位**：`identity.py verify --profile candidate`（候选）/`delivery`（交付）要求指纹可重算、
  参数已捕获、干净提交、产物一致；只检查字段存在不算核验。
- **问题单范围**：未交接的普通编译错误进开发记录即可；安全、已交接候选、跨角色发现、回归失败必须开正式单并独立复核。
- **不共享结论来源**：Auditor 不得调用 `kernel_img/offset_harness`、`tools/identity.py` 等实现方/维护方脚本作为审计依据；必须自解析产物字节。审计报告要声明同源风险。
- **不猜偏移**：偏移推导失败就走降级或报错，禁止按内核版本号分支、禁止猜一个偏移硬上。
- **真机不可靠，死机不自救**：测试中遇到死机/卡死/无响应，**立即停止一切重试**，按 [docs/process/07-escalation-device.md](docs/process/07-escalation-device.md) 采集证据并**通知维护者**。禁止自行改偏移、反复加载、反复重启。
- **产不可覆盖**：同一 Build ID 的产物不得重建覆盖；重建使用新的空输出目录并产生新 Build ID。
- **公开文件不写本机信息**：不写本机绝对路径、设备序列号、superkey、抓包内容（测试报告用设备指纹哈希代替序列号）。
- **遵守测试 Oracle 与防反向过拟合**：基准测试套件视为只读 Oracle。严禁为了通过测试而私自修改、弱化或删除已有断言；严禁为了迁就宿主单测/Mock 而扭曲生产代码架构；确需变更断言时必须在报告中单独说明技术依据并由 Auditor 独立复核（详见 [.agents/skills/respect-the-oracle/SKILL.md](.agents/skills/respect-the-oracle/SKILL.md)）。
- **不为了过门禁而放宽断言**：断言、用例、检查范围的任何缩小都要在报告中写明并给出理由。

## KPM 偏移模式默认规范

有结构体偏移依赖的模块默认提供 static / dynamic 两种编译产物，共用业务实现，定义 `CONFIG_KPM_BASELINES` 选择静态基线，未定义时使用动态推导。静态版附带可替换偏移表及同名 `.kpm.json`；动态版加载时优先使用 BTF，再使用目标支持的固定小窗口推导。必要字段或共同布局无法确认时停止加载，不按版本号猜偏移。

普通产物命名为 `<模块>_<版本>_baselines.kpm`、`<模块>_<版本>.kpm`，debug 增加 `_debug`，元信息记录 `offset_mode`。Releases 发布两种普通版与静态 JSON；debug 保留在 artifacts。同一模块的两种模式保留同一管理名称，每次选择一种加载。无偏移依赖的模块继续生成通用 KPM。

当前接入 rek / rekx / run_cmd，其他模块逐个接入，各模块在自己的 Makefile 中维护构建规则，额外输入规则见 `Developer/README.md`。Android 4.4～5.10 是函数推导新增适配范围，5.15 及以上默认使用 BTF；该范围用于安排工作，偏移仍由目标证据取得。

## 常用入口

```bash
cd kernel_img/offset_harness && python3 extract_kernel.py --list                # Developer：先看 kernel_img/ 里有什么
cd kernel_img/offset_harness && python3 extract_kernel.py --image <名字> && python3 run.py --image <名字>   # 指定镜像：img -> 裸 kernel -> 偏移矩阵（输出在 local/kernel_offset）
make -C re_kernel all debug                        # Developer：探索构建（需 NDK）
python3 tools/identity.py manifest re_kernel       # Developer/维护者：源树哈希、Build ID 与配方指纹
python3 tools/build_candidate.py re_kernel --toolchain ndk26.3.11579264 --target "all debug"   # 冻结输入→构建→登记（脏树拒绝）
python3 tools/selftest_tools.py                    # 工具判据自检（历轮发现的漂移回归）
python3 tools/freeze_check.py                      # 冻结就绪检查（无干净提交则 Auditor/Tester 无法绑定身份）
python3 tools/check_repository.py                  # 门禁（结构/链接/身份/版本一致性/卫生）
python3 tools/check_repository.py --strict         # 维护者验收：产物必须在场且哈希可复算
python3 Auditor/tools/artifact_audit.py --module re_kernel    # Auditor：独立产物审计
python3 Auditor/tools/static_scan.py re_kernel                 # Auditor：边界/安全静态扫描（启发式）
bash Tester/tools/preflight.sh                     # Tester：真机预检（设备身份/环境事实）
bash Tester/tools/run_test.sh --kpm <path>         # Tester：带看门狗的真机测试（失败退出码 90 = 设备无响应，走升级）
```
