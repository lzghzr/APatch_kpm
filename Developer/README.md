# Developer（实现方）

Developer 拥有「让功能在目标内核上跑起来」的全部工作：内核分析、结构体偏移推导、模块代码、构建器、自检。

- 手册：`docs/process/developer-handbook.md`
- 偏移方法论（必读）：`.agents/skills/kernel-offset-derivation/SKILL.md`
- KPM 编码规范：`.agents/skills/kpm-development/SKILL.md`
- 测试基准守则（必读）：`.agents/skills/respect-the-oracle/SKILL.md`
- 开发报告模板：`docs/templates/developer-report.md`

## 拥有的路径

| 路径 | 说明 |
| --- | --- |
| `re_kernel/`、`hosts_redirect/`、`cgroupv2_freeze/`、`dont_kill_freeze/`、`lmkd_dont_kill/`、`qti_battery_charger/`、`xperia_*/` … | 各模块源码、Makefile、模块 README |
| `kpm_utils.h` | 仓库级共享工具宏（所有模块共用） |
| `kernel_img/offset_harness/` | 离线偏移推导回归 harness：解包 img、推导偏移、输出矩阵（自检用途） |
| `kernel_img/<大版本>/<小版本>/` | 用户放置的原始 img 与符号表（**不入库**） |
| `local/` | 运行产生的本地文件：提取出的裸 kernel、缓存（**不入库**） |
| `Developer/reports/` | 开发报告 |
| `Developer/reports/responses/` | 修复响应（问题编号 + 修复 commit + Build ID + 证据）：模板见 `docs/templates/developer-response.md` |
| `Developer/reports/handoffs/` | 交接清单（`identity.py record --handoff` 产出，维护者 `import-manifest` 导入） |

## 常用命令

```bash
make -C re_kernel all debug                                   # 构建四个变体
cd kernel_img/offset_harness
python3 extract_kernel.py                                     # img -> local/extracted/<标签>/Image
python3 run.py                                                # 全镜像偏移矩阵（自检）
python3 tools/identity.py manifest re_kernel --variant network_debug --toolchain ndk26.3.11579264
python3 tools/identity.py record re_kernel --toolchain ndk26.3.11579264
```

## 边界声明（每份开发报告都要写）

> 本轮结论来自实现方自检（构建 + 离线语料 + 代码走查），**不是独立审计，也不是实机结论**。
> 跨版本正确性、权限与生命周期安全、真机可用性分别由 Auditor 与 Tester 出具。

## 交接与授权（2026-10-02 维护者批复）

- `tools/identity.py record` 只**追加 `builds[]`**，Developer 可以直接运行（不会碰 `status`/`audits`/`issues`）；
  也可以 `--handoff` 只产出清单，交给维护者 `import-manifest` 导入。
- 探索阶段允许工作树不干净；**交接候选必须从冻结提交构建**（推荐 `git worktree add ../APatch_kpm-dev <sha>`），
  产物归档到 `artifacts/<build_id>[#n]/`，封存后不可覆盖。
- 修复别人开的问题单后，在 `Developer/reports/responses/` 写修复响应并把问题单置 `fixed(待复核)`；
  由发现方复核关闭（`DEV-*` 自检问题也需另一位角色复核）。
- 需要改别人的文件时，提补丁建议（`git format-patch`/diff + 说明）给所有者落地。

## 与审计有关的注意事项

- `kernel_img/offset_harness` 与设备上的 C 代码同源：它能证明「移植一致」，不能证明「推导正确」。审计会用独立工具重解析产物字节。
- 自检发现的问题请自己开 `DEV-xxx` 单；Auditor 发现的 `AUD-xxx` / Tester 发现的 `TST-xxx` 由发现方复核关闭，修复者只能置为 `fixed(待复核)`。
- 改动实现、参数或工具链 → 新的 Build ID 与新的 commit；旧产物保留，不覆盖。
