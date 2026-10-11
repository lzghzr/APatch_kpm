# Developer（实现方）

Developer 拥有「让功能在目标内核上跑起来」的全部工作：内核分析、结构体偏移推导、模块代码、构建器、自检。

- 手册：`docs/process/developer-handbook.md`
- 偏移方法论（必读）：`.agents/skills/kernel-offset-derivation/SKILL.md`
- KPM 编码规范：`.agents/skills/kpm-development/SKILL.md`
- 测试基准守则（必读）：`.agents/skills/respect-the-oracle/SKILL.md`
- 开发报告模板：`docs/templates/developer-report.md`

## 偏移获取的默认范围（2026-10-09）

后续 Android 内核偏移开发按使用者确认的范围推进：

- **4.4～5.10**：从函数入口的固定小窗口推导偏移；目标提供可用 BTF 时优先使用 BTF。
- **5.15 及以上**：默认从目标 BTF 获取类型、成员偏移与尺寸，函数推导的新增适配不包含这些版本。
- BTF 数据、必要类型或运行时查询接口缺失时，记录具体缺项，按目标镜像另行分析。版本范围用于安排适配工作，实际偏移仍由目标证据取得。

已有回归用例继续保留；新增适配范围与历史验证覆盖分别记录。

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
make -C re_kernel all debug                                   # 构建 static/dynamic 及各自 debug
cd kernel_img/offset_harness
python3 extract_kernel.py                                     # img -> local/extracted/<标签>/Image
python3 run.py                                                # 全镜像偏移矩阵（自检）
python3 tools/identity.py manifest re_kernel --toolchain ndk26.3.11579264
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

## 模块偏移模式默认规范

有结构体偏移依赖的模块默认提供 static / dynamic 两种编译产物，共用业务代码，定义 `CONFIG_KPM_BASELINES` 选择静态基线，未定义时使用动态推导。普通版名称为 `<模块>_<版本>_baselines.kpm`、`<模块>_<版本>.kpm`；debug 版增加 `_debug`。模块信息记录 `offset_mode`，两种产物保留同一管理名称，每次选择一种加载。

static 的偏移表须可通过二进制替换，并生成同名 `.kpm.json`；dynamic 的偏移表在加载时填写，优先使用 BTF，再使用目标支持的固定小窗口推导。已经取得 BTF 但必要类型或布局不符合时停止加载。没有偏移依赖的模块继续生成通用 KPM。

当前接入模块为 rek（`re_kernel`）、rekx（`re_kernel_x`）与 run_cmd（`run_cmd_demo`）。各模块在自己的 Makefile 中维护构建规则，其他模块逐个接入；引用的共用源码须登记为构建额外输入。Releases 发布两种普通版及静态 JSON，debug 留在 artifacts；维护者拥有的 Actions 和门禁调整以补丁建议交接。

各模块独立维护偏移表与推导实现，rek/rekx 使用 `re_offsets.c`，run_cmd 使用 `rc_offsets.c`。仓库根目录的 `patch_offsets.py` 生成和替换静态偏移表：schema 1/2 用于既有 Binder 调用配置，schema 3 用于普通偏移表。生成布局 JSON 时通过 `--source` 指定本模块的表定义；构建时须通过 `--extra-input patch_offsets.py` 捕获该工具。

## 公共 BTF 查询

`kpm_utils.h` 提供 `kpm_btf_type/member/offset/enum`。模块取得有效 BTF 及四个原生查询函数后初始化 `struct kpm_btf`，随后按自己的字段清单读取目标布局。嵌套成员支持点分路径和匿名 struct/union，返回 bit 偏移、位域宽度及类型尺寸；字节偏移入口拒绝位域或非整字节字段。字段清单、配置表的存储范围和函数 ABI 判定留在模块内。实现和自检见 [公共 BTF 与偏移组织记录](reports/2026-10-10-rek-shared-offsets.md)。

## 模块文件职责

rek、rekx 的自有常量与协议放 `re_kernel.h`，内核定义放 `re_structs.h`，KP 风格封装放 `re_utils.h`；`struct struct_offset`、配置表、访问函数和推导放 `re_offsets.c`。通用实现以 rekx 为准核对，模块分别维护自己的协议及业务扩展。见 [头文件职责核对记录](reports/2026-10-10-rek-headers.md)。
