# Tester 手册：真机测试

真机是唯一能给出「功能可用」结论的环境，但它**不可靠**。Tester 的职责是：把不可靠环境里的观察变成**可复核的证据**，并在环境失控时**及时交回维护者**。

## 1. 铁律

1. **一次只加载一个变体**，一次只验证一组判据。
2. **每次加载前必须预检**：预检不通过就停，不带着不稳定设备测试。
3. **任何 `adb` 调用都带超时**（脚本已用看门狗实现）。
4. **死机/卡死 ≠ 继续试**：立即按 [07-escalation-device.md](../process/07-escalation-device.md) 采集证据并通知维护者。
5. **公开报告不写设备序列号/superkey/抓包原文**；序列号只保留 `sha256` 前 8 位。
6. 测试前先保存日志与基线，再按测试方案决定是否清一次 `dmesg`；异常现场保持原样。

## 2. 预检

```bash
export SUPERKEY=<本机 superkey>            # 只放环境变量，不写进提交的文件
bash Tester/tools/preflight.sh             # 输出 Tester/reports/environments/<日期>-<指纹>.md
```

预检采集并记录：

| 事实 | 来源 |
| --- | --- |
| 内核版本 | `uname -r` / `uname -a` |
| 机型（脱敏） | `getprop ro.product.model`、`ro.build.fingerprint` |
| 系统与补丁级别 | `getprop ro.build.version.release`、`ro.build.version.security_patch` |
| APatch/KernelPatch 版本 | `getprop` 与 `truncate <superkey> kpver`（若有） |
| 已加载模块 | `truncate <superkey> module list` |
| SELinux 状态 | `getenforce` |
| 设备稳定性 | `uptime`、`btime`、最近 10 分钟是否有崩溃 |
| 设备指纹哈希 | `sha256(序列号)[:8]`（序列号本身不落盘） |

预检失败（设备离线、superkey 错误、无 `truncate`/`truncate` 不可执行）属于**测试环境问题**，先解决环境，不要进入功能测试。

## 3. 判据与计数

判据必须可量化、可复现。以 `re_kernel` 为例：

| 判据 | 通过条件 | 证据强度 | 计数 |
| --- | --- | --- | --- |
| 设备存活（主判据） | `boot_id` 不变 + `uptime` 单调 + adb 持续响应 | **强** | 1/1 |
| 加载成功 | `module load` 返回码 0 **且** `module list` 出现模块名（正面断言） | 强 | 1/1 |
| 未观察到崩溃特征 | 加载后 60s 内 `dmesg` 无 `BUG:`/`Call trace`/`Kernel panic` | **弱** | 0 命中 |
| 偏移推导成功 | `dmesg` 无推导失败/降级日志（debug 变体） | 弱 | 0 命中 |
| binder 解冻 | 冻结目标 App 后触发 binder 事务，目标被解冻（`/proc/<pid>/stat` 状态变化） | 强 | N/M 次 |
| `/proc/rekernel` | 出现且内容为 netlink unit 号 | 强 | 1/1 |
| netlink 上报 | 打开 netlink 单元后收到 `type=Binder/target=` 消息 | 强 | N/M 条 |
| 卸载干净 | `module unload` 返回 0 **且** `module list` 不含模块，随后 60s 设备存活 | 强 | 1/1 |

**新增功能必须同时给出新判据**，不能用「看起来正常」代替。

### 3.1 证据强度与结论上限

| 强度 | 含义 | 能写成什么 |
| --- | --- | --- |
| **强** | 设备可直接观测（adb 响应、`module list`、`/proc` 内容、`boot_id`/`uptime`） | "该判据通过" |
| **弱** | 只能从日志侧面推断（`dmesg`），而 panic 可能发生在落盘前 | 只能写"**未观察到**"，不能写"没有发生" |
| 未采集 | 拿不到（无设备、无权限、脚本失败） | 必须写原因（C7），不得留空 |

**结论上限（C2）**：报告只对「该字节在该机型 / 该内核 / 该次加载下存活 N 秒且 X/Y 条判据通过」负责，
禁止外推到其它机型、其它内核或多次加载的统计结论。

### 3.2 每次加载前的基线（C4，缺少基线就不许加载）

必录四项：`boot_id`、`uptime`、**pstore 是否残留旧崩溃**、当前已加载模块列表。

- `pstore` 非空（有旧崩溃残留在场）→ **停下来先问维护者**，不要在混着旧现场的机器上加载。
- 基线缺失或采不到 → 记为未执行（A6），不要"先加载再说"。

### 3.3 判据脚本必须绑定（C5）

报告里写清判据脚本的**路径 + sha256**（或脚本所在 commit）。脚本改了，旧结论不自动继承：
改了判据就得重新跑一轮并在报告中说明改了什么、为什么改（不得为了过判据而放宽断言）。

`run_test.sh` 会把每个判据的结果与计数写进报告骨架；Tester 补上人工观察与结论。

### 3.4 判据工具的冻结基线

工具运行复验绑定明确的完整冻结工具 commit，另记报告生成时的 HEAD。采用的仪器集合须覆盖 Tester 工具、共享判据工具及影响判据的规则、模板和配置；报告记录该集合、集合哈希和核验结果。

冻结核验读取工作树实际字节，并与基线提交中的完整仪器集合比较。枚举同时覆盖基线和当前文件：文件或整个目录删除、工具新增、内容或执行属性变化均应检出；Git 索引的忽略改动标记不改变字节核验要求。Git 查询、文件读取或结果解析失败时记为未冻结。

实机报告、升级单、`docs/records/` 的观测记录及构建/复核状态追加，分别绑定自身证据，继续按只追加规则保存。此类记录变更不改变判据仪器的冻结状态。影响判据的元数据配置仍属于仪器输入，不能整体排除全部元数据。

Tester 负责把统一核验接入 `run_test.sh` 和自检；独立夹具入口为 `python3 tools/selftest_instrument_freeze.py`。候选源码冻结继续按 [01-identity.md](01-identity.md) 的构建事务执行，工具运行复验不替代候选冻结。

## 4. 测试顺序（最小风险优先）

1. 预检 → **基线四项**（`boot_id`/`uptime`/pstore 残留/已加载模块，见 3.2）→ 清一次 `dmesg`。
   pstore 非空就先停止并升级，不要继续。
2. 加载 **base** 变体 → 观察 60s → 卸载 → 观察 60s。退出码 90 或人工观察到卡死立即升级（零重试）；退出码 1 记录判据失败，交归属方修复。
3. base 通过后，再测 `network` / `debug` / `network_debug`，每次一个新 Build/变体、一次一个。
4. 破坏性/边界用例（模块满表、移除 `/proc/rekernel` 后再卸载、反复加载卸载）放最后，且必须先在报告中写明风险与预期。

## 5. 报告

用 [../templates/tester-report.md](../templates/tester-report.md)，必须包含：

- 身份三要素（跑的是哪份字节）：**commit + instance_id + 产物 sha256**，其中 Build ID 一项用长形式
  `instance_id`（含 `r…kpb…` 配方段与 `#n`）；别名/归档目录名只能作为映射附注；
- 环境事实与设备指纹哈希；
- 判据表（带**证据强度**列）+ 成功/失败计数 + 尝试次数；
- **结论上限**一行（C2）；
- 失败归属：实现缺陷 / 测试缺陷 / 环境事实；
- 未覆盖清单（没测的机型、内核、功能、判据）+ 每项**未采集原因**（C7）；
- 判据脚本的路径与 hash（C5）；
- 若发生异常：升级单相对路径；有物理动作时附「动作回执」。

## 6. 失败归属速查

Tester 自有工具修复后，在 `Tester/reports/responses/<日期>-<问题编号>-<轮次>.md` 追加响应，使用 [修复响应模板](../templates/tester-response.md)。记录完整工具 commit、冻结状态、逐文件 SHA-256、自检层级、计数和未覆盖项；使用产物时列出完整身份。维护者同步问题状态，独立复核者按关闭条件复验。未冻结证据与临时措施一并保留到关闭条件达成。

| 现象 | 归属 |
| --- | --- |
| 加载返回 `kallsyms_lookup_name` 失败、偏移推导失败 | 实现缺陷（Developer） |
| 加载后崩溃/卡死/软重启 | 实现缺陷（**高**，走升级流程） |
| `truncate: not found`、superkey 错误、`/data/local/tmp` 无权限 | 测试缺陷（Tester） |
| USB 掉线、设备过热降频、adb 版本不匹配 | 环境事实（记录，不算缺陷） |
| 某机型 SELinux 拦截 netlink 协议号 | 环境事实 + 可达性结论的限制条件（写进报告） |

## 7. 脚本与目录

```text
Tester/tools/preflight.sh          # 预检 + 环境事实落盘
Tester/tools/run_test.sh           # 带看门狗的功能测试（90 = 设备无响应）
Tester/tools/collect_evidence.sh   # 异常时的证据采集
Tester/reports/environments/       # 环境事实
Tester/reports/runs/               # 每次测试的报告骨架
Tester/reports/escalations/        # 升级单
```
