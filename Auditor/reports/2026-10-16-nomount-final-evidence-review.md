# NoMount 最终证据复核报告

角色：Auditor。按 S01 整理当前两个候选及其在册派生字节。完整源码提交、instance_id、KPM SHA-256 和长度集中列于[来源索引](data/2026-10-16-nomount-final-evidence-index.json)：C1 为动态件，C2 为静态基线件；P1 仅用于追溯 5.15 Delta 绑定的前轮动态实测。

本次执行的是**文件身份复算与证据汇总**。原独立重编译、产物审计、宿主夹具和设备测试均引用既有报告，不计为本次新运行。请求冻结快照、原件完整提交及三版审计追加链均在索引中；旧报告继续保留。

## 本次直接复核

用 Python 标准库 `hashlib` 读取文件，并通过 `git cat-file --batch` 直接取得提交 blob：本次整理时，10/10 份来源文件的字节、SHA-256 和长度与请求冻结快照一致；S02 三个已登记版本的哈希、长度、原文前缀及两段追加哈希全部相符，当前原件为包含 §8 更正的最终版本。C1/C2 两件基础 KPM 与登记及 S03 对应条目的哈希、长度一致；17 条当前派生记录对应的 13 组唯一字节逐件复算一致，基础实例与基础哈希逐项匹配。派生来源提交由 C1/C2 绑定，索引按相同字节合并目标，原 17 条记录仍在 S07。[S02、S03、S07]

可复核方法如下；其中 `p` 为索引路径，源文件与当前产物分别读取，不执行角色封装或构建流程：

```python
import hashlib, json, subprocess
from pathlib import Path
p = Path("Auditor/reports/data/2026-10-16-nomount-final-evidence-index.json")
d = json.loads(p.read_text())
refs = [s["commit"] + ":" + s["path"] for s in d["sources"]]
buf = subprocess.check_output(["git", "cat-file", "--batch"],
                              input=("\n".join(refs) + "\n").encode())
for s in d["sources"]:
    header, buf = buf.split(b"\n", 1)
    n = int(header.split()[2]); blob, buf = buf[:n], buf[n+1:]
    assert blob == Path(s["path"]).read_bytes()
    assert len(blob) == s["size"]
    assert hashlib.sha256(blob).hexdigest() == s["sha256"]
for a in [x["artifact"] for x in d["candidate_identities"]] + d["derived_artifacts"]:
    raw = Path(a["path"]).read_bytes()
    assert len(raw) == a["size"]
    assert hashlib.sha256(raw).hexdigest() == a["sha256"]
```

## 既有结论与覆盖

以下各项是**引用既有角色证据**；本次只独立核对其文件身份及与当前对象的对应关系。

| 项目 | 保留的结论与计数 | 来源 |
| --- | --- | --- |
| 独立重编译 | 原 Auditor 在隔离目录重编译 C1/C2，两件 SHA-256 与候选逐字节一致，分别 219,984 / 115,104 字节。 | S02 §1 |
| 派生链路 | 原审计复现 4.4 动态 legacy-kp 与 13 份静态配置（10 组静态字节），配置替换范围为 92 字节偏移段。本次在册总量另含静态 legacy-kp 等记录，按 17 条 / 13 组复算，两个口径不合并为新派生实验。 | S02 §1、S07 |
| 产物审计 | S03 的当前两件均无结构错误、无未解析 KP 导入；原数据扫描全部历史的 60 件产物并保留 742 条 `review` 提示，不能把它们解释为本次当前候选的缺陷数或已清零清单。 | S02 §5、S03 |
| 启发式扫描 | 原扫描覆盖 38 文件，25 命中：释放后未置空 3、回调睡眠提示 13、移位提示 7、输入鉴权提示 2。S02 记录未确认阻塞项；提示及人工审查边界保留，扫描不能证明所有并发/安全路径无缺陷。 | S02 §5、S04 |
| 边界与布局夹具 | 原报告记录代码边界 5 场景、尾部锚点 5 组目标及 37 项反例、代理对齐 693 项断言、13 静态配置往返通过。宿主模拟限制仍在；S10 属 Developer 数据。 | S02 §2–3、S10 |
| 静态结构变更 | 代理头对齐由 64 改为 128 字节，全局改变头偏移及分配尺寸，属于结构扩展，不能整体免测顺延；须在可用旧目标至少抽样一趟。S08 记录 4.4 静态 legacy-kp 与 4.19 静态 patch 两趟抽样通过，实测结论归 Tester。 | S02 §4、S08 |
| TST-001 / DEV-042 | 原审计确认 `_etext` 失效时回退 `__start_rodata`、无合法上界则拒绝加载。S08 记录 4.4 动态实测闭环；S07 已登记两单 `closed_by=Tester`。本次没有再执行修复测试或关闭问题。 | S02 §2、S07、S08 |

## 5.15 Delta 与 DEV-044 更正

保留 S02 §7–8 对 **BTF 完备的 5.15 动态目标**的 Delta 证据绑定裁定：前轮 P1 的 S09 趟③为 Sony Xperia 1 V / 5.15 的既有 20/20 实测，C1 本轮由该裁定绑定；不是 C1 在 5.15 的新实测。其前提包括 BTF 路径成功及目标所需符号可解析，不能外推到无 BTF 的 4.4/4.19、静态结构变化或其它目标。设备接入后仍需按原裁定排期补测。[S02 §7–8、S08、S09]

§8 已更正 §7 的算术错误：`192 % 128 = 64`、`192 % 64 = 0`；dentry 代理头为 128 字节、第二表位移为 192 字节，公开表位于基址加 320，满足该目标 64 字节对齐，反查减去 192 与 128 回到基址。原 Auditor 裁定更正不改变 5.15 Delta 绑定。维护者独立核对算式、代理定义和寻址关系并宿主复跑 int/bool 夹具；DEV-044 由维护者独立关闭（归属 Auditor），Developer 又独立确认更正与关闭记录相符。维护者的目标 ABI/完整 Delta 分析仍引用 Auditor，宿主复跑不构成设备实测。[S02 §8、S05、S06、S07]

DEV-043 的登记缺项由维护者修复，Developer 直接核对原件、实例、追加链和风险范围后关闭；本次读取已关闭记录，候选身份及历史原件保持原有语义。[S05、S06、S07]

## 风险、未覆盖与同源性

- **AUD-001 维持 OPEN**：无 BTF 动态路径的 `key_type` 精确尺寸仍未知，512 字节自建清零容量缺少任意厂商扩展的普遍上界证明。最坏情形为堆越界读写、内存破坏或崩溃；频率未知，置信度为静态推断、无已知实测命中。inode/super/dentry 尺寸边界的改善及已测设备通过均不能关闭该风险。[S02 §5、S07]
- **驻留约束与 RA-002**：卸载后原生回调仍可能引用已释放模块，存在高严重度 UAF 风险；当前两实例及在册派生范围已追加到风险接受。保持嵌入加载、常驻至重启，禁止卸载/动态重载；移除通过撤销嵌入后重启。风险接受不降低影响，也不扩展支持目标。[S05、S06、S07]
- **设备覆盖**：静态抽样只覆盖 S08 的 4.4/4.19 两次具体字节及该次运行；5.15 动态为上述 Delta 绑定。6.1 与新增五目标（米8/米9/米10/米11/Android12）没有本轮实机证据；离线配置通过不能替代这些目标实测。长时并发、任意厂商布局及其它设备仍未由本次汇总覆盖。[S02 §4、S08、S09]
- **格式/风格与本次运行限制**：本次未重新编译、重做代码或格式检查、运行宿主夹具或操作设备；主要审计原件没有单列完整的独立格式规范哈希、命令及输出清单，本摘要不补记为已检查。既有报告原覆盖范围完整保留。[S01、S02]
- **同源风险**：原重编译与实现方共享冻结源码、KernelPatch 和 NDK；原派生复现使用实现方 `patch_offsets.py`，不能视作独立实现变换算法；锚点、目标配置和 Developer 宿主套件仍共享实现来源与内核语料。S03 的符号语料为 9 标签、10 份本地符号表，本次未独立提取或扩充，未获得符号不等于目标不存在。S05/S06 的独立确认仅覆盖其声明范围。当前文件哈希一致性证明原件身份，不提升这些历史结论的独立性或设备泛化能力。[S02、S03、S05、S06、S10]

## 来源与复核决定

编号完整元信息见 JSON；以下链接指向保留的原件。

| 编号 | 原件 |
| --- | --- |
| S01 | [整理请求](../../docs/records/2026-10-16-nomount-final-report-request.md) |
| S02 | [尾部锚点审计（含 §8）](2026-10-15-nomount-tail-anchors-audit.md) |
| S03 | [原产物审计数据](data/2026-10-15-nomount-tail-anchors-artifact-audit.json) |
| S04 | [原静态扫描数据](data/2026-10-15-nomount-tail-anchors-static-scan.json) |
| S05 | [Developer 独立响应](../../Developer/reports/responses/2026-10-16-DEV-043-044.md) |
| S06 | [维护者登记与独立确认](../../docs/records/2026-10-16-nomount-final-registration.md) |
| S07 | [身份、问题与风险登记快照路径](../../metadata/modules/nomount.json) |
| S08 | [Tester 两机四趟原报告](../../Tester/reports/runs/2026-10-15-nomount-two-device-round-live%231.md) |
| S09 | [Tester 前轮 5.15 原报告](../../Tester/reports/runs/2026-10-15-nomount-inode-storage-live%231.md) |
| S10 | [Developer 尾部锚点数据](../../Developer/reports/data/2026-10-15-nomount-tail-anchors.json) |

**保留（Retain）**：有效性由原件与 Git blob、当前产物及追加链复算支撑；简洁性采用编号与小型索引集中保存身份，不复制完整历史数据；后果边界保留 AUD-001、驻留风险、Delta 前提和未覆盖清单。此次只形成可追溯摘要，既有判据与 Oracle 保持原样，正式验收与交付由维护者按具体实例处理。
