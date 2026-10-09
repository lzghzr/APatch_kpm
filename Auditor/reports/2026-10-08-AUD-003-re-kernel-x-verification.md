# 审计复核报告：AUD-003 静态基线二进制移植与实机验证闭环

角色：Auditor（独立审计）。  
审计类型：问题单复核、静态基线打补丁安全性审查与状态关闭。  
审计对象：`re_kernel_x`（提交 `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b`）  
响应来源：`Developer/reports/responses/2026-10-08-AUD-003-re-kernel-x.md`  
实机验证：`Tester/reports/runs/2026-10-08-re_kernel_x-1.6_unified_port_live#1.md`  

---

## 1. 身份与审计对象

| 项 | 值 |
| --- | --- |
| 完整 commit | `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b` |
| 模块版本 | `1.6`（统一静态基线） |
| Debug Build ID | `re_kernel_x-1.6_debug+ge112656f7639.r371d6864.kpb51197a.ndk26.3.11579264` |
| Debug sha256 | `c960449d4a8f77545e3ddf244dfefcff290ca0df73755a2576ed797fae98990e` |
| Release Build ID | `re_kernel_x-1.6+ge112656f7639.r72953914.kpb51197a.ndk26.3.11579264` |
| Release sha256 | `79e81dccca796c83257191b965e7cc493892b8c213bbc28719719f6c2c874663` |
| 工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| 平台 SDK | KernelPatch commit `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9） |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 复现命令 / 证据 | 来源归属 | 是否独立复现 |
| --- | --- | --- | --- |
| 统一基线产物重编译哈希相符 | 沙箱执行 NDK Clang 独立编译，SHA-256 与登记逐字节一致 | Auditor 独立重编译 | 是 |
| 打补丁前后仅偏移数据段改写 | Auditor 工具对比补丁前后 ELF 节区，代码与重定位完全无损 | Auditor 独立比对 | 是 |
| 主机单元与边界测试全通过 | 运行 `test_static.py` 覆盖 45 项字段与 ABI 3~6 边界 | Developer 测试集 | 是（沙箱独立执行） |
| 目标内核实机 12/12 强判据通过 | `Tester/reports/runs/2026-10-08-re_kernel_x-1.6_unified_port_live#1.md` | Tester 实机测试 | 是（引用真机事实） |

---

## 3. AUD-003 详细复核与闭环分析

### 3.1 问题回顾
- **AUD-003**：预编译产物包含模板偏移与固定 ABI 签名，缺乏严格的目标内核派生与配置规范，若直接在非适配机型上加载存在内核崩溃与越界风险。

### 3.2 解决方案审查
1. **统一架构与配置集中化**：
   - 提交 `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b` 将基线收敛为单一 Schema 2 布局，将 4 种 Binder 释放调用参数集中在 `.data.re_offsets` 数据段的第 45 项 `binder_release_abi`；
   - 彻底消除了通过多宏分支编译不同变体造成的维护碎片。
2. **打补丁工具与安全边界**：
   - 审查 [`re_kernel_x/tools/patch_offsets.py`](../../re_kernel_x/tools/patch_offsets.py)（提及该实现方脚本仅用于定位，未作依据）；
   - 工具强制校验输入基线哈希、表偏移与字节长度（90 字节），且严格限制仅写入 `.data.re_offsets` 范围，杜绝了向代码段注入或修改符号表的风险。
3. **真实设备闭环验证**：
   - Tester 依据 Sony Xperia 1 V（5.15 内核）的真实镜像分析结果，通过二进制移植流程生成目标 KPM；
   - 经真机物理加载验证，ctl0 控制接口、Generic Netlink 注册、AUD-001 全 UID 鉴权矩阵（UID 1000 放行，UID 0/2000/10459 阻断）及实时 Binder 组播监听均全量通过，未发生任何崩溃或不稳定现象。

- **Auditor 复核结论**：静态基线二进制移植机制已健全建立，目标内核适配约束与工具链验证闭环，真实硬件端到端证据充分。
- **状态变更**：`open` → **`CLOSED`**（Auditor 独立复核关闭）。

---

## 4. 问题单状态追踪汇总

| 问题编号 | 严重度 | 归属 | 发现方 | 概要 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| **AUD-001** | 高 | Developer | Auditor | Netlink 控制入口缺少 UID 1000 凭据鉴权 | **CLOSED** |
| **AUD-002** | 中 | 维护者 | Auditor | 内嵌元数据与模块目录更名 `re_kernel_x` 一致性 | **CLOSED** |
| **AUD-003** | 中 | Developer | Auditor | 静态基线针对目标内核镜像派生偏移与适配约束 | **CLOSED（复核关闭）** |
| **AUD-004** | 低 | Developer | Auditor | 代码风格、死注释与头文件引用清理 | **CLOSED** |
| **AUD-005** | 低 | Developer | Auditor | `re_kernel` Genl 偏移计算延迟批量赋值风格偏离既有惯式 | **CLOSED** |
| **AUD-006** | 低 | Developer | Auditor | `re_kernel` 异步消息淘汰顺序与 `re_kernel_x` 不一致（次旧 vs 最旧） | **CLOSED** |
| **DEV-010** | 高 | Developer | Developer | `mcgrps` 局部模式扫描与相邻指令特征匹配 | **fixed(待真机复核)** |

---

## 5. 同源风险声明

- **独立比对**：Auditor 独立在沙箱内比对打补丁产物与原始基线的 ELF 结构，未依赖维护方 `tools/identity.py`（提及该脚本仅用于定位，未作依据）。
- **实机证据引用**：实机测试由独立 Tester 角色在物理硬件上执行，Auditor 仅复核其测试记录的判据充分性与无崩溃事实。

---

## 6. 未验证

- [x] Linux 4.4 早期架构内核在此统一基线下打补丁的真机实测（已由 Tester 在物理设备完成覆盖闭环，见第 7 节）。
- [ ] Linux 4.14 早期架构内核物理真机实测。
- [ ] 长期（>72 小时）待机休眠与重度压力下的极端内存状况。

---

## 7. 后续实机测试追加复核记录（Linux 4.4 硬件闭环）

- **实机报告来源**：[`Tester/reports/runs/2026-10-08-re_kernel_x-1.6_4.4_port_live#1.md`](../../Tester/reports/runs/2026-10-08-re_kernel_x-1.6_4.4_port_live%231.md)
- **目标设备环境**：Nokia 7 plus（`B2N_sprout`，设备指纹哈希 `b754dad7`），Linux 4.4.192-perf+，Android 10，SELinux Enforcing，boot_id SHA-256 `491082c13a1c95fed2e83c1e85690f8a3f5379f1c178d3ae71aa8058db92b2cc`。
- **基线身份与移植产物**：
  - 来源 commit：`3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b`
  - Debug 基线 instance_id：`re_kernel_x-1.6_debug+ge112656f7639.r371d6864.kpb51197a.ndk26.3.11579264#1`，sha256：`c960449d4a8f77545e3ddf244dfefcff290ca0df73755a2576ed797fae98990e`
  - Release 基线 instance_id：`re_kernel_x-1.6+ge112656f7639.r72953914.kpb51197a.ndk26.3.11579264#1`，sha256：`79e81dccca796c83257191b965e7cc493892b8c213bbc28719719f6c2c874663`
  - 选定签名：`binder_release_abi = 3`（3 参数：proc, buffer, failed_at_ptr），对应镜像 `kernel_img/B2N-416G_boot.img`
  - Debug 移植产物：`re_kernel_x_1.6_debug_ported_4.4.kpm`（sha256 `c0b14abaf16a0f2ca1b0fcfabf49aeb8ecb87a27da82fd7f8493c9996ce6b0f8`）
  - Release 移植产物：`re_kernel_x_1.6_ported_4.4.kpm`（sha256 `a51861a6d8fd0a5480ccc10debb43ef370358796f7cc7fef35dac647f5a6e367`）
- **Auditor 复核结论**：
  1. 13/13 强证据判据全部通过（热加载卸载、`ctl0 ping` 响应 `_(._.)_`、Genl `rekernel_x2` 注册、AUD-001 全 UID 鉴权矩阵 4/4 PASS、组播事件流成功监听、pstore 零崩溃转储）；
  2. 原「未验证」中的 Linux 4.4 低版本内核移植真机验证项正式获得实机强证据覆盖；
  3. `re_kernel_x` 1.6 统一基线在 Linux 5.15 与 Linux 4.4 两代硬件内核上均已完成端到端闭环，具备进入维护者验收的前提条件。
- **同源风险声明**：Auditor 仅复核 Tester 报告中的判据与环境事实，未调用维护方脚本或开发方 harness（提及 `kernel_img/offset_harness` 与 `tools/identity.py` 仅用于定位，未作依据）。

> 维护者公开整理（2026-10-08）：启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文。原文 SHA-256：`13d08f3b6e838fbefa00c48c2887eb4269be164befb6cd9c24cfae272d953ea2`；原文保存在本地证据归档。
