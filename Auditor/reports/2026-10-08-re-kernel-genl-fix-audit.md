# 独立审计报告：re_kernel 8.0.0 Genl 兼容性修复与 Oracle 边界变更独立审计

角色：Auditor（独立审计）。  
审计对象：`re_kernel` 8.0.0 动态推导模块（冻结修复提交 `f80c9a270c27d611b0147729e11c30d1f25577a1`、Oracle 边界变更提交 `fce5d75ef8e1a3c70921b5afa8e847dab751e707` 及候选交接 `a7cf9633fe468ca0a36e19e825e618bc2a348390`）。  
交接来源：`Developer/reports/handoffs/2026-10-08-re_kernel-genl-candidate.md` 与交接清单 `Developer/reports/handoffs/re_kernel-8.0.0-20261008-genl.json`。  

---

## 1. 身份与基线依据

| 项 | 值 |
| :--- | :--- |
| **生产修复 commit** | `f80c9a270c27d611b0147729e11c30d1f25577a1` |
| **Oracle 独立变更 commit** | `fce5d75ef8e1a3c70921b5afa8e847dab751e707` |
| **候选交接 commit** | `a7cf9633fe468ca0a36e19e825e618bc2a348390` |
| 模块版本声明 | `8.0.0`（Makefile / README / 内嵌元数据完全一致） |
| **Release Build ID** | `re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264` |
| **Release instance_id** | `re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264#1` |
| **Release sha256** | `931aca2529acfad4953ba62b024312b9e88fd6da037f891930a189f8d4485234`（47,216 字节） |
| **Debug Build ID** | `re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264` |
| **Debug instance_id** | `re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264#1` |
| **Debug sha256** | `f9cb3b639e906f4f2053e508393bd682026ac3e752fc77c5a2d6d089f8b19322`（56,472 字节） |
| 编译工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| 平台 SDK | KernelPatch commit `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9） |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 独立复现命令 / 证据 | 来源归属 | 是否独立复现 |
| :--- | :--- | :--- | :--- |
| **源码编译字节完全一致** | 在沙箱 `local/auditor-scratch/verify_commits_20261008/` 独立执行 NDK Clang 编译，产物 SHA-256 与交接归档逐字节一致 | Auditor 独立重编译 | 是 |
| **Oracle 变更合规性** | 走查 `fce5d75` 补丁与单测，验证断言未删减且边界调整技术依据充分 | Auditor 独立审查 | 是 |
| **生产推导无版本硬分支** | 全文扫描 `LINUX_VERSION_CODE` 与 `utsrelease`，确认零命中 | Auditor 独立检索 | 是 |
| **静态扫描与启发式边界** | 运行 `Auditor/tools/static_scan.py re_kernel`，无生产阻塞性缺陷 | Auditor 静态扫描 | 是 |
| **ELF 结构与符号导出审查** | 运行 `Auditor/tools/artifact_audit.py --module re_kernel`，17 项导入合规 | Auditor 产物审计 | 是 |

---

## 3. 核心审计项目审查

### 3.1 `respect-the-oracle` 约束与单测边界调整独立复核（DEV-011 Oracle 部分）
- **审查对象**：提交 `fce5d75ef8e1a3c70921b5afa8e847dab751e707` 及补丁 `Developer/reports/responses/2026-10-08-DEV-011-oracle-boundary.patch`；
- **变更事实**：
  - `re_kernel/tools/test_genl_offsets.py` 中，`genlmsg_put` 扫描与分配长度由 20 条（`0x14`）调整为 25 条（`0x19`）；
  - `hdrsize_outside_prefix` 诱饵指令偏移从索引 20 移至索引 25；
- **技术依据核验**：
  - 在 Sony Xperia 1 V（Linux 5.15 物理镜像）的汇编数据流中，`genlmsg_put` 在指令索引 7 读取 `hdrsize`，在指令索引 24 读取 `id`；
  - 旧测试套件硬编码的前缀截断窗口（20 条）脱离了真实内核汇编事实，导致索引 24 上的真实读取被测试套件截断或视为诱饵；
  - 开发者未隐蔽修改测试，单独成立提交 `fce5d75`，完整保留了原 290 项负例断言，且仅将诱饵外移至新边界（索引 25）；
- **Auditor 复核结论**：符合 `respect-the-oracle` 规范，调整依据真实硬件事实，**予以批准认可**。

### 3.2 Sony 5.15 与高版本（6.1/6.6）动态推导算法审查
- **审查对象**：提交 `f80c9a270c27d611b0147729e11c30d1f25577a1` 之 `re_kernel/re_offsets.c`；
- **算法改进要点**：
  1. **扫描窗口对称扩展**：`re_offsets.c:475` 同步由 `0x14` 扩至 `0x19`；
  2. **`config_first` 结构体头部识别**：增加了当 `offset >= 28` 且参数寄存器直接流向 `__nlmsg_put` 时的头部配置识别逻辑，成功解决 5.15 头部单一读取导致的 `genl_family_config` 失败；
  3. **独立组播校验入口 fallback**：新增 `genl_validate_assign_mc_groups` 锚点识别（前 24 条），与原注销窗口互为回退；
  4. **代码风格符合 AUD-005**：`struct_offset.genl_family_id` 等字段计算后立即赋值，未引入临时暂存变量，全量日志与错误处理保持统一。
- **Auditor 复核结论**：推导逻辑严密，无版本号硬编码分支，失败统一返回 `-11` 安全退出。

### 3.3 产物独立沙箱复编译
在沙箱目录 `local/auditor-scratch/verify_commits_20261008/re_kernel/` 中执行独立构建：
- **Release 产物**：
  `sha256 = 931aca2529acfad4953ba62b024312b9e88fd6da037f891930a189f8d4485234`（与候选登记逐字节一致）
- **Debug 产物**：
  `sha256 = f9cb3b639e906f4f2053e508393bd682026ac3e752fc77c5a2d6d089f8b19322`（与候选登记逐字节一致）
- **结论**：候选源码具备 100% 独立可复现性。

---

## 4. 问题单状态追踪

| 问题编号 | 严重度 | 归属 | 发现方 | 概要 | 当前状态 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AUD-001** | 高 | Developer | Auditor | Netlink 控制入口缺少 UID 1000 凭据鉴权 | **CLOSED** |
| **AUD-002** | 中 | 维护者 | Auditor | 内嵌元数据与模块目录更名 `re_kernel_x` 一致性 | **CLOSED** |
| **AUD-003** | 中 | Developer | Auditor | 静态基线针对目标内核镜像派生偏移与适配约束 | **CLOSED** |
| **AUD-004** | 低 | Developer | Auditor | 代码风格、死注释与头文件引用清理 | **CLOSED** |
| **AUD-005** | 低 | Developer | Auditor | `re_kernel` Genl 偏移计算延迟批量赋值风格偏离既有惯式 | **CLOSED** |
| **AUD-006** | 低 | Developer | Auditor | `re_kernel` 异步消息淘汰顺序与 `re_kernel_x` 不一致 | **CLOSED** |
| **DEV-010** | 高 | Developer | Developer | `mcgrps` 局部模式扫描与相邻指令特征匹配 | **CLOSED**（实机复核通过） |
| **DEV-011** | 中 | Developer | Tester | Sony 5.15 动态 Genl 推导失败与 Oracle 边界调整 | **CLOSED（实机复核关闭）** |
| **DEV-012** | 中 | Developer | Developer | 6.1 / 6.6 动态组播与 Binder from 覆盖 | **fixed（待真机复测）**（BTF 离线自检通过） |
| **DEV-013** | 中 | Tester | Developer | Tester 实际加载文件大小差异与 SDK 来源纠正 | **OPEN（待 Tester 响应）** |
| **DEV-014** | 低 | Developer | Developer | 离线 kallsyms 顺序表提取工具改进 | **CLOSED**（工具自检通过） |

---

## 5. 同源风险声明

- **独立编译**：Auditor 独立在沙箱 `local/auditor-scratch/verify_commits_20261008/` 构建，未调用维护方 `tools/build_candidate.py`（提及该脚本仅用于定位，未作依据）。
- **独立二进制解析**：ELF 格式与符号解析由 `Auditor/tools/artifact_audit.py` 直接自解析 ELF 头部，未调用 `kernel_img/offset_harness` 与 `tools/identity.py`（提及该脚本仅用于定位，未作依据）。
- **语料同源限制**：虽然 Developer 进行了离线全量语料回归，但真实内核的泛化能力仍需由 Tester 在目标物理设备上确认。

---

## 6. 未验证清单

1. [x] **新构建候选在 Sony 5.15 物理设备上的热加载验证**：已由 Tester 在物理设备（Sony Xperia 1 V / 5.15.189）完成端到端闭环（见第 7 节）。
2. **6.1 与 6.6 新内核物理硬件加载**：目前仅有 BTF 离线自检证据，未在实体 6.1/6.6 设备上挂载。
3. **Tester 实机文件尺寸与 SDK 引用纠偏（DEV-013）**：等待 Tester 给出正式修复响应。

---

## 7. 后续实机测试追加复核记录（Sony 5.15 硬件闭环与 DEV-011 关闭）

- **实机报告来源**：[`Tester/reports/runs/2026-10-08-re_kernel-8.0.0_5.15_genl_live#1.md`](../../Tester/reports/runs/2026-10-08-re_kernel-8.0.0_5.15_genl_live%231.md)
- **目标设备环境**：Sony Xperia 1 V（`XQ-DQ72`，设备指纹哈希 `48b7ee2f`），Linux 5.15.189，Android 15，SELinux Enforcing，boot_id SHA-256 `26a5e8d58af33638d78e1e34e2cbf3c9e86dee24b1725f88a53e6049611be3f1`。
- **基线身份与产物核对**：
  - 生产修复 commit：`f80c9a270c27d611b0147729e11c30d1f25577a1`
  - 候选交接 commit：`a7cf9633fe468ca0a36e19e825e618bc2a348390`
  - Debug 在册 instance_id：`re_kernel-8.0.0_debug+g9c1ce4ad97c0.r0a32e256.kpb51197a.ndk26.3.11579264#1`，sha256：`f9cb3b639e906f4f2053e508393bd682026ac3e752fc77c5a2d6d089f8b19322`
  - Release 在册 instance_id：`re_kernel-8.0.0+g9c1ce4ad97c0.r96eac7cd.kpb51197a.ndk26.3.11579264#1`，sha256：`931aca2529acfad4953ba62b024312b9e88fd6da037f891930a189f8d4485234`
- **判据与动态推导证据核验**：
  1. **热加载与控制响应**：Release 与 Debug 变体均成功热加载（退出码 0），`ctl0 ping` 返回 `_(._.)_`；
  2. **Sony 5.15 动态推导实证**：
     真机内核 `dmesg` 明确输出：
     ```text
     re_kernel: genl_family_id=0x0
     re_kernel: genl_family_config=0x4
     re_kernel: genl_family_n_mcgrps=0x27
     re_kernel: genl_family_n_mcgrps_size=1
     re_kernel: genl_family_mcgrp_offset=0x20
     re_kernel: genl_validate_assign_mc_groups ...
     re_kernel: Created Re:Kernel Generic Netlink family! ID: 46
     ```
     证实 Sony 5.15 的 `config_first`（`id=0, config=4`）与 `genl_validate_assign_mc_groups` 组播回退锚点在真实 GKI 内核上推导成功，成功建立 Generic Netlink Family 46；
  3. **FIFO 异步消息淘汰实测（AUD-006）**：内核持续产出 `free_outdated pid=...,uid=...,data_size=...` 淘汰日志，算法正确执行；
  4. **干净卸载与 pstore 干净度**：卸载退出码 0，`/sys/fs/pstore/` 无崩溃日志，零 panic。
- **问题单状态变更**：
  - **DEV-011**（Sony 5.15 动态 Genl 推导失败与 Oracle 边界调整）：`fixed（待真机复测）` → **`CLOSED（实机复核关闭）`**。
- **同源风险声明**：Auditor 仅复核 Tester 报告中的量化判据与日志事实，未调用维护方工具或开发方 harness（提及 `kernel_img/offset_harness` 与 `tools/identity.py` 仅用于定位，未作依据）。

> 维护者公开整理（2026-10-08）：启动标识改为 SHA-256，保留相等关系；核验结论与候选身份保持原文。原文 SHA-256：`f828016a64412d0e809fe1e07228c55635057f4afa33ffa64f0545c0720e0085`；原文保存在本地证据归档。
