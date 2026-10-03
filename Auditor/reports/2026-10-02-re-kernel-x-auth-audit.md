# 审计报告：re_kernel_x 1.6（统一命名与 Netlink 权限鉴权审计）

角色：Auditor（独立审计）。  
审计类型：候选产物审计、命名一致性复核与安全鉴权审计。  
审计对象：`re_kernel_x/`（由 `re_kernel_static` 迁移更名）  
修复响应：`Developer/reports/responses/2026-10-02-AUD-001-002-re-kernel-x.md`  

---

## 1. 身份与审计对象

| 项 | 值 |
| --- | --- |
| 完整源码 commit | `e8b1ef2ca3aa0bd2e1b043cf513bb1b2dbea33aa` |
| 候选交接与对齐 commit | `52b303df659616012077bc95ed7899655295d925` |
| 模块版本 | `1.6`（对齐上游 ReKernel-X，历史 `8.0.0` 归档记录完整保留） |
| 交付登记来源 | `Developer/reports/handoffs/2026-10-02-re-kernel-x-auth-candidate.json` 及 `metadata/modules/re_kernel_x.json` |
| 工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| KernelPatch commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（SDK 0.13.9） |
| 平台符号快照 | `Auditor/snapshots/kp_runtime_symbols-b51197aaba8f.json`（174 导出符号） |
| 语料内核 | 4.4 (`4.4.192-perf+`)、5.15 (`5.15.189-android13-8-00016`)、4.14 (`4.14.356-Liberty`) |

### 8 份新基准（1.6）产物身份与独立重编译核验

Auditor 在隔离沙箱 `local/auditor-scratch/verify_re_kernel_x/` 中执行独立重新编译，对比 SHA-256 逐位吻合：

| 变体 | Build ID / instance_id | 产物与沙箱重编译 sha256 | 复核结果 |
| --- | --- | --- | --- |
| abi3 | `re_kernel_x-1.6_abi3+g3ea7f04a4665.r5730df8f.kpb51197a.ndk26.3.11579264#1` | `deb58ffc0ebed5a4f22f7df190f75ce2539b53592639911e7fd5c51b1bab2a15` | **PASS (Match)** |
| abi3_debug | `re_kernel_x-1.6_abi3_debug+g3ea7f04a4665.rbb9ef2a0.kpb51197a.ndk26.3.11579264#1` | `52e22ee6e41e7c9597bdec720ac533238744ba34b0f6fdd89005b9ad6659ae52` | **PASS (Match)** |
| abi4 | `re_kernel_x-1.6_abi4+g3ea7f04a4665.r3c69ad06.kpb51197a.ndk26.3.11579264#1` | `4f2b9fbd09d61650b81de114e8cfa3a1522723e95e1dbf36bd7a06dc668b8261` | **PASS (Match)** |
| abi4_debug | `re_kernel_x-1.6_abi4_debug+g3ea7f04a4665.r11816726.kpb51197a.ndk26.3.11579264#1` | `dc63b6008c917dc1ed2ac1c555052e09f9f2ee1d249e372407bc13bd806a469e` | **PASS (Match)** |
| abi5 | `re_kernel_x-1.6_abi5+g3ea7f04a4665.r4a149e5c.kpb51197a.ndk26.3.11579264#1` | `01efb65d0d4b26e6e2b64ff7cc47188b4afb6221eb9cdbb00295b6f4663b3095` | **PASS (Match)** |
| abi5_debug | `re_kernel_x-1.6_abi5_debug+g3ea7f04a4665.rfcfd2185.kpb51197a.ndk26.3.11579264#1` | `b044efa32ce965f0e2fd0d5417edc460473d8bf7beae3f789741beb8f87a0d3d` | **PASS (Match)** |
| abi6 | `re_kernel_x-1.6_abi6+g3ea7f04a4665.r13a2a6f8.kpb51197a.ndk26.3.11579264#1` | `163b83310bca7444bb802a38645f1e3bade200673c986572c1bee05868577c63` | **PASS (Match)** |
| abi6_debug | `re_kernel_x-1.6_abi6_debug+g3ea7f04a4665.rbdaea1e9.kpb51197a.ndk26.3.11579264#1` | `f2d6961b88359565b1a91800f481618b2f34826d5fcb9ad3a257ceddf1873d11` | **PASS (Match)** |

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 复现命令 / 证据 | 来源归属 | 是否独立复现 |
| --- | --- | --- | --- |
| 独立重编译哈希逐字节相符 | 在 `local/auditor-scratch/verify_re_kernel_x/` 运行 clang 命令，8 份产物 SHA-256 与 `metadata/modules/re_kernel_x.json` 一致 | Auditor 独立重编译 | 是 |
| 产物结构与符号表健全 | `python3 Auditor/tools/artifact_audit.py --module re_kernel_x`（退出码 0，无阻塞性错误） | Auditor 自有工具 | 是 |
| 命名门禁严格一致 | `python3 tools/check_repository.py` 中 `re_kernel_x` 的 `version_consistency` 检查完全通过 | 仓库门禁 | 是 |
| Netlink 权限鉴权代码走查 | `re_kernel_x/re_kernel.c:288` 核查 `NETLINK_CB(skb).creds.uid.val != REKERNEL_GENL_UID` 校验 | Auditor 源码审查 | 是 |
| 主机单元与权限测试全通过 | `python3 re_kernel_x/tools/test_static.py --baselines local/auditor-scratch/verify_re_kernel_x`（含 6 种非法 UID 拒绝测试，退出码 0） | Developer 测试套件 | 是（在沙箱执行） |

---

## 3. 详细审计与问题单复核

### 3.1 AUD-001：Generic Netlink 控制入口缺少发送方权限校验 —— CLOSED
- **修复方案审查**：
  在 `re_kernel_x/re_kernel.c:285-290`（`rekernel_genl_rcv_msg`）头部增加了明确的内核凭据鉴权：
  ```c
  if (!skb->sk || sock_net(skb->sk) != kvar(init_net))
    return -ENOENT;
  if (NETLINK_CB(skb).creds.uid.val != REKERNEL_GENL_UID)
    return -EPERM;
  ```
  其中 `REKERNEL_GENL_UID` 在 `re_kernel.h` 中严格定义为 `1000`（Android `AID_SYSTEM`）。
- **防御机制分析**：
  1. **防伪造**：凭据提取自内核套接字层的 `NETLINK_CB(skb).creds.uid.val`（通过 `struct scm_creds` 由内核 `current_cred()` 在发送时压入），而非报文载荷中的伪造字段。
  2. **阻断前置**：鉴权检查发生在任何属性解析与规则更新之前；非 1000 的 UID（如普通应用 UID 10000+、ADB UID 2000、甚至是 Root UID 0）均直接返回 `-EPERM`，无法触发任何状态变更。
  3. **沙箱测试覆盖**：Developer 在 `tools/tests/genl.c` 中覆盖了 6 种未授权 UID（0, 999, 1001, 2000, 10000, -1）及伪造 PID 的全量拒绝用例，实测通过。
- **状态变更**：`open` → **`closed`**（Auditor 独立复核关闭）。

### 3.2 AUD-002：产物内嵌名称与目录名差异导致的冲突风险 —— CLOSED
- **修复方案审查**：
  1. 源码目录与产物前缀全面更名为 `re_kernel_x`；
  2. `re_kernel_x/re_kernel.c:29` 更新为 `KPM_NAME("re_kernel_x");`；
  3. 内嵌元数据 `name`、模块目录名、产物文件名三者严格对齐为 `re_kernel_x`。
- **门禁验证**：
  运行 `tools/check_repository.py`，`re_kernel_x` 顺利通过 `version_consistency`（内嵌名称完全一致，零警告零错误）。
- **状态变更**：`open` → **`closed`**（Auditor 独立复核关闭）。

### 3.3 其余问题单状态追踪
- **AUD-003**（基准产物需针对目标内核镜像派生偏移）：**`open`**（基准仍为模板候选，测试设备已通过 5.15 适配验证；跨内核机型派生约束保持有效）。
- **AUD-004**（代码风格与工程卫生对齐）：已于上一轮**`closed`**。

---

## 4. 结论摘要

1. **命名一致性与门禁合规**：更名 `re_kernel_x` 后，完全解决了内嵌名称与目录差异导致的门禁拦截问题。
2. **控制信道安全性提升**：控制入口通过内核 SCM 凭据强制锁定 `AID_SYSTEM`（UID 1000），成功阻断非特权应用对监控 UID 与异步清理规则的篡改与 DoS 风险。
3. **独立复编译一致性**：沙箱独立重新编译 8 份 `1.6` 产物，SHA-256 逐位一致，ELF 结构合规，重定位合规，19 项 SDK 导入健全。

---

## 5. 同源风险声明

- **独立编译**：Auditor 独立在 `local/auditor-scratch/verify_re_kernel_x/` 重新构建 8 份变体，采用独立命令，未使用维护方 `tools/build_candidate.py`（提及该脚本仅用于定位，未作依据）。
- **分析依据**：产物结构审计由 `Auditor/tools/artifact_audit.py` 直接自解析 ELF 节区与头部，未调用 `kernel_img/offset_harness`。
- **符号核验**：符号快照由 Auditor 自有工具生成，核对 KernelPatch 0.13.9 导出表。

---

## 6. 未验证清单

1. **UID 1000 的真机联调验证**：本轮鉴权修复在离线沙箱与单元测试中已通过完整正反测试；实机环境下与上层 ReKernel-X daemon（UID 1000）的真实交互需由 Tester 在后续实机测试中闭环确认。
2. **动态卸载生命周期**：模块卸载（`unload`）依既定约定维持暂缓。
