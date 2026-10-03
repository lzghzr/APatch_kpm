# 审计复核报告：re_kernel_static 风格修复（AUD-004）与规范说明（AUD-002）复核

角色：Auditor（独立审计）。  
复核对象：Developer 针对 `AUD-004` 与 `AUD-002` 的修复提交与响应。  
响应记录：`Developer/reports/responses/2026-10-02-AUD-004-style.md`  
修复源码 Commit：`5c779c9b6cc7de1308d884906c4ddda3f7152c13`  
新候选清单：`Developer/reports/handoffs/2026-10-02-re-kernel-static-style-candidate.json`  

---

## 1. 身份与复核对象

| 项 | 值 |
| --- | --- |
| 修复源码 Commit | `5c779c9b6cc7de1308d884906c4ddda3f7152c13` |
| 修复提交说明 | `re_kernel_static: 修正头文件保护并整理源码与构建清理` |
| Developer 响应 Commit | `68f50053737fda2e1138cb34efc9ee7602d87928` |
| 工具链 | NDK 26.3.11579264（Clang aarch64-linux-android31-clang） |
| KernelPatch Commit | `b51197aaba8f2272dd8a3e30c85698a29aa928c9`（SDK 0.13.9） |
| 语料内核 | 4.4 (`4.4.192-perf+`)、5.15 (`5.15.189-android13-8-00016`)、4.14 (`4.14.356-Liberty`) |

### 8 份新候选实例与 SHA-256 复核

Auditor 在隔离沙箱 `local/auditor-scratch/verify_5c779c9/` 中独立重新编译全部 8 份变体，逐一比对哈希：

| 变体 | Build ID / instance_id | 候选与沙箱重编译 sha256 | 复核结果 |
| --- | --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g40f56f1e1476.rc6e986ec.kpb51197a.ndk26.3.11579264#1` | `b3cee82601fd89a8ccfc908830b522d52871cc3000e9b6c3280909a084a2e9e3` | **PASS (Match)** |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g40f56f1e1476.r6b018c83.kpb51197a.ndk26.3.11579264#1` | `ec42d6b3e94d17fe1805e366425a510a64a089e661727404f85a84314c05aaa7` | **PASS (Match)** |
| abi4 | `re_kernel_static-8.0.0_abi4+g40f56f1e1476.red25fa6f.kpb51197a.ndk26.3.11579264#1` | `b1e7e8a47d81ba0bb292dedf616ad226e2d72e27390fa2079392bb6b1a887fe6` | **PASS (Match)** |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g40f56f1e1476.r21a27d69.kpb51197a.ndk26.3.11579264#1` | `20b1bbe19f29c0ce4d59419b88d89e2c0fe374313e1d60a212ba6e2b454fb3fe` | **PASS (Match)** |
| abi5 | `re_kernel_static-8.0.0_abi5+g40f56f1e1476.r2298d412.kpb51197a.ndk26.3.11579264#1` | `b40f556e38305d8dec46a8322aa9df063c40e6f405a927f48dbc302acda345d6` | **PASS (Match)** |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g40f56f1e1476.r20f6465d.kpb51197a.ndk26.3.11579264#1` | `9a42e3b6886542188f652927e419a627d14e65768b44bf10ce3228bf8f59dbc0` | **PASS (Match)** |
| abi6 | `re_kernel_static-8.0.0_abi6+g40f56f1e1476.r359585c3.kpb51197a.ndk26.3.11579264#1` | `d8c33f1a407bd03c3353054800b4c783eb4d0f82cd7d5d32554d7494a0eef8da` | **PASS (Match)** |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g40f56f1e1476.rd4d7118b.kpb51197a.ndk26.3.11579264#1` | `99ba2818a0dd495d74b61e6e74d3a9ae8ed3abff3ff2082bc51855d430a1b6e1` | **PASS (Match)** |

---

## 2. 独立复核证据表（结论 → 命令 → 证据）

| 检查项 | 复核命令 / 证据 | 结论 |
| --- | --- | --- |
| **头文件防重复保护** | `head -n 5 re_kernel_static/re_structs.h` 与 `tail -n 5 re_kernel_static/re_structs.h`：第 3 行提前闭合的 `#endif` 已移除，文件末尾正确闭合 `#endif /* __RE_STRUCTS_H */` | **PASS** |
| **包含文件块整洁** | 检查 `re_kernel_static/re_kernel.c:23-28`：`#undef task_uid` 移至 `re_offsets.c:98`；`static struct net kvar_def(init_net);` 移入 `re_utils.h:123`；包含块纯净连续 | **PASS** |
| **死代码清理** | 检查 `re_kernel_static/re_utils.h:123`：注释行 `// extern struct net kvar_def(init_net);` 已移除 | **PASS** |
| **常量收敛** | 检查 `re_kernel_static/re_kernel.h:37` 增加 `#define REKERNEL_NET_UID_MAX 32`；`tools/tests/genl.c` 移除重复定义 | **PASS** |
| **构建脚本清理** | `make clean` 包含 `rm -rf *.kpm *.kpm.json`，在沙箱构建后执行 clean，KPM 与 JSON 伴随元数据零残留 | **PASS** |
| **误跟踪二进制移除** | `git ls-files re_kernel_static/re_vmlinux` 退出码 0 且无输出；`re_kernel_static/.gitignore` 补充规则；空 `tests/` 目录已删除 | **PASS** |
| **代码格式排版** | `clang-format --dry-run -Werror re_kernel_static/*.c re_kernel_static/*.h re_kernel_static/tools/tests/*.c` 退出码 0 | **PASS** |
| **产物结构与符号审计** | `python3 Auditor/tools/artifact_audit.py --module re_kernel_static --manifest Developer/reports/handoffs/2026-10-02-re-kernel-static-style-candidate.json`：无阻塞性错误，19 项符号完全由平台导出表覆盖 | **PASS** |
| **AUD-002 规范说明** | `re_kernel_static/README.md:1-4` 标明模块注册名 `re_kernel` 系为兼容上层管理客户端，并明确警示静态版与动态版不能同时加载 | **PASS** |

---

## 3. 问题单复核与关闭判定

### 3.1 AUD-004（源码风格与工程规范一致性）：CLOSED
- **原问题**：头文件保护过早闭合、包含块夹带宏、死注释残留、常量散落、构建残留及二进制误提交。
- **复核结论**：Developer 在 commit `5c779c9b6cc7de1308d884906c4ddda3f7152c13` 中完全落地修复；且 Auditor 独立重编译确认产物 SHA-256 逐位一致，零二进制漂移。
- **关闭证据**：本报告第 2 节全量独立验证命令与结果通过。
- **状态变更**：`open` → **`closed`**（Auditor 独立复核关闭）。

### 3.2 AUD-002（产物内嵌名称与目录名差异）：OPEN (待门禁规约裁决)
- **原问题**：产物 `.kpm.info.name` 为 `"re_kernel"`，与模块目录 `re_kernel_static` 存在名称差异；若与动态版混用会导致加载冲突。
- **复核结论**：Developer 在 `re_kernel_static/README.md` 正文头部明确给出规约说明（“模块注册名仍为 `re_kernel`，用于兼容现有客户端和管理工具；静态版与动态版不能同时加载”）。但经运行 `tools/check_repository.py`，当前门禁 `version_consistency` 强制断言 `embedded_name == module`，此项在自动化门禁中仍告警报失败。
- **状态变更**：维持 **`open`**（待维护者在元数据/门禁中放行别名映射，或 Developer 修改内嵌名称）。

### 3.3 其余问题单状态追踪
- **AUD-001**（中，Generic Netlink 控制入口缺少发送方身份校验）：**`open`**（待后续迭代补充权限校验）。
- **AUD-003**（中，候选产物包含模板偏移，真机测试前必须派生专用 KPM）：**`open`**（已在 Sony 5.15 机型测试中按机型偏移派生验证）。

---

## 4. 同源风险声明

- **独立编译**：Auditor 独立在 `local/auditor-scratch/` 重新构建 8 份变体，采用独立命令；提及 `tools/build_candidate.py` 仅用于定位，未作依据。
- **分析依据**：产物结构审计由 `Auditor/tools/artifact_audit.py` 直接自解析 ELF 节区与头部，未调用 `kernel_img/offset_harness`。

---

## 5. 未验证清单

- 本复核专注于源码规范与编译产物一致性，真机运行稳定性及动态交互由 Tester 实机报告覆盖。


> 维护者整理（2026-10-02）：保留本报告作为 AUD-004 的历史关闭证据。当前命名与鉴权复核见 [ReKernel-X 1.6 审计](2026-10-02-re-kernel-x-auth-audit.md)；本报告其余状态均为该次复核时的记录。
