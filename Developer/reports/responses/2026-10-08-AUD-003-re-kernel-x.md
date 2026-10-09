# AUD-003 修复响应：统一静态基线与目标内核二进制移植规范

问题编号：AUD-003。严重度：中。归属：Developer。发现方：Auditor。

---

## 1. 问题背景与修复方案

- **原问题审查（AUD-003）**：
  静态模块（`re_kernel_x`）发布的预编译产物包含模板偏移与固定 ABI 签名分支，缺乏目标内核安全派生机制，直接在未核对偏移的真机上加载存在系统崩溃与语义错位风险。
- **修复方案与落地措施**：
  1. **基线合并统一（Schema 2）**：提交 `3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b` 将多 ABI 产物收敛为单一 release 与 debug 统一基线，将 4 种 Binder 释放调用参数通过末项 `binder_release_abi`（字段 45）集中于 `.data.re_offsets` 数据段；
  2. **离线打补丁工具与规范**：重构并固化 [`re_kernel_x/tools/patch_offsets.py`](../../re_kernel_x/tools/patch_offsets.py)，支持 baseline 导出、blob/JSON 校验与目标镜像偏移写入，严格保证代码段、符号表与重定位逐字节不变；
  3. **技能与操作指引固化**：在 [`.agents/skills/kpm-static-binary-port/SKILL.md`](../../.agents/skills/kpm-static-binary-port/SKILL.md) 中完整定义用户侧离线移植流程、调用配置确认法则、验证边界与现场分析原则。

---

## 2. 身份与基线依据

- 修复 commit：`3dcd5962e6d8abe2167bfecaccf63b8ea3b5563b`
- 工具链：NDK 26.3.11579264，KernelPatch 0.13.9 (`b51197aaba8f2272dd8a3e30c85698a29aa928c9`)
- 关联 Build ID 与统一基线：
  - Debug: `re_kernel_x-1.6_debug+ge112656f7639.r371d6864.kpb51197a.ndk26.3.11579264#1` (`c960449d4a8f77545e3ddf244dfefcff290ca0df73755a2576ed797fae98990e`)
  - Release: `re_kernel_x-1.6+ge112656f7639.r72953914.kpb51197a.ndk26.3.11579264#1` (`79e81dccca796c83257191b965e7cc493892b8c213bbc28719719f6c2c874663`)

---

## 3. 证据

1. **主机单测与往返一致性**：
   ```bash
   python3 re_kernel_x/tools/test_static.py --baselines artifacts/re_kernel_x-1.6+ge112656f7639.r72953914.kpb51197a.ndk26.3.11579264
   ```
   覆盖 45 项字段往返、ABI 3~6 边界检查、并发多线程与 ASan/UBSan。
2. **目标内核二进制移植与实机回归证据**：
   Tester 依据 `kernel_img/boot_67.2.A.3.178.img` 提取事实（`binder_release_abi=5`），通过 `patch_offsets.py` 成功打补丁生成目标 KPM 并在物理设备上通过 12/12 强判据（详细记录见 [`Tester/reports/runs/2026-10-08-re_kernel_x-1.6_unified_port_live#1.md`](../../Tester/reports/runs/2026-10-08-re_kernel_x-1.6_unified_port_live#1.md)）。

请求 Auditor 独立复核二进制移植工具与真实设备测试证据，并确认 AUD-003 闭环状态。
