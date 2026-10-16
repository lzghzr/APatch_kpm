# 开发者请求：动态版补非 BTF 降级路径（含旧 KP 的二进制变换件）

角色：维护者 → Developer。来源：**用户决定**——"不改文档，改代码：给动态版加非 BTF 降级"。

## 事实依据（发布轮四趟真机，`Tester/reports/runs/2026-10-14-nomount-2.1.1-20261014-live#1.md`）

| 环境 | 动态版现象 | 根因 |
| --- | --- | --- |
| Linux 4.19（无 BTF，KP 可加载模块） | VFS `file`/`inode`/`dentry` 布局**字节流推导成功**，但进入 `nm_prepare_control_engine` → `calculate_btf_control_layout` 时 `nm_get_btf` 返回 `-ENODATA(-61)`，模块 fail-closed 拒绝加载（`rc: -61`） | **control layout 只有 BTF 路径，没有非 BTF 降级** |
| Linux 4.4（旧版 KernelPatch `d04`） | KP 符号解析阶段 `unknown symbol: kallsyms_lookup_name_by_suffix` → KP 安全拒绝（`rc: -2/-ENOENT`），模块未执行 | 动态件直接面向最新 KP 构建，依赖新版 KP 符号（**属既有二进制兼容范畴，不是源码问题**） |

两趟都**未致死机、系统正常启动**，属安全 fail-closed。

## 请求内容

### A. 源码（只面向最新 KernelPatch，不得引入低版本兼容分支）

1. **给 control layout 加非 BTF 降级**：BTF 不可用时（`-ENODATA`）改走"目标支持的固定小窗口推导"取得 control layout 所需字段，与现有动态偏移推导同一机制、同一判据；
2. **不得猜偏移**：字段或共同布局无法确认时必须继续 fail-closed 停止加载（保持现有安全语义），并在日志里区分"BTF 不可用已降级"与"推导失败"；
3. 降级只影响**取值来源**，不得改变协议结构、回调集合、调用序列与生命周期；
4. 交付时给出：非 BTF 目标上的推导依据（字节锚点/窗口）、失败面清单、以及"哪些内核版本仍必须用静态版"的边界结论。

### B. 二进制变换件（旧 KP，按仓库既有机制）

4.4 的失败在 KP 符号解析，属**旧 KP 兼容**范畴：请按现行规则对**已构建的动态件**做 `patch_offsets.py legacy-kp` 变换，产出 **动态 + legacy-kp** 派生件（落在 `artifacts/binary-port/nomount/<派生 sha256>/`），并给出 base instance、base 哈希、工具哈希与命令、派生哈希；
5. 派生件与源码/Makefile 的兼容内容一律不进内核源码（AGENTS.md 硬规则）。

## 交付后流程（维护者安排）

- 候选与派生件登记 → Auditor 独立审计（非 BTF 降级路径的推导依据、失败面、是否越界改动协议/生命周期）+ 变体差异判定；
- Tester 在 **4.19**（非 BTF 动态）与 **4.4**（动态 legacy-kp 派生件）实测，并与静态趟对比；5.15 动态功能路径同样需要一次真机证据（此前从未验证过 BTF 路径的功能面）。

## 与当前发布的关系

`2.1.1-20261014` 已通过发布审计与四趟真机（静态两目标 20/20；动态在无 BTF/旧 KP 上 fail-closed）。**用户选择改代码而非改文档，因此本请求视为发布前置项**：在本轮落地并通过独立验证前，发布按暂停处理；若用户改主意要带限制发布，维护者再据此调整。
