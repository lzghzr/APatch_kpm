# 独立审计报告：新增 run_cmd_demo 模块与 2026-10-10 冻结候选全量代码审计

角色：Auditor（独立审计）。  
审计对象：
1. **新增模块 `run_cmd_demo` 1.2.0**（基于内核 Usermode Helper 的命令执行器）；
2. **`re_kernel` 11.7**（BTF 与静态/动态双模式冻结候选）；
3. **`re_kernel_x` 1.6-20261008**（BTF 与静态/动态双模式冻结候选）；
4. **伴随修改模块**：`hosts_redirect`、`dont_kill_freeze`、`cgroupv2_freeze`、`kpm_utils.h`。

基线提交：
- 源码冻结 commit：`2257f2291e2be77c8809c266393da9d9d093d7b4`
- 候选元数据登记 commit：`e855a3d515276acb8aefe58dc48a49e5d53ee312`

---

## 1. 身份与基线依据

Auditor 在隔离沙箱 `local/auditor-scratch/` 中使用 NDK 26.3.11579264（Clang `aarch64-linux-android31-clang`）独立重新编译全部关键产物，比对候选登记清单 SHA-256 逐位吻合：

| 模块 | 变体 | Build ID 与 instance_id | 在册 sha256 | 沙箱独立重编译 sha256 | 复核结果 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`run_cmd_demo`** | base | `run_cmd_demo-1.2.0+g9669c80f9942.r2e72bd0b.kpb51197a.ndk26.3.11579264#1` | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` | `d1ebd33b0675d4a6c655348615ffdd209a2910fc12d76c57574e7658a44eb1b7` | **PASS (100% 吻合)** |
| **`run_cmd_demo`** | debug | `run_cmd_demo-1.2.0_debug+g9669c80f9942.r534a6113.kpb51197a.ndk26.3.11579264#1` | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` | `a1a78b752d4638e3decce97088aa9df49f2384f7315127289258037c4a938cfc` | **PASS (100% 吻合)** |
| **`re_kernel`** | dynamic release | `re_kernel-11.7+g63a3af7d7034.r3efcc29a.kpb51197a.ndk26.3.11579264#1` | `fb00ca982319b7e7487085781a09aea4e41da9a3af05b10145149be8565d6fe9` | 逐字节匹配 | **PASS** |
| **`re_kernel`** | dynamic debug | `re_kernel-11.7_debug+g63a3af7d7034.rfd66d6af.kpb51197a.ndk26.3.11579264#1` | `3dba88b800871dac66e8a78ae84775213b0d967aa444d652fa6846065f6895c9` | 逐字节匹配 | **PASS** |
| **`re_kernel_x`** | dynamic release | `re_kernel_x-1.6-20261008+gc98feee61782.r05be2926.kpb51197a.ndk26.3.11579264#1` | `1fc76b126c5d81f14c4edeeef3cb662cd60494211cfbb405a81b926af8d97a45` | 逐字节匹配 | **PASS** |
| **`re_kernel_x`** | dynamic debug | `re_kernel_x-1.6-20261008_debug+gc98feee61782.rafb02aeb.kpb51197a.ndk26.3.11579264#1` | `e6ce734b2ad7c60290b495c86244a988e8180462711a63fb57e88cbecdd73304` | 逐字节匹配 | **PASS** |

工具链与平台支持：
- Android NDK：26.3.11579264（Clang 17.0.2）
- KernelPatch SDK commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`（0.13.9）

---

## 2. 证据来源表（结论 → 命令 → 归属角色）

| 结论 | 独立复现命令 / 证据 | 来源归属 | 是否独立复现 |
| :--- | :--- | :--- | :--- |
| **产物重编译哈希逐字节一致** | 沙箱 `local/auditor-scratch/` 独立执行 Clang 编译，对比 `metadata/modules/` SHA-256 完全吻合 | Auditor 独立重编译 | 是 |
| **run_cmd_demo 启发式安全扫描** | 运行 `python3 Auditor/tools/static_scan.py run_cmd_demo`，审查内存释放与边界 | Auditor 独立工具 | 是 |
| **产物 ELF 符号与导入导出审查** | 运行 `python3 Auditor/tools/artifact_audit.py --module run_cmd_demo`，11 项未定义导入均与 SDK 符号匹配 | Auditor 产物审计 | 是 |
| **run_cmd_demo 宿主单测与回归** | 独立执行 `python3 run_cmd_demo/tools/test_run_cmd.py`，185 项断言通过（ASan/UBSan） | Developer 测试集 | 是（沙箱独立执行） |
| **re_kernel / re_kernel_x 模式自检** | 独立执行 `test_modes.py` 与 `test_static.py`，双模式产物与 ABI 分派通过 | Developer 测试集 | 是（沙箱独立执行） |
| **仓库门禁 16 项全通过** | `python3 tools/check_repository.py --strict` 0 失败 0 警告（提及该脚本仅用于定位，未作依据） | 仓库门禁 | 是 |

---

## 3. 新增模块 `run_cmd_demo` 深度代码安全审计

### 3.1 架构与执行流程走查
`run_cmd_demo` 实现了在内核态调度执行 `/system/bin/sh -c <命令>` 的通道：
1. **控制入口**：通过 KernelPatch `ctl0` 接口传入参数；
2. **异步队列**：由 `kthread_worker` 专属内核工作线程串行消费，避免在控制调用上下文中阻塞内核；
3. **状态轮询**：通过 `ctl0 result` 查询命令执行进度（`idle` / `pending` / `ret=<退出状态码>`）；
4. **凭据建立**：从 `init_task` 派生 root 执行凭据，注入 SELinux `u:r:magisk:s0` 上下文；
5. **stdio 重定向**：通过 `filp_open`、`replace_fd` 将标准输入/输出/错误重定向至 `/dev/null`，防止污染内核控制台。

### 3.2 关键安全与稳定性审计判定

#### A. 内存与缓冲区安全（PASS）
- 命令输入缓冲区 `cmd_buffer` 固定为 4096 字节（`RUN_CMD_MAX_SIZE`）。在 `submit_cmd()` 中使用 `strnlen(cmd, sizeof(cmd_buffer))` 严格校验，若达到上限则返回 `-E2BIG`，杜绝输入溢出；
- 控制响应缓冲区在 `run_cmd_control0()` 中强制要求 `outlen >= RUN_CMD_REPLY_SIZE`（32 字节），采用 `snprintf()` 格式化并以 `compat_copy_to_user()` 精确拷贝实际长度，修复了历史未初始化内存泄露缺陷（**DEV-016 经独立复核已闭环**）。

#### B. 并发互斥与执行状态机（PASS）
- 采用模块私有中断屏蔽自旋锁 `run_cmd_lock()`（`daifset #2` + 原子交换）；
- 严格单任务串行化：当 `cmd_status == CMD_PENDING` 时，任何新提交均返回 `-EBUSY`，防止并发覆盖命令缓冲区；
- `kthread_queue_work()` 若入队失败，立即持锁恢复 `cmd_status = CMD_DONE` 并设置 `cmd_result = -EAGAIN`，无死锁或状态挂起风险。

#### C. SELinux 凭据与域转换（PASS，附真机依赖提示）
- 模块通过 `security_secctx_to_secid(RUN_CMD_CONTEXT, ...)` 解析目标 `u:r:magisk:s0` 的 SID；
- 支持传统内核（通过 `selinux_task_getsecid` 校验初始 SID）与现代动态 LSM blob 内核（加上 `selinux_blob_sizes.lbs_cred` 动态偏移）；
- 在 `run_cmd_prepare()` 中通过 `override_creds()` 在受限域下打开 `/dev/null` 并调用 `replace_fd()`，随后即刻调用 `revert_creds()` 恢复上下文，生命周期处理严谨；
- **真实环境依赖**：若目标系统的 SELinux 策略中不存在 `magisk` 域或已被去除，模块将在加载阶段直接返回错误（安全失败）。

#### D. 卸载安全致命约束（HIGH ATTENTION - 架构固有边界）
- **审计发现**：[`run_cmd_demo/run_cmd.c:302-306`](file://<repo>/run_cmd_demo/run_cmd.c#L302-L306)：
  ```c
  static long run_cmd_exit(void* __user reserved) {
    if (cmd_worker) {
      logkm("WARNING: unloading is unsupported; KP will free live worker callbacks\n");
      return -EBUSY;
    }
  ```
- **技术成因**：KernelPatch 框架在 RCU 读锁上下文（原子上下文）中调用模块 `exit` 回调。在此上下文中调用 `kthread_destroy_worker()` 等待工作线程退出属于非法睡眠操作（触发 RCU stall / panic）；而 KP 0.13.9 在模块 exit 返回非零时仍可能继续卸载模块。若用户强行卸载模块，内核工作线程若再次调度到已释放的模块代码区，必将引发致命崩溃。
- **审计定性**：模块在 `README.md` 与 `KPM_DESCRIPTION` 中明确声明 **`DO NOT UNLOAD`（禁止卸载，移除需重启设备）**，且开发者已在加载日志中输出显式警示。此处理在当前 KP 架构下属于已知、有界的工程权衡，非逻辑实现缺陷。

#### E. 跨内核版本（4.4～6.6）推导兼容性（PASS）
- **BTF 路径**：使用原生 `btf_resolve_size` 代替了易触发空指针的缓存 API（**DEV-021 经独立复核已闭环**）；
- **汇编指令路径**：限定 32 条指令窗口内识别 `call_usermodehelper_exec` 的 `path` 读取与 `CBZ/CBNZ` 检查，修复了 `CONFIG_STATIC_USERMODEHELPER` 下静态空路径问题；
- **旧版 kthread worker 支持**：针对缺乏 `kthread_create_worker` 的 4.4/4.9 内核，通过 `__init_kthread_worker` 链表特征自动推导 `legacy_worker_size` 并在堆上清零分配，回退路径完备。

---

## 4. `re_kernel` 与 `re_kernel_x` 新增代码审计

### 4.1 BTF 支持与动态/静态双模式架构
1. **BTF 字段抽取**（`re_btf.c`）：
   - 两模块均支持通过 `bpf_get_btf_vmlinux` 读取目标内核 BTF，精准解析 `binder_buffer`、`binder_stats`、`task_struct`、`sk_buff` 等字段偏移；
   - 提取逻辑使用成员名称匹配与类型解析，未引入写操作，BTF 缺失时安全降级回汇编推导或静态基线。
2. **静态基线（Baselines）**：
   - 静态模式下将 45 个 `int16_t` 结构体偏移置于 `.data.re_offsets` 独立数据段，声明为 `volatile` 防止编译器立即数折叠；
   - 配合仓库根目录 `patch_offsets.py` 支持离线二进制修改，使得无 NDK 环境亦可适配目标设备。
3. **伴随模块日志清理**（`cgroupv2_freeze`, `dont_kill_freeze`, `hosts_redirect`）：
   - 移除了未定义行为的冗余调试输出，保留纯净的内核调用与返回值，代码安全性提升。

### 4.2 已知问题单跟踪
- **`AUD-007`**（`re_kernel` 与 `re_kernel_x` 预处理包含及条件宏风格不一致）：
  - 已报告给 Developer 整改。Developer 随后提交修复 `55c3b1c` / `820165f` 与交接 `3dfd6ce`，Auditor 经独立重编译与 AST 走查复核后已正式 **CLOSED**（详见 [`2026-10-10-AUD-007-verification.md`](2026-10-10-AUD-007-verification.md)）。

---

## 5. 同源风险声明

- **独立二进制重编译**：Auditor 在沙箱 `local/auditor-scratch/run_cmd_demo/` 中使用独立命令行重新编译，未调用维护方构建脚本（提及 `tools/build_candidate.py` 仅用于定位，未作依据）；
- **ELF 独立解析**：采用 `Auditor/tools/artifact_audit.py` 直接自解析 ELF 头部与符号表，未调用实现方 harness 脚本（提及 `kernel_img/offset_harness` 仅用于定位，未作依据）；
- **同源风险范围**：`run_cmd_demo` 离线推导测试集（`test_compat_offsets.py`）依赖的 10 份内核镜像语料与实现方同源，该模块在目标设备上的实际表现仍须由 Tester 在真机上实测确认。

---

## 6. 未验证清单

1. **`run_cmd_demo` 真实设备端到端执行验证**：
   - 尚未在 Android 4.4（旧版 worker / 无 BTF）及 Android 15（5.15 / 6.6 GKI 现代 worker）物理设备上加载；
   - 尚未验证真实 SELinux 策略下 `u:r:magisk:s0` 凭据的提权有效性与 `/system/bin/sh` 执行权限；
   - 尚未验证命令输出重定向文件（如 `id > /data/adb/run_cmd`）的文件生成事实。
2. **`AUD-007` 代码风格对齐整改**：
   - Developer 已提交修复并在 [`Developer/reports/responses/2026-10-10-AUD-007.md`](../../Developer/reports/responses/2026-10-10-AUD-007.md) 响应；Auditor 经独立复核已确认闭环（详见 [`2026-10-10-AUD-007-verification.md`](2026-10-10-AUD-007-verification.md)）。

## 维护者脱敏记录（2026-10-10）

本轮将设备连接标识及本机路径改为占位符；技术内容与角色结论保留。原件和原始 SHA-256 保存在本地维护者证据目录。
