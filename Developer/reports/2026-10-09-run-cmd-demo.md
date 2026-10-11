# run_cmd_demo 立项与 UMH 执行路径修复

角色：Developer。使用者确认正式建立 run_cmd_demo，按当前公共宏及偏移规则重建，并确认本轮采用加载参数执行命令、ctl0 只读结果。版本 1.1.0，KPM 注册名与目录名均为 run_cmd_demo。本轮尚未提交冻结，未操作设备；这是实现方自检，不是独立审计或实机结论。

## 立项范围与修改

- 加载参数整体传给 `/system/bin/sh -c`，初始化阶段同步等待 UMH 完成；模块登记后 `ctl0 result` 读取保存的结果。连续执行需卸载后重新加载。依赖或偏移准备失败中止加载；命令执行失败仍保存其 errno/wait status，由结果接口返回。模块加载返回 0 表示结果已保存，不代表命令成功。
- 使用 `call_usermodehelper_setup` 的 init 回调对传入的新 cred 调用 `set_security_override_from_ctx`，默认域 `u:r:magisk:s0`。回调失败由内核终止该 helper；记录换域结果和 UMH 返回值，不自动修改策略。
- 删除 exec/async 两个常驻 hook、argv 偏移、task_ext 依赖及本地宏副本。只恢复本模块创建的 subprocess_info.path，保留对静态 UMH 空路径的处理。
- 偏移计算统一在加载准备入口，使用 kpm_utils.h 的指令宏：32 条固定窗口内的 64 位 LDR，从 X0 读取指针，随后三条内对应寄存器的 64 位 CBZ；首个候选不匹配即失败，不继续接受后续偶然候选。不扩大窗口。入口首条 B 仅跟随一次。
- 在公共宏的 B/BL 指令分组加入 B、imm26 和有符号 label，沿用既有模板及 ARM 编码。未知偏移用 -1；不再使用大数哨兵或复制 SELinux 布局。
- 响应只复制 snprintf 产生的字符串及终止符，检查输出容量和复制结果。任意 ctl0 命令被拒绝，结果读取不再创建 helper。构建加入仓库当前 ARM64 寄存器和 builtin 限制，C 文件按 .clang-format 格式化。

使用者日志中 `cmd=ls,ret=-13` 对应 kernel 域执行 shell_exec 的 execute 拒绝，命令尚未开始；旧 ctl0 随后返回 0。该日志未附产物 SHA-256，不能绑定本轮新产物或某份历史归档，也不能据此确定旧 priv_sel_allow 未生效的内部原因。

## 身份与构建

统一入口：`python3 tools/build_candidate.py run_cmd_demo --toolchain ndk26.3.11579264 --target "all debug" --env ANDROID_NDK=<ndk> --allow-dirty --handoff <新清单>`。

构建所记录完整 source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；SDK：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。工作树 dirty，模块源码尚未进入该提交，构建输入 tree SHA-256 为 `74e8423baf6e976f9b2dd23f8e274ac09a9cf04329d4b460b33b7345c2f1da14`。以上提交是探索基点，不能单凭它重建本轮字节；完整输入指纹和构建参数见[探索清单](handoffs/run_cmd_demo-1.1.0-20261009-exploration.json)。冻结后必须重新从干净提交构建候选，不将本清单当作候选交接。

| 变体 | instance_id | 产物 SHA-256 |
| --- | --- | --- |
| base | run_cmd_demo-1.1.0+g74e8423baf6e.rdfa4ecbd.kpb51197a.ndk26.3.11579264#1 | 03a7bfec352cea49eebca337c6140b31aec23a61987a19146a95c58b06e3d9a4 |
| debug | run_cmd_demo-1.1.0_debug+g74e8423baf6e.r7a13e7ab.kpb51197a.ndk26.3.11579264#1 | 2880474a1b06a3476d7c9cb05443e39264003ad33b2ef5443f4761da3fee0e99 |

两份产物分别为 6432、6440 字节。构建无警告；ELF 为 ARM64 ET_REL，模块信息及初始化/退出节有效。5 项导入存在于 SDK 导出源码；未发现 task_ext、裸 memcpy/memset、FP/SIMD/SVE/x18 操作数。这不证明设备运行端的实际导出或 CFI 状态。

## Sony 5.15 离线证据与自检

使用者指定 `boot_67.2.A.3.178.img`。从 img 提取到新的本地目录，再独立于旧缓存重新运行实现方 kallsyms 提取，取得 159332 个符号；这仍是同源的 Developer 自检。提取器提示厂商头部 page_size 与 image_size 问题，按其既有内容识别路径处理，不覆盖原提取或旧偏移资产。

- call_usermodehelper_exec 地址 0x16fae4，32 条窗口中 0x16fb20 的 LDR X9,[X0,#0x38] 与 0x16fb2c 的 CBZ X9 对应。
- 另一处证据：call_usermodehelper_setup 在 0x16f1bc 用 STP X8,X23,[X0,#0x38] 写入 path/argv；X23 保存 argv 参数，X8 由 ADRP+ADD 指向静态路径字符串。该字符串内容为空，因此必须在 exec 调用前恢复本模块 helper 的 path。字段参考值 0x38 来自此处写入，不按内核版本猜测。
- 生产 C 的偏移计算对本轮重新提取的镜像指令得到 0x38。没有运行其它镜像，也没有声明其它内核已覆盖。
- 新模块 ASan/UBSan 夹具覆盖首次 LDR 不对应后续 CBZ、32 位读/检查、RET、窗口尾和窗口外、跳板、缺失符号、B label 正负边界；覆盖分配失败、换域失败不执行 shell、exec errno、原始 wait status、响应尾部不写入、非法 ctl0、短输出、复制失败及只读结果不重执行。
- 本轮新编探索夹具随使用者确认的接口从 ctl0 执行调整为加载阶段执行：准备算法单独以真实指令验证，init 夹具模拟准备阶段返回，验证失败时不创建 helper，以及命令错误保存到结果接口。修改依据是 KP 实际调用上下文；不是为了满足 mock 改写生产架构。该夹具尚未成为冻结候选的测试基准。
- 公共宏修改后，既有八组 Genl/Binder/指令 ASan/UBSan 回归全部通过，未修改或缩小已有套件断言。
- 仓库 regular 门禁通过；既有 171 份模块产物和归档文件的保护快照复核无变化。未修改共享 SDK、维护者元数据或 Auditor/Tester 文件。

本地证据：`local/run-cmd-demo-20261009-w0m6uo00/` 中 image/extracted/index.json、sony-kallsyms.txt、load-interface-host/receipt.json、load-interface-build-check.json、shared-macro-regression/receipt.json、protected.json、protected-after.json；构建日志为 `local/build_logs/20261009T044557Z-run_cmd_demo.log`。

## 正式问题单与后续复核

### DEV-016（中，归属 Developer）：旧控制接口复制未初始化响应尾部，未核对用户缓冲区长度

- 证据：旧代码 char msg[64]，snprintf 只生成 `_(._.)_`，却 compat_copy_to_user(...,sizeof(msg))；忽略 outlen 和复制结果。原文件的字节身份未冻结，证据来自本轮修改前的源码检查。
- 影响：可向已通过 KP 鉴权的调用方泄露未初始化内核栈字节，或越过调用方声明的缓冲范围；不推断为已证明提权。
- 修复：按实际响应长度复制，提前验证容量，复制不足返回 -EFAULT。生产结果接口主机边界自检通过。
- 频率：高频。置信度：源码已确认，真实泄露内容未采集。状态：fixed(待复核)。
- 关闭条件：冻结后由 Auditor 独立复核实际复制长度、初始化范围、短输出及复制失败，绑定新候选身份关闭；Developer 不关闭。

### DEV-017（高，归属 Developer）：旧 ctl0 在 KP 的 RCU 读侧同步等待 UMH

- 证据：构建 SDK module_control0 在 rcu_read_lock/read_unlock 之间调用 ctl0；原模块使用 UMH_WAIT_PROC，内核会等待子进程完成。另有模块回调与异步 helper 的生命周期耦合。
- 影响：可能触发 RCU 非法睡眠或 stall；原路径的并发卸载还可能使 helper 调用释放后的模块代码。严重度按可能造成内核故障定为高，不因尚无真机复现而降级。
- 修复：经使用者确认，执行放入当前 SDK 不持有该控制读锁的加载 init，UMH 完成后才登记模块；ctl0 只读结果，exit 没有在途模块 work 或待等待的 callback。没有尝试从模块解开调用方的 RCU 锁，也没有增加后台任务。
- 频率：未知。置信度：调用上下文源码已确认，运行时故障推断。状态：fixed(待复核)。
- 关闭条件：Auditor 从冻结源码独立核对手动加载路径、命令完成至模块登记的顺序及 callback 持有周期；Tester 再验证对应环境下的加载、结果读取、卸载。KP 自身并发管理接口的通用问题不在本轮修正范围，设备验证采用串行管理操作。

## 未验证与维护者接续

未执行真机加载、Enforcing 下换域、CFI 回调、标准输出重定向、长命令或卸载。目标域存在、use_as_override 与执行权限、实际 KP 导出、CFI 放行都需真机确认。换域失败时记录真实 errno，不能把后续 module load 的注册成功当作命令成功；观察 result 及 helper 日志。

当前没有命令超时；长驻前台命令会阻塞加载。使用方式面向开机完成后的手动 module load，不据本轮离线结果承诺内嵌早期开机事件可用。

维护者后续建立 run_cmd_demo 元数据并登记 DEV-016/017；本清单仅为 exploration。完成源码冻结后使用统一候选入口生成新身份，交 Auditor/Tester 独立复核。本轮不提交、不签名、不远程同步。


## 后续记录：按用户授权验证 UMH / SELinux 执行路径

本节追加此前尚未执行的设备验证。用户明确授权 Developer 连接 ADB，范围限于 UMH 和 SELinux 执行路径；反复执行接口恢复后不再继续 ADB 测试。以下是实现方探索记录，不替代 Auditor 审计、Tester 完整测试或维护者验收。本轮未提交、未冻结、未同步远端。

### 实测阻点与修复

Sony 5.15 / KP 0.13.9，SELinux Enforcing。原探索产物成功计算 `subprocess_info.path=0x38` 并进入 UMH 初始化回调，但 `set_security_override_from_ctx` 返回 `-13`。对应 AVC 为 `kernel → magisk` 的 `kernel_service use_as_override` 被拒绝，尚未执行 shell。

改用 `prepare_creds` 获取已授权调用者的凭据副本，在 UMH 初始化回调通过 `security_transfer_creds(new, snapshot)` 复制其 LSM 上下文。目标 Android 5.15 的 `security_transfer_creds` 调用 `cred_transfer`，SELinux 实现复制两个凭据中的安全数据，不再次申请安全 blob。helper 的 UID/GID 保持 UMH 创建的值；调用者凭据不修改，全局策略不修改。不再固定执行域字符串。

快照在 `UMH_WAIT_PROC` 返回后用 `abort_creds` 释放，setup 分配失败也释放。当前接口只在加载阶段执行一条命令，因此全局快照仅用于这次同步初始化；尚未支持并发或后台命令，不能直接把它挪入 ctl0。

首个复制实现加载时发现运行端未导出 `kf_prepare_creds` / `kf_abort_creds`。为这两个指针补齐模块自有定义并在初始化时从内核查找，最终产物不再导入它们。此失败为导入错误，未发生设备无响应，不属于设备死机重试。

### 身份和证据

- 完整 source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；工作树为 exploration，源码树哈希 `e778faa4e55dcbb7` 开头，完整值见清单。
- instance_id：`run_cmd_demo-1.1.0_debug+ge778faa4e55d.rd11fd39e.kpb51197a.ndk26.3.11579264#1`。
- SHA-256：`225a1c2d922dcae08be3c293b4f08cde01d32f7c552a5d630d20e46f8848d10c`，本地、归档与设备传入字节一致。
- 清单：[security-transfer exploration](handoffs/run_cmd_demo-1.1.0-20261009-security-transfer-exploration.json)。原清单与归档保留，不覆盖。
- 私有原始日志、命令回执、主机夹具、反汇编及汇总位于 `local/run-cmd-adb-20261009-path/`；公开报告只保留脱敏摘要。

| 判据 | 实测 |
| --- | --- |
| `id` 执行 | 输出 UID/GID 0，`u:r:magisk:s0`，`ret=0` |
| `exit 7` | `ret=1792`，保留 UMH_WAIT_PROC 原始 wait status |
| SELinux 状态 | 全程 Enforcing |
| 存活 | boot ID 不变、uptime 单调、ADB 持续响应 |
| 收尾 | 测试模块卸载，恢复原有模块清单，pstore 为空 |
| 既有资产 | 171 个已有文件 SHA-256 未变 |

最终产物的五项导入均在 SDK 导出源码中核对，且实际加载成功；无裸 memcpy/memset，无 FP/SIMD 或 x18 指令。主机 ASan/UBSan 夹具通过。

### 自检断言变更说明

本轮自检文件是本项目新增的探索夹具，不属于 Tester/Auditor 的外部 Oracle。凭据方案由“显式换域”改为“复制调用者上下文”，因此将原换域拒绝模拟替换为凭据快照分配失败、上下文复制和释放断言；`-EACCES` 仍作为 UMH 执行错误核对，没有将错误改成成功。原加载参数接口、固定扫描窗口、首个候选失败、用户缓冲区长度和复制结果断言继续保留。旧测试源码字节及运行回执仍在上一轮私有输出中，独立复核前不关闭 DEV-016 / DEV-017。

### 当前接口边界与后续事项

此轮仅完成执行路径修复。当前仍为“加载参数执行命令，ctl0 result 读取结果”，未恢复“加载一次、反复执行”。KP 的 module_control0 在 RCU 读锁内调用回调；unload_module 同样在 RCU 内调用 exit，且无论 exit 返回值如何都会释放模块。因此同步等待不能直接移回 ctl0，后台方案也不能依靠 exit 返回 EBUSY 阻止卸载。后续接口设计需先解决这两项调用上下文和回调生命期约束；不得把本轮设备证据外推为后台执行或并发卸载验证。


## 后续记录：1.1.1 反复执行接口

按用户本轮确认：保持 KP 源码及运行端，ctl0 改为异步提交，以明确“不要卸载模块”的使用约束处理 worker 寿命；本轮不连接 ADB。此前同步接口的探索副本与清单仅保留在私有输出中，没有作为最终交接输入。此处为 Developer 实现方自检，不代替独立审计、Tester 真机结论或维护者验收。

### 最终实现与协议

- 空参数加载只建立 worker；加载参数可选，作为第一条命令排队。
- ctl0 在 RCU 中仅检查参数、复制到模块自己的 4096 字节缓冲并调用原生 `kthread_queue_work`。不在 ctl0 调用 prepare_creds 或同步等待 UMH；最长命令 4095 字节。
- kthread worker 在可睡眠上下文调用 UMH_WAIT_PROC，保留原始 errno / wait status。排队成功响应 queued，读取状态为 idle / pending / ret=N。pending 返回 EINPROGRESS，执行中再次提交返回 EBUSY。排队失败保存 EAGAIN，worker 建立后的初始命令排队失败不使 init 失败，以免加载器释放仍在使用的模块。
- 命令在排队前复制，后续不借用 KP 的 ctl_args。一槽串行执行，不积压任意数量的命令。状态和结果由模块私有 IRQ 锁保护，该锁沿用 rek/rekx 的实现，不向内核传入猜测的 raw_spinlock_t 布局。先前探索产物发现两个原生锁指针未导出，最终产物已消除这两个导入。
- 凭据副本改为加载时创建并持有，所有后续命令继承加载者当时的 LSM 上下文。它不是每次 ctl0 调用者的凭据；worker 创建前初始化失败会释放，运行期间保留。helper 的 UID/GID 仍由 UMH 创建。
- kthread_work 来自 Android 5.15 头文件，使用 node / func / worker / canceling，worker 本体由内核分配。Sony 镜像在 kthread_worker_fn 的 0x182604/0x182610 读取 work.func(+0x10)，kthread_insert_work 的 0x1830d8 写入 work.worker(+0x18)，kthread_queue_work 的 0x182f9c 读取 work.canceling(+0x20)。本轮没有据此宣称所有旧内核兼容。

### 寿命约束（尚未关闭 DEV-017）

加载后不要卸载模块，需要移除或更换时重启设备。提示写入 KPM_DESCRIPTION、加载日志和 README；exit 也会记录警告并返回 EBUSY。当前 KP 忽略 exit 的返回值，因此这不是阻止卸载的保护机制。强行卸载可能释放 worker 回调引用的模块代码或数据，导致内核崩溃。用户已明确选择这一 demo 使用约束，未实现安全热卸载，DEV-017 不由 Developer 关闭。

ctl0 调用按顺序进行。模块的私有状态锁与 EBUSY 仅保护自己的执行槽，不能修复 KP 加载器自身并发替换 ctl_args 的寿命问题；本轮没有验证并发模块管理或并发控制请求。

### 自检与断言调整

主机 ASan/UBSan 直接包含生产控制、worker、UMH 及偏移函数。覆盖空参数加载、初始命令、初始排队失败仍注册、worker 创建失败及凭据释放、异步排队不触发同步 exec、命令副本、重复提交、idle/pending/done、原始错误及1792、响应初始化字节/长度/复制错误、加载者上下文保持与不支持卸载。固定扫描窗口及首个候选失败断言继续保留。

协议由“同步加载/只读 ctl0”改为“异步提交/查询”，因此先前只读 ctl0、空参数拒绝和每命令凭据释放断言不再描述最终接口；本轮仅调整实现方新增探索夹具并追加异步断言。旧夹具和回执保存在私有探索副本中，未改 Tester/Auditor Oracle。断言变化须独立复核，Developer 不自行宣称审计通过。

Sony 离线入口自检通过，path=0x38；新 worker 所需函数均可在镜像符号表中找到。NDK26.3 base/debug 构建成功；最终 ELF 的八项导入已与 SDK 导出源码核对，无裸 memcpy/memset、原生锁指针或 task_ext 导入，无 FP/SIMD/x18 指令。171 份已有资产哈希未变。私有锁的 ARM64 指令由真实 NDK 构建检查，宿主锁只是夹具替身，不证明真实 SMP 安全。

私有证据位于 `local/run-cmd-repeat-20261009/`，包括 async-final-host、worker 函数反汇编和 async-final-build-check.json。上一轮 ADB 的 UMH 路径事实不自动继承为本轮 worker 调度、CFI 或异步接口实机结论。本轮未提交、未冻结、未同步远端。

### 最终探索身份

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true，source_tree_sha256：`dafc62f90513bdea61e02c741836b2f9d5a8d4e57dedeb9f4bc73ead74300153`。
- instance_id：`run_cmd_demo-1.1.1_debug+gdafc62f90513.rbdf5e860.kpb51197a.ndk26.3.11579264#1`。
- debug 产物 SHA-256：`3a6d3e8beffa2c0a314498888cd6e05d000d1035ebb702a77bb9e094e23a16a6`。
- 清单：[1.1.1 异步探索](handoffs/run_cmd_demo-1.1.1-20261009-async-final-exploration.json)。

## 后续记录：使用文档与注释整理

README 收拢为使用协议、凭据与兼容性、构建自检；代码注释说明当前锁、结构体来源和 helper 路径。卸载警告及接口错误语义保留。执行逻辑与测试断言未变。

格式检查、ASan/UBSan 宿主自检及 Sony 5.15 入口自检通过，path=0x38。NDK26.3 base/debug 构建通过，产物与上一轮逐字节一致；171 份既有资产哈希未变。原开发记录与历史身份保留，本节为 Developer 探索自检，当前异步接口仍待独立审计与真机验证。

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true。
- source_tree_sha256：`8557a85997e3dcca6bd5e269af7bd4867832c33154276f751cb2d01c9ca031e8`。
- base instance_id：`run_cmd_demo-1.1.1+g8557a85997e3.ra7fc4f50.kpb51197a.ndk26.3.11579264#1`；SHA-256：`613cb10e1d22cd1d793cf0bf9911f3d5ff7c0ba187faf66e8f2021516e7a3d5e`。
- debug instance_id：`run_cmd_demo-1.1.1_debug+g8557a85997e3.r893464cb.kpb51197a.ndk26.3.11579264#1`；SHA-256：`3a6d3e8beffa2c0a314498888cd6e05d000d1035ebb702a77bb9e094e23a16a6`。
- 构建清单：[1.1.1 文档整理探索](handoffs/run_cmd_demo-1.1.1-20261009-documentation-exploration.json)。
- 自检回执：`local/run-cmd-repeat-20261009/documentation-host/receipt.json`；字节与资产核对：`local/run-cmd-repeat-20261009/documentation-build-check.json`。


## 后续记录：1.1.2 标准流初始化

使用者反馈裸 `ls` 得到 `ret=256`；按建议执行 `ls /system/bin >/dev/null 2>&1` 后，提供的日志记录 `helper result=0`。该输入同时包含 `ls` 在 `untrusted_app` 域中遭到文件 getattr 拒绝。反馈未提供产物哈希，作为诊断事实保留，不能绑定为本轮新产物的真机结论；两次命令路径不同，也不能仅凭对照排除目录权限的影响。

原生产回调只复制 LSM 上下文，没有建立标准描述符。目标 UMH 由内核线程创建执行进程，Toybox 的输出封装会因 stdout 写入失败而退出（[源码](https://android.googlesource.com/platform/external/toybox/+/b73f894/lib/xwrap.c)）。标准流是本轮明确修复点，SELinux 域限制按实际上下文记录。

### 自查决定（Decision）

**修改（Modify）**

### 挑战

#### 有效性

在 UMH init 回调使用 `filp_open("/dev/null", O_RDWR, 0)`，通过 `replace_fd` 安装 0、1、2，再以 `filp_close` 放掉打开引用。替换成功返回对应 fd，回调统一返回 0；原生错误按负 errno 返回，部分安装的描述符由 helper 退出清理。命令仍可自行重定向输出。执行域继续来自加载者，UID/GID 由 UMH 创建；UI 加载时观察到的 untrusted_app 限制不能由标准流修复消除。

#### 简洁性

用户自行重定向是可行的较简基线，但每条产生输出的命令都需处理 fd。统一建立三条标准流使普通命令具备稳定的默认输入输出；复用原生文件接口，仅增加三个加载依赖，省去文件表私有布局推导。初始化位于可睡眠的 helper 回调。

#### 后果

缺少任一新增函数时初始化失败；文件打开或安装失败时 helper 停止执行并报告真实错误。默认输出丢弃，需要内容时仍重定向到文件。原有 worker 生命周期和 DEV-017 的卸载约束继续适用。

### 修订建议

采用标准流初始化；需要 root 及相应 SELinux 权限时从已授权 root 环境加载，按真实域和 AVC 核对执行权限。保留原始 errno / wait status 协议。

### 自检与证据范围

ASan/UBSan 宿主自检、Sony 5.15 离线入口自检及格式检查通过。Sony 镜像中新增 `filp_open`、`replace_fd`、`filp_close` 入口均可取得，既有 path 推导为 0x38。NDK26.3 base/debug 构建成功，ELF 仍为八项 KP 导入，已核对 SDK 导出；实际反汇编无 FP/SIMD/x18。171 份既有资产及本轮开始时登记的 232 份归档/清单文件哈希保持一致。

69 条既有 C 断言原文（忽略格式空白）均保留，追加 16 条断言，覆盖新依赖缺失、打开失败、三处安装失败、成功引用数及 helper 退出释放。夹具增加原生文件接口的替身和进程退出时关闭 fd 的模型。首次新增依赖自检留下了用于偏移扫描的合成入口指针，导致宿主夹具执行数据；已在该检查结束后恢复原有执行替身，修正后新目录自检通过，生产控制流按内核契约实现。

本轮遵循 no-negative-echo 核对 README、代码注释、元信息及新清单；使用文档描述当前行为，历史记录只追加。私有自检在 `local/run-cmd-stdio-20261009-xywnvid0/host-2/receipt.json`，产物/断言/资产核对在同目录上级的 `build-check.json`。这是 Developer 自检；新产物的实际文件操作、重定向、SELinux 和异步调度仍需独立审计及真机验证。

### 探索身份

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true，source_tree_sha256：`248fe0d87ab0365a3d4d367dc5e8ce9cc8ef16bfeca4deea69608f029db2c741`。
- base instance_id：`run_cmd_demo-1.1.2+g248fe0d87ab0.r41df1319.kpb51197a.ndk26.3.11579264#1`；SHA-256：`ef013f3b968dfb9740c775c86280b1fb8ef660548559a4009e069b552304e597`。
- debug instance_id：`run_cmd_demo-1.1.2_debug+g248fe0d87ab0.r0d93d61c.kpb51197a.ndk26.3.11579264#1`；SHA-256：`e8c1dbd5e4f251b4387f0002eeb15859b3b243eb59bb05a7a03e30b2fc0c3f5c`。
- 清单：[1.1.2 标准流探索](handoffs/run_cmd_demo-1.1.2-20261009-stdio-exploration.json)。


## 后续记录：1.1.3 标准流凭据一致性

使用者反馈命令 `ls /system/bin >/data/adb/run_cmd 2>&1`，日志出现 sh 在 untrusted_app 域使用 kernel 域创建的 `/dev/null` FD 被拒绝，helper result=11。反馈没有产物哈希；原 1.1.2 源码可确认 `filp_open` 在 UMH 提交新 cred 之前执行，因此 FD 创建者仍为 kernel 域。本轮先修复已确认的域不匹配，SIGSEGV 的具体原因和与拒绝的因果关系尚待复核。

### 自查决定（Decision）

**修改（Modify）**

### 挑战

#### 有效性

目标 5.15 的 UMH 以 `prepare_kernel_cred(current)` 创建 helper 凭据，回调只复制 LSM 安全数据，随后由 UMH commit。UID 与 SELinux 域是独立属性；app 域不证明非 root。目标 SELinux 的 file_alloc_security 保存创建者 SID，file_has_perm 检查调用者与该 SID 之间的 FD__USE 权限。原实现跨域打开 FD，可独立确认不匹配。

#### 简洁性

复用原生 `override_creds(new)` / `revert_creds(old)`，将临时覆盖严格限定为 `/dev/null` 打开操作；成功和失败都先恢复旧 cred，再处理结果或安装 FD。两项新增函数在 Sony 镜像中可解析。UID/EUID 日志直接复用 KP 已推导的 cred_offset 读取 UMH 传入的 new 凭据。

#### 后果

helper 在其将使用的凭据下打开标准流，文件访问仍受该域策略约束。回调返回前恢复原凭据，满足后续 UMH commit_creds 的前置条件。FD 一致性不等于任意命令具有 SELinux 权限，也不证明 SIGSEGV 已消失；后续真机按同一命令复核。

### 修订建议

采用凭据一致的标准流初始化，并以新增 helper UID/EUID 日志确认身份。11 是 SIGSEGV 的原始 wait status，不能解读为正常退出码。用户态子进程终止与整机无响应分别记录；本轮没有收到整机失联证据，也未连接 ADB。

### DEV-018（中，归属 Developer）：标准流 FD 创建域与执行域不匹配

- 证据：1.1.2 源码在提交新凭据前以原 kernel 凭据打开标准流；用户日志记录 untrusted_app → kernel 的 fd use 拒绝，反馈未绑定产物哈希。
- 影响：命令启动或标准流使用失败；该日志还记录子进程 SIGSEGV，因果关系未确认，不将其定性为内核崩溃。
- 频率：应用域加载时可达，具体频率未知；置信度：源码不匹配已确认，运行端绑定和 SIGSEGV 原因待核对。
- 修复：打开文件期间临时使用 new 凭据，随后恢复；状态：fixed（待独立复核）。
- 关闭条件：Auditor 独立核对 override/revert 配对、UID 与 LSM 处理及导入；Tester 在绑定的新产物上复核标准流、重定向和 helper 终止状态。Developer 不关闭该单。

### 自检与身份

ASan/UBSan、Sony 5.15 入口自检和格式检查通过，path=0x38；追加 12 条断言，保留 85 条已有断言，覆盖临时凭据配对、打开时的创建域、执行域一致性及新增依赖。原打开失败与三处安装失败用例仍执行，凭据恢复由新断言覆盖。宿主 Mock 仅为逻辑自检，不能证明真实 SELinux、RCU 或 CFI 行为。

NDK26.3 base/debug 构建成功，九项 ELF 导入核对 SDK 导出，实际反汇编无 FP/SIMD/x18。171 份既有资产及本轮开始的 237 份归档/清单文件保持原哈希。最终元信息、README、代码注释及清单按 no-negative-echo 回读；历史报告只追加。私有回执在 `local/run-cmd-credentials-20261009-c11ci4cg/host-2/receipt.json`，产物与断言核对在同目录上级的 `final-build-check.json`。

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true，source_tree_sha256：`5bdf516adbfa9fa17a4b363a647be14e4bf66c4ce4afe21d4cc00c89ec1a0e78`。
- base instance_id：`run_cmd_demo-1.1.3+g5bdf516adbfa.r6d68833b.kpb51197a.ndk26.3.11579264#1`；SHA-256：`b38cbf6038d5dd22466ec1e93827cb0fc9d661f4ab9dc9488ba4732369cd9702`。
- debug instance_id：`run_cmd_demo-1.1.3_debug+g5bdf516adbfa.rc1062de3.kpb51197a.ndk26.3.11579264#1`；SHA-256：`f3f1a1ca41f6dbe4f9bc7cd7a144e6276abbeb8a0198eaf820b3b118b568bb1c`。
- 清单：[1.1.3 FD 凭据探索](handoffs/run_cmd_demo-1.1.3-20261009-fd-credentials-exploration.json)。


## 后续记录：1.1.4 root 执行域

使用者反馈 helper 初始化日志明确记录 UID=0、EUID=0，而 shell 仍在 untrusted_app 域，进入 adb_data_file 目录被 search 拒绝，raw result=256。可据此确认 UID 与执行域独立；shell 的输出重定向失败。反馈没有产物哈希，保留为诊断输入，不能替代绑定身份的真机结论。

### 自查决定（Decision）

**修改（Modify）**

### 挑战

#### 有效性

加载时通过 prepare_kernel_cred(init_task) 建立独立凭据与 LSM blob，使用 security_secctx_to_secid 将策略中的 u:r:magisk:s0 解析为非零 SID，仅修改新凭据的当前 SID，再通过 selinux_cred_getsecid 回读。每次 helper 仍由原生 security_transfer_creds 复制完整 LSM 数据，并以 new 凭据打开标准流。init_task 为内核初始任务；目标基准源码的初始 SELinux blob 由零初始化建立，只写 osid/sid，exec/create/key/sock SID 为零。未修改初始任务的凭据。

SID 位置来自 selinux_cred_getsecid 的前 16 条指令，先核对 cred.security 与 KP 偏移，再匹配 SID 读取及写入 secid 输出。多 LSM 形态核对 ADRP/LDRSW 的地址等于 selinux_blob_sizes.lbs_cred，读取该运行值后与 SID 字段偏移相加。首候选匹配失败即停止，不寻找后续替代；不认识的编译形态返回 -ENOENT。Sony 5.15 入口核对为 cred.security=0x78、SID 字段=0x4。

#### 简洁性

保留 worker、UMH 回调和标准流接口，替换原加载者凭据来源。set_security_override_from_ctx 的原生路径带 kernel_service use_as_override 策略检查，已有实机调用曾失败；新路径只修改模块独立的新凭据。新增短 getter 锚点、SID 解析接口及 init_task 数据符号，复用 KP cred_offset 和既有 ARM 指令宏。此版本使用 magisk 策略域作为执行配置，该域来自此前已授权 root 环境的 UMH 实测。

#### 后果

符号、字段、域解析或 SID 回读失败均在 worker 创建前停止加载，退出回调释放已建立的独立凭据。执行仍受目标域策略和原生 exec 转域检查约束；SID 存在、初始化回读成功均不证明 shell 最终留在该域。worker 建立后的 DEV-017 卸载限制延续，更换模块仍需重启。其它内核的布局、策略与编译形态没有本轮实测覆盖。

### 修订建议

采用独立 root 执行凭据。真机以同一产物提交 `{ id; cat /proc/self/attr/current; ls /system/bin; } >/data/adb/run_cmd 2>&1`，查询 result 并读取文件，分别核对 UID、exec 后域和目录操作。加载日志中的 context/SID 只说明模板凭据；helper UID/EUID 是 exec 前身份。Developer 本轮未连接 ADB，实机与独立审计仍待完成。

### DEV-019（中，归属 Developer）：界面加载后执行域受到应用权限限制

- 证据：原 1.1.3 使用 prepare_creds 保存加载者 LSM 上下文；反馈记录 UID/EUID=0 与 untrusted_app 域的目录 search 拒绝，未绑定运行产物 SHA-256。
- 影响：界面加载后 root 命令无法访问 /data/adb 等受限对象；模块的重复执行协议仍能返回结果。
- 频率：应用域加载时可达，具体策略依赖设备；置信度：源码与输入日志一致，绑定产物的最终执行域尚待复核。
- 修复：建立独立内核凭据，设置现有 magisk SID 并回读；状态：fixed（待独立复核）。
- 关闭条件：Auditor 核对字段推导、私有 blob 修改与原生引用生命周期；Tester 在绑定本轮产物的 Enforcing 环境复核 shell 实际 UID/域、标准流及目标重定向。Developer 不关闭该单。

### 测试夹具调整范围与技术依据

97 条既有 C 断言原句（忽略格式空白）均保留，新增 25 条。生产凭据来源由 prepare_creds 变为 prepare_kernel_cred(init_task)，因此夹具按原生契约改为复制内核基准，建立独立 security 指针；transfer 替身复制安全字段到 helper 自有存储。依赖清单相应把 prepare_creds 改为 prepare_kernel_cred；原断言没有放宽。原固定 context=3 的检查现在对应目标执行域，新用例明确将加载者 context 设为 29，验证其与执行模板及初始内核 context=1 的隔离。

新增检查包含域不存在/零 SID/getter 回读不一致、新依赖缺失、首候选失配、RET/窗口边界、SID 数据流寄存器、32 位输出以及 LSM blob 的零/非零加量、负值和全局地址失配。真实 Sony getter 指令保持原字节，用整页对齐镜像相对放置保留 ADRP 几何关系；blob 在宿主采用启动后参考值 0，与镜像文件中初始化前的 sizeof 值区分。非零加量另用合成用例覆盖。夹具及镜像验证为同源 Developer 自检，需 Auditor 独立复核其参考值与语义，不能替代真实运行。

### 自检与证据范围

ASan/UBSan 宿主自检、Sony 5.15 path/SID 入口核对及 clang-format 检查通过。NDK26.3 base/debug 构建成功，九项 ELF 未定义导入均在 SDK 导出表，实际指令检查未发现 FP/SIMD/x18 使用。247 份本轮开始时的归档/清单与 171 份既有资产保持原 SHA-256；既有构建与清单保留。独立反例审查支持私有凭据生命周期，同时要求 SID 非零、getter 回读以及 exec 后域的真机判据；它属于 Developer 自查，不是 Auditor 结论。

私有回执：`local/run-cmd-selinux-20261009-uifgffb7/host-2/receipt.json`、`oracle-check.json`、`build-check.json`。一次临时寄存器检查把反汇编地址 b0/b4 等误识别为寄存器，已将该一次性检查限定到冒号后的指令操作数；生产源码与基准断言未因该诊断修改。最终代码、README、元信息与新清单已回读，并按 no-negative-echo 检查。此产物为 dirty exploration，尚未冻结提交，不能作为正式候选交接。

### 探索身份

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true，source_tree_sha256：`ac226093b768227529b760b4a27d6dbbf80d24bdc54660c02cb387cb323db328`。
- base instance_id：`run_cmd_demo-1.1.4+gac226093b768.r8b9f4e91.kpb51197a.ndk26.3.11579264#2`；SHA-256：`fefc5f280b25827878bd4c9daafe305d5bec67ac5bb76a5e2f74a7482628cc33`。
- debug instance_id：`run_cmd_demo-1.1.4_debug+gac226093b768.r14954336.kpb51197a.ndk26.3.11579264#2`；SHA-256：`04164755c3d4b344cb4f1a37b756250e28574c1ec98b156cf567a7ead25620b4`。
- 清单：[1.1.4 root 凭据探索](handoffs/run_cmd_demo-1.1.4-20261009-root-credentials-exploration.json)。


## 后续记录：1.1.5 cred.security 偏移来源修复

使用者反馈 1.1.4 加载时 path=0x38，cred_sid=0xffffffff，初始化返回 -ENOENT。该失败发生在 worker、凭据模板和 helper 建立前；尚未执行命令。反馈没有产物 SHA-256，作为诊断输入保留。

### 自查决定（Decision）

**修改（Modify）**

### 挑战

#### 有效性

KP 声明并导出 cred_offset，但不意味着每个成员均已推导。0.13.9 的 task_cred.c 将 security_offset 初始化为 -1，没有任何 cred_offset.security_offset 赋值。原 1.1.4 将 getter 中实际 0x78 与该哨兵强制比较，立即停止；原宿主夹具提供已知有效偏移，遗漏运行端未计算的状态。本轮在原版生产码夹具中仅把 Sony 验证时的 KP 输入设为 -1，精确复现 ret=-2、sid=-1。

修复将完整 getter 链中的首个 cred->security LDR 偏移保存为模块自己的 cred_security_offset，后续凭据访问使用该值。KP 已给出非负值时仍交叉核对；未计算时按同一完整指令链推导，不改 KP 的全局偏移表。两个字段只在 SID 输出链匹配后一起保存，SID 扫描仍为前 16 条，首候选失败即停止。

#### 简洁性

复用原短 getter，一次取得 security 与 SID，增加一个本地缓存字段，无新增符号或扫描窗口。只跳过比较无法修复后续对 cmd_cred 的访问，必须同时更换存储和消费路径。私有模板、SID 回读、标准流及 worker 接口保持既有契约。

#### 后果

未知编译形态仍返回 -ENOENT，已提供的 KP 偏移与 getter 不一致仍拒绝。修复解除错误的未初始化字段依赖，未证明真实设备上的 shell 域、策略及目录权限已满足目标。DEV-019 继续待独立复核；DEV-017 卸载限制仍适用。

### 修订建议

使用 getter 推导的模块私有偏移；新日志同时记录 cred_security、kp_security、cred_sid，以区分原生字段、外部哨兵与 SID 推导。目标参考为 cred_security=0x78、kp_security=-1、cred_sid=0x4；实际输出由运行端核对。成功加载后复核先前的 UID、exec 后域与重定向判据。

### DEV-020（中，归属 Developer）：依赖 KP 未计算的 cred.security 导致加载失败

- 证据：原 1.1.4 强制比较 security_offset；KP 0.13.9 源码只有初始 -1，没有赋值；原生产码夹具设置该外部输入后复现 -ENOENT。
- 影响：模块初始化失败，root 执行域功能不可用；本失败点尚未建立后台回调。
- 频率：原实现遇到该未计算状态必现；置信度：源码及离线复现已确认，运行端具体输入待新日志确认。
- 修复：完整 getter 链提取并保存模块自己的 security 偏移，实际 cred 访问使用该值；状态：fixed（待独立复核）。
- 关闭条件：Auditor 独立复核 KP 字段状态、推导/消费路径与边界；Tester 在绑定新产物上核对加载及后续执行。Developer 不关闭该单。

### 自检与证据范围

122 条既有 C 断言保留，新增 8 条；Sony 原始 getter 的已知 KP 输入和 -1 输入均验证 security=0x78、sid=0x4。新增合成用例覆盖未知 KP 输入时的直接布局、非零 LSM blob 加量、错误输出/基址/RET 及初始化消费路径，确认全局 KP 字段仍为 -1。既有已知偏移不一致负例继续执行，测试断言未放宽。

ASan/UBSan、Sony 5.15 离线入口验证、格式检查及 NDK26.3 base/debug 构建通过。九项 ELF 导入匹配 SDK 导出；实际反汇编检查未发现 FP/SIMD/x18。257 份本轮开始时归档/清单文件与 171 份既有资产保持原哈希。代码、使用说明、元信息和新清单按 no-negative-echo 回读，原开发记录只追加。本轮为 Developer 自检与 dirty exploration，尚未冻结，未连接 ADB，也不是独立审计或实机结论。

私有证据：`local/run-cmd-security-offset-20261009-rzlmg44o/reproduce.txt`、`host/receipt.json`、`oracle-check.json`、`kp-source-evidence.json`、`build-check.json`。

KP 源码证据：标签 0.13.9，commit `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，文件 `kernel/patch/ksyms/task_cred.c`，SHA-256 `2ea7b9fda6a645a0845aadee5908bc9bbfa3f5c90341e4273f73c5c1c3a22396`。

### 探索身份

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true，source_tree_sha256：`0cde1d204b4fdd9d7ea8954b15747fae881da0e5a1b374dc6be8d90c8aa51416`。
- base instance_id：`run_cmd_demo-1.1.5+g0cde1d204b4f.r2034b13f.kpb51197a.ndk26.3.11579264#1`；SHA-256：`8f177a842cf002aba23d42e4000243a974bae7f8d1a853ff10c42dbfdf4ac70a`。
- debug instance_id：`run_cmd_demo-1.1.5_debug+g0cde1d204b4f.r8a694e0d.kpb51197a.ndk26.3.11579264#1`；SHA-256：`e3810473a9920eabc1b0ae296397f73b4a9ac33706dda040b5e7ec01c085e014`。
- 清单：[1.1.5 security 偏移探索](handoffs/run_cmd_demo-1.1.5-20261009-security-offset-exploration.json)。

## 后续记录：4.4～6.6 接口兼容性调查

使用者反馈本轮执行输出为 UID/GID 0、`u:r:magisk:s0`，目录列表写入目标文件，helper result=0，并确认可用。该反馈未带产物 SHA-256，保留为运行诊断；不代替绑定身份的 Tester 报告，也不关闭 DEV-019、DEV-020。本节继续以以上 1.1.5 探索身份为分析对象，本轮未生成新构建。

### 已核对的原生契约

| 项目 | 源码差异及当前影响 | 后续适配依据 |
| --- | --- | --- |
| UMH 回调 | 原生 4.4 与 6.6 的 init 回调均接收 subprocess_info 和新 cred；callback 返回非零会终止执行。setup 的 path 参数 const 限定变化不改变 ARM64 调用 ABI | 保留当前 UMH 接口，目标镜像核对入口与 path 的实际偏移 |
| worker 创建与入队 | 原生 4.4 提供 __init_kthread_worker、kthread_worker_fn、queue_kthread_work，缺少当前依赖的 kthread_create_worker、kthread_queue_work | 按实际符号选择现代接口或配套旧接口；旧线程仍由内核 worker loop 执行 |
| worker 存储 | 4.4 initializer 初始化锁、链表及 task，没有写 current_work；调用方必须先清零。原生 ARM64 4.4 的全调试配置布局上限为 104 字节、8 字节对齐，厂商扩展仍需核对 | 容量和对齐须有目标依据，现代路径继续由原生 creator 分配；不复制现代 worker 布局给旧 initializer |
| 工作项 | 原生 4.4 的 node/func/worker 前缀与 6.6 相同；后者增加 canceling | 现有较大工作项能容纳这两份原生定义；目标机器码须核对实际访问 |
| SELinux 锚点 | 原生 4.4 没有 selinux_cred_getsecid，有 selinux_task_getsecid；当前必需符号检查会拒绝该原生形态 | 评估短 task getter 的 task→cred→security→SID 链；不能将 task getter 强转为 cred getter 调用 |
| 凭据来源 | 6.6 的 prepare_kernel_cred 不再接受 NULL；当前已传 init_task | 复用当前私有凭据来源，偏移仍按目标短锚点推导 |

来源：[4.4 kmod.c](https://github.com/torvalds/linux/blob/v4.4/kernel/kmod.c)、[6.6 umh.c](https://github.com/torvalds/linux/blob/v6.6/kernel/umh.c)、[4.4 kthread.h](https://github.com/torvalds/linux/blob/v4.4/include/linux/kthread.h)、[6.6 kthread.h](https://github.com/torvalds/linux/blob/v6.6/include/linux/kthread.h)、[4.4 SELinux hooks](https://github.com/torvalds/linux/blob/v4.4/security/selinux/hooks.c)、[6.6 cred.c](https://github.com/torvalds/linux/blob/v6.6/kernel/cred.c)。源码核对日期为 2026-10-09。

### 自查决定（Decision）

**修改（Modify）**

#### 有效性

当前 1.1.5 的必需符号集合无法覆盖上述原生 4.4 形态。旧 initializer 与原生 kthread_worker_fn、kthread_create_on_node、wake_up_process 配套，可以保留 ctl0 只入队、线程等待 UMH_WAIT_PROC 的接口。stock 源码的可行路径不等于厂商目标镜像已兼容；本轮尚未运行新增镜像回归。

#### 简洁性

保留现有现代路径，旧路径优先复用原生初始化及循环。4.4 原生 worker 没有独立分配函数，存储方式须结合目标布局与 KPM 分配对齐确认。使用普通 workqueue 仍需处理工作项 flags、配置布局和调试对象，目前没有证据表明更简单。SELinux 使用独立短函数作锚点，继续限定入口扫描范围。

#### 后果

旧 worker 的 lockdep key 不能仅按普通 LKM 的 static key 做法复制。KP 的模块数据属于自有分配区，未注册到原生 struct module 列表；4.4 lockdep_init_map 的 static_obj 检查可能拒绝该地址。原生 __lockdep_no_validate__ 是合法 key，其用途由 lockdep_set_novalidate_class 宏明确给出；使用它只跳过该 worker 锁的依赖验证，实际自旋锁仍由内核操作。这一局限须随旧路径记录。来源：[4.4 lockdep.h](https://github.com/torvalds/linux/blob/v4.4/include/linux/lockdep.h)、[4.4 lockdep.c](https://github.com/torvalds/linux/blob/v4.4/kernel/locking/lockdep.c)。

高版本的回调 CFI/KCFI 行为还依赖运行端 KP；当前 SDK 含 KPM 地址范围的 bypass 处理，不能据此宣称所有运行端已经生效。执行域是否存在、exec 后域转换及文件权限仍需各目标实机验证。

### 范围与保全

镜像范围选择已发出，待使用者确认。此前读取的是源码与缓存目录清单，未处理本轮未选定镜像。仅下载九份公开源码文件，合计 162767 字节，URL 与 SHA-256 保存在私有回执；未下载完整内核树。

私有证据目录为 `local/run-cmd-compat-source-20261009-mfezbik3/`：native-sources/receipt.json 记录源码来源，source-baseline.json 记录当前生产及测试源文件哈希，protected.json 记录本轮开始时的 258 份归档与清单。原有 C 断言、生产源码与构建清单保持原字节；无新构建、提交、冻结或设备操作。本节属于 Developer 源码调查及反例自查，不是独立审计或跨内核实机结论。

## 后续记录：1.2.0 Android 4.4～6.6 兼容与 BTF 偏移

使用者确认范围为 Android 4.4～6.6，并允许有 BTF 时直接获取准确偏移。本轮处理现有 12 份输入，原 img 先解包并核对与缓存 Image 的 SHA-256，所有输出放在新目录。使用者对 1.1.5 的功能反馈显示 root UID、magisk 执行域及目录输出，尚未绑定产物哈希；本轮兼容扩展的验证属于 Developer 离线和宿主自检。

### 实现与覆盖

BTF 路径调用内核 `bpf_get_btf_vmlinux` 取得对象，以原生 `btf_find_by_name_kind`、`btf_type_by_id`、`btf_name_by_offset`、`btf_resolve_size` 查成员、剥 typedef 并核对尺寸。三个字段齐备后使用 BTF 结果；缺少 API、对象或类型时使用完整指令路径。SID 加上运行时 `selinux_blob_sizes.lbs_cred`；工作项的共享字段、现代 canceling 成员及总尺寸与模块定义核对，冲突则停止加载。BTF 原始格式只复制 UAPI 共同头与成员记录，不访问内核 `struct btf` 私有布局。

指令扫描继续限定固定前缀：UMH 32 条、SID getter 与旧 initializer 各 16 条。UMH 识别首个 path 读取与后续最多 10 条内的 64 位 CBZ/CBNZ，跨过保持 path 寄存器的 completion 初始化；首候选失配即停止。`kpm_utils.h` 按原宏格式增加 CBNZ 和整数 signed-offset STP；STNP、配对加载、SIMD、pre/post-index 不属于该 STP 形式。

旧接口配套使用 `__init_kthread_worker`、`kthread_worker_fn`、`kthread_create_on_node`、`wake_up_process` 和 `queue_kthread_work`。worker 从 BTF 取得完整尺寸；无 BTF 时按原生 initializer 的链表自指向与随后 task/current_work 连续片段计算，内核堆分配后整体清零。现代 creator 继续由内核分配。旧路径开启 lockdep 时须取得内核持久的 `__lockdep_no_validate__` key；实际锁由内核操作。缺少原生 cred getter 时，结合 KP 的 real_cred 偏移读取旧 task getter 链，并在修改私有安全副本前核对初始 SID；现代 getter 在修改后回读。

| 输入 | 实际内核 | path / security / SID | 偏移自检 |
| --- | --- | --- | --- |
| B2N-416G_boot.img | 4.4.192-perf+ | 0x28 / 0x78 / 0x4 | 通过；旧 worker 40 字节 |
| kernel_4.4 | 4.4.192-black_caps+ | 0x28 / 0x78 / 0x4 | 通过；旧 worker 40 字节 |
| kernel_4.9 | 4.9.227-perf+ | 0x28 / 0x78 / 0x4 | 通过 |
| kernel_4.9_miui | 4.9.186-perf-g10af704 | 0x28 / 0x78 / 0x4 | 通过 |
| kernel_4.14 | 4.14.117-perf+ | 0x28 / 0x78 / 0x4 | 通过 |
| kernel_4.19 | 4.19.324-perf+ | 0x38 / 0x78 / 0x4 | 通过 |
| boot_67.2.A.3.178.img | 5.15.189-android13-8 | 0x38 / 0x78 / 0x4 | BTF 与指令两条路径通过 |
| kernel_5.15 | 5.15.149-android13-8 | 0x38 / 0x78 / 0x4 | BTF 与指令两条路径通过 |
| kernel_6.1 | 6.1.112-android14-11 | 0x38 / 0x78 / 0x4 | BTF 与指令两条路径通过 |
| kernel_6.6 | 6.6.57-android15-8 | 0x38 / 0x80 / 0x4 | BTF 与指令两条路径通过 |
| boot-250514.img | 4.14.356-Liberty | — | SKIP：符号提取未覆盖 |
| kernel_4.14.186 | 4.14.186-gbc682460573f | — | SKIP：符号提取未覆盖 |

参考来自实际入口反汇编，有 BTF 时交叉核对类型成员；旧 real_cred 另在 `get_task_cred` 核对。生产代码没有按版本取表。多 LSM 镜像副本的 blob 使用启动后参考值 0，镜像中的初始化前 sizeof 值不作为运行时偏移；非零加量由宿主负例/正例覆盖。离线工具直接插入生产计算代码，在整页对齐 Image 副本上读取原始指令，并以目标 BTF 记录模拟原生查询接口。它不执行 ARM64 内核函数，不能证明调度、SMP、RCU、CFI 或 SELinux exec 行为。

### 自查决定（Decision）

**保留（Retain）**，对象为修正尺寸 API 后的 1.2.0 最终实现。

#### 有效性

10 份可提取符号的实际镜像均匹配参考字段；四份 BTF 镜像的两条路径一致，包括 6.6 的 security=0x80。宿主覆盖旧接口创建失败清理、初始 SID 核对、连续执行、BTF typedef/ERR_PTR/NULL/类型缺失、布局冲突及固定窗口边界。两份符号提取失败列为未覆盖，不据此判断内核缺少 kallsyms。

#### 简洁性

1.1.5 依赖现代 worker 与 cred getter，无法覆盖已观察到的旧接口形态。新路径复用原生初始化、线程循环和 BTF 查询，模块仅保存必要字段与一个旧 worker 尺寸。仅用指令的实现也通过本语料，但 BTF 提供成员身份与实际布局依据，符合本轮目标；无需自行实现运行时 BTF 解析器或按版本维护偏移表。

#### 后果

BTF 初始化可能调用内核解析和互斥锁，只发生在可睡眠的加载阶段。无 BTF 的旧 worker 尺寸依据原生连续片段；OEM 新增尾部字段须现场核对，不能将两份已测 4.4 推广为任意厂商保证。旧 SID getter只能核对修改前副本，不具备现代 getter 的修改后原生回读。真实运行端的回调 CFI 支持、策略中 magisk 域、最终 exec 域与重定向权限仍需各目标实机验证。DEV-017 的卸载限制继续适用。

### 修订建议

以本轮原生 BTF 与短入口兼容实现进行独立审计，再按覆盖矩阵绑定新产物验证加载、连续执行、最终执行域及文件输出。厂商扩展布局与未提取语料按镜像现场分析；正式交接从冻结提交重新构建。

### DEV-021（高，归属 Developer）：vmlinux BTF 尺寸 API 依赖未建立缓存

- 证据：本轮预构建实现曾调用 `btf_type_id_size`。Android common 5.15 的 `btf_parse_vmlinux` 只检查元数据，没有建立 resolved_ids/resolved_sizes；该尺寸 API 的 typedef 分支会读取缓存。Sony BTF 中工作项 func 是 typedef→pointer，SID 是 u32→__u32→integer，可命中空指针访问。
- 影响：若采用该预构建实现，模块加载可导致内核崩溃。频率：命中上述原生 vmlinux 类型链时可达；置信度：原生源码与实际 BTF 已确认，未在设备执行该实现。
- 修复：改用逐链查询的原生 `btf_resolve_size`，按其 ERR_PTR 契约处理错误。四份 BTF 镜像均具有该 API，并通过实际类型链的宿主模拟；状态：fixed（待独立复核）。
- 关闭条件：Auditor 独立核对原生 API 契约与最终导入/调用路径，Tester 在绑定产物上核对 BTF 初始化及命令执行。Developer 不关闭该单。

来源：[5.15 BTF 实现](https://github.com/torvalds/linux/blob/v5.15/kernel/bpf/btf.c)、[6.6 BTF 头文件](https://github.com/torvalds/linux/blob/v6.6/include/linux/btf.h)、[6.6 vmlinux BTF 初始化入口](https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/verifier.c)、[BTF UAPI](https://github.com/torvalds/linux/blob/v6.6/include/uapi/linux/btf.h)。Android common 5.15 本地源码亦核对了该契约；检查日期 2026-10-09。有界反例审查属于 Developer 自查，指出上述 API 缓存问题；不是独立 Auditor 结论。

### 测试与保全

原有 130 条 C 断言按忽略空白的表达式及次数复核，全部保留；最终共 185 条。本轮新增夹具按原生返回契约模拟 typedef 查询和旧 worker，不给生产代码增加 Mock 专用分支。新增 STP 用例在当前未冻结夹具中随精确 signed-offset 定义调整；既有 Oracle 断言未修改。另对 64 种配对访存编码与实际反汇编比对，区分 STP offset、STNP、回写形式、整数与 SIMD。ASan/UBSan 宿主检查、10 份镜像生产计算、clang-format 及 regular 门禁 16/16 通过。

NDK26.3 base/debug 构建无警告；每份 ELF 的 11 个未定义导入均对应当前 SDK 导出，实际指令未使用 FP/SIMD/x18。初始 258 份归档及清单保持原 SHA-256。一次临时检查器未安装 pyelftools，另一次没有展开 SDK 的 kfunc 导出宏；改用 ELF 字节解析及两种导出宏形式完成检查，生产代码与测试 Oracle 未因这些诊断修改。

私有证据位于 `local/run-cmd-compat-20261009-um53er1y/`：inventory.json 记录输入 SHA-256、解包与符号来源；各输入 reference.json、probe-02/receipt.json 绑定参考字段及实际计算；host-07/receipt.json、oracle-check.json、stp-encoding-check.json、build-check.json 记录宿主与产物自检。最终源码、README、清单和产物元信息回读，并使用 are-you-sure、no-negative-echo、respect-the-oracle 自查。本节为 dirty exploration，不是冻结候选、独立审计或实机结论。

### 探索身份

- source_commit：`7cb89e0c8c065443ac019f147c9bf4995f01db61`；source_dirty=true；source_tree_sha256：`518826c13f85a370b7eab2e76ebce781e2b26a0503674557c8fe0971b8429945`。
- KernelPatch SDK commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；工具链 `ndk26.3.11579264`，目标 `all debug`。
- base instance_id：`run_cmd_demo-1.2.0+g518826c13f85.r88f418e4.kpb51197a.ndk26.3.11579264#1`；SHA-256：`f59a896ec8f59ce8717272430071fa3095f5c6479667fd2cee36768584040209`。
- debug instance_id：`run_cmd_demo-1.2.0_debug+g518826c13f85.r336be92d.kpb51197a.ndk26.3.11579264#1`；SHA-256：`db3d1db63f6913c88a3463bc9fe0d11809ce52f3439d700e0b56a12dd479573e`。
- 清单：[1.2.0 兼容探索](handoffs/run_cmd_demo-1.2.0-20261009-compat-exploration.json)。

## 后续约定：偏移获取的默认范围

使用者确认后续函数推导只默认适配 Android 4.4～5.10，5.15 及以上默认使用 BTF。规则已写入 [Developer 工作指引](../README.md#偏移获取的默认范围2026-10-09)。旧版本有可用 BTF 时也优先使用；高版本缺少数据、必要类型或运行时查询接口时按实际镜像单独分析。

本次为开发约定更新。当前 1.2.0 实现、既有回归用例与探索产物沿用上节记录，本次没有新构建或实机测试。按 are-you-sure 复核适配范围与偏移依据的区别，按 no-negative-echo 精简表述，按 respect-the-oracle 保留既有测试覆盖，并回读本次文档。
