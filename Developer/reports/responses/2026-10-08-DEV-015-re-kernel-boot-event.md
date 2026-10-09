# DEV-015：内嵌 rek 在 pre-kernel-init 阶段返回 -107

角色：Developer。问题状态 open，等待独立复核；仅本地源码与初始化顺序核对，未操作设备或修改内核镜像。

## 对应问题

DEV-015（中，归属 Developer）：内嵌加载说明未注明 Generic Netlink 初始化时序，使用 KP 默认 pre-kernel-init 事件会导致模块初始化失败。

- 发现依据：使用者提供 4.4 开机日志，模块名 re_kernel、版本 11.7，最后 `event: pre-kernel-init, rc: -107`。
- 影响：该阶段 Genl 尚未初始化，模块停止加载；当前证据没有内核崩溃或卡死。
- 频率：未知。置信度：初始化顺序与错误分支已确认，用户实际加载文件哈希未验证。
- 建议：将该内嵌 KPM 的事件配置为 post-kernel-init；已嵌入的模块需更新配置。保留 socket 检查。
- 关闭条件：维护者核对嵌入事件和实际加载文件 SHA-256，Tester 在对应设备启动时观察该事件、模块加载返回 0 和 Genl family 建立；另由 Auditor/维护者复核说明，不由 Developer 自行关闭。

## 身份与证据边界

参考冻结源码为 `2074106d835b7a20f7e11ab29febc86ec54b7bb2`，参考 release instance_id 为 `re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264#1`，SHA-256 为 `d00c3f45d8af3be7dcfe5b9d699d43a1f4b81e27e9a81a256901b2c96f6d4404`。它与日志的模块名和版本一致，但没有设备文件哈希，不能断言用户加载的字节就是此候选。

冻结交接见 [rek 候选](../handoffs/2026-10-08-re_kernel-cleanup-candidate.md)。本轮只有 README 加载说明变更，没有生产 C 代码修改，没有新 KPM 或新构建实例。

## 初始化顺序核对

`re_kernel/re_kernel.c` 的 prepare_rekernel_genl_server 先解析符号，再读取 init_net.genl_sock；该指针为空时返回 -ENOTCONN（-107）。calculate_offsets 的失败返回 -11/-21；日志中的 -107 与此 readiness 检查一致。binder_free_proc=0 的日志属于已有替代锚点路径，后续已经继续推导，不是这次错误的出口。

核对构建 SDK `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 的 KernelPatch 源码：preset.h 默认事件为 pre-kernel-init；patch.c 在 kernel_init 的 before 发出 pre-kernel-init，在 after 发出 post-kernel-init。kptools.c 的 -V/--extra-event 设置其前一个 -M 或 -E 条目的加载事件。

[Linux v4.4 genetlink.c](https://github.com/torvalds/linux/blob/v4.4/net/netlink/genetlink.c#L986-L1037) 通过 subsys_initcall(genl_init) 初始化 family 哈希链，并调用 register_pernet_subsys，后者执行 genl_pernet_init 来创建 net.genl_sock。[kernel_init](https://github.com/torvalds/linux/blob/v4.4/init/main.c#L880-L952) 的初始化流程在入口之后执行这些 initcall。因此这次 pre-kernel-init 的空 socket 有明确的初始化时序依据。不能删除检查后提前注册 family：4.4 的 family 哈希链此时也尚未初始化。

读取 Tester 的 11.7 双机型报告，其 4.4 结果是开机后手动加载成功；该报告没有覆盖内嵌 pre-kernel-init，也不能替代本次开机事件验证。本轮不修改 Tester/Auditor 报告或旧候选身份。

## 修改与自检

在 re_kernel/README.md 增加开机事件和 kptools 配置说明。未增加延迟 work、额外 hook 或自动重试；KP 已有相应事件。git diff --check 及本地引用检查通过。生产代码和旧冻结资产不变，不为文档变更重复构建或修改测试 Oracle。

本响应是实现方的源码/初始化顺序核对，不是独立审计或真机修复结论。post-kernel-init 的实际启动验证仍未执行。

## 资产核对补充

本轮复算旧 artifacts 归档及四份 11.7/1.6-20261008 冻结 KPM 的哈希，均与既有记录一致。先前保护快照中的模块根目录 8.0.0 探索文件当前已不在原位置；本轮未删除或恢复它们，不将探索文件的现场变化外推为归档损坏。

## 维护者字段索引（2026-10-08）

- 问题编号：DEV-015。
- 修复 commit：README 加载事件说明随本轮 `[re_kernel]` 源码提交保存；生产代码仍绑定参考冻结提交 `2074106d835b7a20f7e11ab29febc86ec54b7bb2`，文档修正没有生成新 KPM。
- Build ID：`re_kernel-11.7+gb51704088a2f.rc7733a0a.kpb51197a.ndk26.3.11579264`；对应 instance_id 与产物 SHA-256 见原响应身份栏。
- 维护者整理范围：补齐文档修复的身份字段索引，保留原有 open 状态、证据边界与待执行的启动复验。原文 SHA-256：`98133bc5f882575ad31fcd13412d8b6a39d9689e95d809a3feb6890f452e0a2e`。
