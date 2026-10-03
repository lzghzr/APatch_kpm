# 开发记录：re_kernel_static Generic Netlink 收发

角色：Developer。本轮按用户要求完成通信实现和必要自检，产物为探索构建，未冻结交接，不展开完整交付流程。

## 身份

基础提交：`40d33aca895cc4778deb1925ec12e4a635b5612f`；`source_dirty=true`。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。实际源码与配方指纹见 [探索清单](handoffs/2026-10-02-re-kernel-static-genl-exploration.json)。统一构建入口使用 `--allow-dirty --no-archive --target baselines`，未写维护者元数据、未创建提交或签名。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+gfd682d46ef02.rc8fd1da2.kpb51197a.ndk26.3.11579264#1` | `d6ac7afdbe7c4d6f6d8fae427513aaecb2fb962ff416f60922e856b9d17cbbe6` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+gfd682d46ef02.rafc2edb5.kpb51197a.ndk26.3.11579264#1` | `c7b7105e06c1470d592753ecc9a2e1b01b589ce079d669d0122637454307d929` |
| abi4 | `re_kernel_static-8.0.0_abi4+gfd682d46ef02.r203ac9b0.kpb51197a.ndk26.3.11579264#1` | `10e9349641d5bc942d248e12509940d9df83e739158ca2d971c61fb0cec6dbca` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+gfd682d46ef02.r2ba8e62b.kpb51197a.ndk26.3.11579264#1` | `493669b01f9edd6c4d43f0d0d7c31a87ff55f1b9a936adf5d8838aa898a087e5` |
| abi5 | `re_kernel_static-8.0.0_abi5+gfd682d46ef02.rd4509517.kpb51197a.ndk26.3.11579264#1` | `cb56a7bd17bd05c58f7f4af7ebbd6865fa788950e3429d469d4def3a29f79dec` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+gfd682d46ef02.r4ebae434.kpb51197a.ndk26.3.11579264#1` | `9508258f52200a75c07081fd2efbda4ab2e49b9b4d66b101ce0d53f205898690` |
| abi6 | `re_kernel_static-8.0.0_abi6+gfd682d46ef02.rb2ee28ad.kpb51197a.ndk26.3.11579264#1` | `71d97aa7cdf3bc7642a9147b0cae2b6e6dd034f9bcdd837947e877736057f047` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+gfd682d46ef02.rd30d22f2.kpb51197a.ndk26.3.11579264#1` | `5e4ae037261033a5dc5982e9d3f259bc6f67a8ed7a636a9156c267cf07c53f1b` |

## 实现

- 内部 176 字节事件保留，发送层转换为上游的嵌套 attributes，三类事件通过 `rekernel_x2/events` 组播。Binder 子类型转换为上游 1/2/3 编号，标量和字符串按 `rkx_genl.c` 编码；发送层对齐不改变旧的冻结判断和事件过滤。
- 接收 hook `genl_rcv_msg` 的前两个公共参数，只截获注册 family 的 ID；支持 ADD_MONITOR_NET=2、DEL_MONITOR_NET=3，UID=40。按 init_net、长度、版本、attribute 宽度/标志校验后修改数组；负返回交回内核 netlink_rcv_skb 的 ACK 流程。不引入 genl_ops/genl_info 布局和回调；控制器仍能查询 family/组播组，但不公布命令列表。free-async 与 dump 尚未支持，返回 EOPNOTSUPP。
- 保留 32 项数组，读写用短临界区保护。重复添加/删除不存在项幂等；删除压紧；满容量改为 ENOSPC，取消旧“满后监控全部 UID”行为。未移植上游 RCU 哈希表。
- 增加 sock_sk_net 静态偏移（已有目标 BTF 核对为 0x30）；表为 42 个 int16、84 字节。生成器同步输出该字段。其余目标内核仍需按 img 核对，未声明基准可直接加载任意内核。
- 移除私有 Netlink unit、固定 port 100 和 proc 发现路径。新增 Genl 注册失败会撤销自身接收 hook；Genl 启动失败会撤销已安装的业务回调并返回失败。通用旧 hook 初始化的其它失败分支和卸载生命周期不在本次扩展范围。

## 自检与边界

八个 ABI release/debug 完整构建通过，保留既有 SDK 的 5 条警告。`tools/test_static.py` 使用真实基准 ELF 检查 JSON/blob 往返及仅表字节变化；ASan/UBSan 主机测试提取生产事件、上下文、Genl 收发及封装函数，覆盖实际上游编号、嵌套标志、全部 padding、139 字节 RPC、所有 attribute 写入失败、无订阅者、发送失败及 skb 接管、注册/hook 失败回滚、UID 容量与删除、非法报文/不同 family/命名空间、20000 个随机报文和 8 线程并发。原内部事件与 Binder 上下文用例保留；旧原始 Netlink 发送测试由 Genl 实际字节和错误路径测试替代，原因是该传输路径已移除。

最终登记构建的八个产物与已测试字节完全相同；逐个导入对照当前 KP 导出表通过，无 get_task_ext 依赖；对真实 ARM64 指令检查未发现 FP/SIMD/SVE。生成器输出 sock_sk_net 与当前已有 BTF 一致。现有偏移替换工具端断言和用例没有缩小。

以上是 Developer 自检。测试中的锁以 pthread 模拟，内核广播/注册为受控桩；不证明目标内核锁、CFI、组播订阅或 ACK 已在设备生效。尚无本轮真机测试、独立审计或签名交付。卸载问题依用户先前范围继续暂缓；旧 DEV-001 的独立复核状态未改变。

上游参考：ReKernel-X `8c217319d7d73c40667650a43a485e9f185e3a92` 的 `LKM-Source/rkx.h`、`rkx_genl.c`；Linux v5.15 `net/netlink/genetlink.c`、v4.4 同文件用于核对公共接收入口和 ACK 所在层级。未改上游源码。
