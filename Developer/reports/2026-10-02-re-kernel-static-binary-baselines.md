# 开发报告：re_kernel_static 静态基准与二进制事件

角色：Developer。本轮为脏树探索构建，不作为冻结候选交接。

## 身份

基础提交：`40d33aca895cc4778deb1925ec12e4a635b5612f`，`source_dirty=true`；实际构建输入树与逐文件指纹见 [探索身份清单](handoffs/2026-10-02-re-kernel-static-baselines-exploration-02.json)。KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。统一入口：`tools/build_candidate.py re_kernel_static --target baselines --allow-dirty --handoff ...`，工具链 NDK 26.3.11579264。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g4f40e2046f89.r6dd4873d.kpb51197a.ndk26.3.11579264#1` | `3dbf6add8a78ac01c5829567e0cfc493ba2814503a04650f803874789951141c` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g4f40e2046f89.r7f9593ad.kpb51197a.ndk26.3.11579264#1` | `fbf3d8cb1e02fa15b8eb9b1c823b12ba13d9918ecbe1dfbe4f150c211b547a3b` |
| abi4 | `re_kernel_static-8.0.0_abi4+g4f40e2046f89.r0a6da2d7.kpb51197a.ndk26.3.11579264#1` | `f548a6fadf48f2be480fa296d25a37e4495f5d26a9e4350dafd62df41da085ee` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g4f40e2046f89.r52fa58f2.kpb51197a.ndk26.3.11579264#1` | `dfc51aed2f004eaece1566b2bc70f6acc3b0e5bb5cf587644de81019d7604eb8` |
| abi5 | `re_kernel_static-8.0.0_abi5+g4f40e2046f89.r62961f04.kpb51197a.ndk26.3.11579264#1` | `077c15bf8c5017c4c5b11022a8b492340c98471cc4b7b155c2aaa26295a44b16` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g4f40e2046f89.r451d4456.kpb51197a.ndk26.3.11579264#1` | `95308b8c7527129fdf3f57ec5c9326b05fce55a4783e8c9609e219a0e1109e10` |
| abi6 | `re_kernel_static-8.0.0_abi6+g4f40e2046f89.rf18bcea6.kpb51197a.ndk26.3.11579264#1` | `71335b2c6be63470747d5d27650a80d5541cd24df17d68a1901b7eb7920728bb` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g4f40e2046f89.rba6293f2.kpb51197a.ndk26.3.11579264#1` | `af72e9ed715bbd0b4792dd3aad2a75393b565df9e2a59b1bc8b99409d26d9943` |

## 变更与自检

- 四种 Binder 释放 ABI 沿用 CONFIG_KERNEL_3/4/5/6，编号不是 Linux 主版本。当前仍有按原内核布局定义的 Binder 字段，未声明四个基准可覆盖任意内核。
- 41 个小端 int16 偏移/宽度参数独立放在 `.data.re_offsets`，82 字节。volatile 使访问从表中读值。新增 cred、uid、comm 的默认值来自已有目标 BTF；未新增 img 范围或做全镜像回归。
- patch_offsets.py 用基准 KPM 哈希及布局清单定位数据段；接收完整 JSON 或原始二进制，只替换表字节，拒绝覆盖、错布局、错大小与不可编码的值。工具端验证编码宽度，不添加模块运行时偏移检查。
- 自定义 176 字节事件放回 re_kernel.h；Binder/Signal/Network 用联合体，命令编号与原 8 字节格式保持。用户态需配合结构体 payload 与版本检查。
- Binder 参数保存改为模块上下文：按当前任务、hook 参数地址关联，after 精确删除。模块自己的 0/1 原子锁屏蔽本地 IRQ，持锁期间只访问链表；不把自有锁传给目标内核。分配失败时暂时暂停 RPC 读取，直到对应失败调用返回，避免读取外层参数。分配/释放在锁外完成。
- 局部修复原编译残留：共享头文件、init_net 声明位置、缺失的 calculate_offsets 调用、调用表达式中的 bool 类型词；编译器生成的 memset 通过 re_runtime.c 转发 KP 导出的 kf_memset。

`python3 re_kernel_static/tools/test_static.py --baselines local/static-baselines-20261002-09`：8 份真实 KPM 的 JSON/原始 blob 往返、仅偏移数据段改变、无覆盖及无效输入拒绝通过；生产事件函数 ASan/UBSan 测试覆盖三种事件、清零、RPC 长度、过滤与发送失败；生产上下文函数覆盖任务隔离、嵌套、参数更新、分配失败以及 8 线程各 500 次 before/after。

8 份最终产物的未定义导入均在当前 SDK 的 KP 导出表中找到；不再导入 kf_get_task_ext、task_ext_size、task_struct_offset 或 cred_offset。ARM64 指令自检未发现 FP/SIMD/SVE，重定位证明代码引用偏移表。构建仍有 5 条既有 SDK 警告（cmpxchg.h 与 READ_ONCE/WRITE_ONCE 重定义），未修改 SDK。

## 问题单 DEV-001

- 严重度：高；归属：Developer；频率：未知；置信度：源码布局已确认，设备触发未测试；状态：fixed（待独立复核）。
- 问题：旧 binder_transaction_before 从 task_ext_size+8 起无边界扫描并写入 task_ext。当前 KP 槽表中的 task_ext 没有额外尾部容量，若使用该槽表接口，写入可越过对象并破坏相邻槽。
- 证据：基础提交的 re_kernel_static/re_kernel.c；SDK taskext.h 中 sizeof(task_ext)=20、offsetof(_magic)=16；taskob.c 中槽为 task 指针加 task_ext，LP64 sizeof(slot)=32。第一次 8 字节写从 ext+24 开始；ext 位于 slot+8，因此写到 slot+32，即相邻槽起点。原 while 也没有容量上界。
- 修复：删除 task_ext 存储路径，由模块为本次 Binder 调用单独分配上下文并在 after 释放；本轮身份绑定以上最终探索产物。
- 关闭条件：Auditor 独立核对 ABI 布局与产物，复核嵌套、任务隔离、分配失败和 before/after 生命周期后关闭；Developer 不自行关闭。元数据登记由维护者执行。

## 边界与待处理

以上是实现方自检，不是独立审计或真机结论。卸载上下文问题依用户要求暂留，用户态协议接收修改、目标 img 的完整布局移植与设备验证待完成。当前上下文链表仅保存活跃调用，不假定固定并发容量；锁实现与 hook 退出期间生命周期需要独立复核。
