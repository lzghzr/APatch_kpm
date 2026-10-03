# re_kernel_static 旧 Binder 缓冲读取开发记录

角色：Developer。状态：探索；实现方自检，不是独立审计，也不是实机结论。

## 本轮结果

新增共用 `binder_buffer_read`，RPC 规则读取与 BY_DATA 比较都通过它。优先调用原生 `binder_alloc_copy_from_buffer`；目标没有该函数、但已离线确认内核映射 data 时，按 `binder_buffer_data` 偏移读取指针并复制。只增加一个静态配置项，不按 Linux 版本号分支，不在加载时推导偏移。

`binder_buffer_data` 默认 -1，表示未配置。缺少原生函数且未配置时，添加规则返回 `-EOPNOTSUPP`；已存在规则的读取失败保留消息。配置成新内核 `user_data` 的偏移不成立，因为那是用户地址。静态表增至 44 项、88 字节，旧基准的 JSON/blob 不与新基准混用。

旧路径检查 free、4 字节起始对齐、data_size 与复制范围、空 data 指针；长度校验先比较 offset，再做减法，避免溢出。RPC 在当前未投递事务生命期内读取，BY_DATA 在已有 node/inner_lock 下读取队列事务；不新增页映射、工作队列或资源释放流程，继续使用整次扫描共享预算。

## 目标证据

只分析 `kernel_img/B2N-416G_boot.img`，复用已提取裸 Image。

- boot SHA-256：`ea919143cb1f057f3d35d726294166d5186f376e9751941b83940e75d48a288c`。
- Image SHA-256：`7633fbac5ce30b726a1acdbf57f730aa847a9510984a25bc23f9ddcdb0956e1c`。
- 目标 Binder 符号表有 allocator/transaction 等函数，没有 `binder_alloc_copy_from_buffer`。不凭这点认定功能无法实现。

参考 Android 官方 wahoo 4.4 的 [binder_alloc.h](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder_alloc.h)、[binder_alloc.c](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder_alloc.c)、[binder.c](https://android.googlesource.com/kernel/msm/+/android-msm-wahoo-4.4-pie/drivers/android/binder.c)（2026-10-02 读取三个文件，未下载整个内核）。旧内存模型将 data 映射到内核，事务复制直接使用 `buffer->data`。此源码用于解释语义，偏移由 B2N 镜像确认，未宣称源码与厂商镜像完全同源。

| 源码快照 | SHA-256 |
| --- | --- |
| `binder_alloc.h` | `947212c0f2342177f46010ea75b919cdb7821e3f453aafe649bb88a86324f8c2` |
| `binder_alloc.c` | `6c60b9941b9228c07fdf4be4bf805d7a8d23b35541ac5ad8045f72cb85bb1bcc` |
| `binder.c` | `d687e6e0a7152dca5a640af9312330e4e99eb1683e2566df6f5f656e3b8b48e7` |

实际指令证据：

| 锚点与 Image 文件地址 | 数据流 | 结果 |
| --- | --- | --- |
| binder_alloc_buffer_size，0xb69a94 / 0xb69a9c / 0xb69aa0 | buffer+0x58 数据地址；末块用 alloc+0x38 映射基址加 alloc+0x78 容量减 data，相邻块用 next+0x58 减 data | data=0x58，alloc.buffer=0x38，alloc.buffer_size=0x78 |
| binder_alloc_mmap_handler，0xb6ac7c / 0xb6ad04 / 0xb6ad0c | 映射地址写入 alloc+0x38；创建首块时读回并写入 buffer+0x58 | 独立交叉核对两处指针偏移 |
| binder_alloc_mmap_handler，0xb6ad24 / 0xb6ad28 | buffer+0x28 的低位作为 free 设置 | 旧、新 copied buffer 定义的 free 低位可复用 |

既存 B2N 表的 `binder_alloc_buffer=0x40` 与以上两处指令不一致。完整配置时应使用经镜像确认的 0x38；当前公共模板不是 B2N 的完整配置。本轮仅确认读取相关局部字段，不生成可直接加载的完整 B2N 配置。

开发证据保存在 `local/static-binder-read-20261002-01/target-evidence.json`，包括源码与反汇编哈希；其它镜像未重新提取或分析。

## 自检

最终统一构建的 8 个 ABI3/4/5/6 release/debug 基准全部完成。日志 `local/build_logs/20261002T113032Z-re_kernel_static.log` 中的警告来自 SDK cmpxchg 的 C2x 标签/ret 提示及 READ_ONCE/WRITE_ONCE 重定义；没有新增模块编译警告。

- 实际 ELF 身份、保存副本及布局哈希相符；44 字段、88 字节；全部未定义导入由本轮 SDK 提供；没有裸 C 内存函数导入、task_ext 依赖或 FP/SIMD/SVE 指令。
- 实际 8 个 KPM 的 JSON/blob 往返仅改变静态表，ABI/布局/哈希不匹配及无效输入拒绝，输出不覆盖旧文件。
- 四个 ABI 的生产读取/清理函数通过 ASan/UBSan：旧 data 路径的 RPC/SKIP/BY_DATA，原生入口优先，未配置、free、空指针、对齐/越界/极大长度，跨页末字节差异，保留最早消息和共享预算。
- 既有事务上下文、Genl 收发/规则、输入随机测试及并发清理自检通过。
- 当前 BTF 生成器输出全部 44 项，默认 `binder_buffer_data=-1`。只有离线确认旧头文件的内核 data 后才使用 `REKERNEL_BINDER_KERNEL_DATA`；在当前只有 user_data 的头文件上误启用该选项会编译失败，拒绝混用。
- 新中文 `kpm-static-binary-port` 与补充后的 `kernel-offset-derivation` 通过 skill-creator 官方格式校验；中文经验与相互引用已写入项目技能。依据用户本轮授权更新技能目录。

第一份探索记录保留；主机 fixture 补齐 u32 类型、修正“仅一条匹配”的测试数据后生成第二份登记，最终 KPM 字节与第一份相同。没有放宽断言。自检日志 `local/static-binder-read-20261002-01/selftest-02.log`；身份自检 `local/static-binder-read-20261002-01/identity-selfcheck-02.json`。

## 构建身份

基础完整 commit：`40d33aca895cc4778deb1925ec12e4a635b5612f`。`source_dirty=true`，源树 SHA-256：`85406787a3ba53b06b9b3996e67c04819d4dfe0a0067d2e73c8e4cdb6aa9c586`。工作树未提交，基础 commit 不能单独重现这些变化；实际输入逐文件指纹与配方见 [探索清单](handoffs/2026-10-02-re-kernel-static-binder-read-exploration-02.json)。未进行 Git 提交、签名或候选验收。

KP SDK commit：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。工具链：NDK 26.3.11579264。保存目录：`local/static-binder-read-20261002-01/registered-02/`。

```bash
python3 tools/build_candidate.py re_kernel_static --toolchain ndk26.3.11579264 --target baselines --allow-dirty --no-archive --handoff Developer/reports/handoffs/2026-10-02-re-kernel-static-binder-read-exploration-02.json --env NDK_PATH=<NDK-bin> --env LAYOUT_DIR=../local/static-binder-read-20261002-01/registered-02
python3 re_kernel_static/tools/test_static.py --baselines local/static-binder-read-20261002-01/registered-02
```

复现应使用新的空输出目录和清单名。上面的目录仅绑定本轮实例。

| 变体 | instance_id | 产物 SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g85406787a3ba.r2decccaf.kpb51197a.ndk26.3.11579264#1` | `b3cee82601fd89a8ccfc908830b522d52871cc3000e9b6c3280909a084a2e9e3` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g85406787a3ba.rd21951d6.kpb51197a.ndk26.3.11579264#1` | `ec42d6b3e94d17fe1805e366425a510a64a089e661727404f85a84314c05aaa7` |
| abi4 | `re_kernel_static-8.0.0_abi4+g85406787a3ba.r3e3c5a18.kpb51197a.ndk26.3.11579264#1` | `b1e7e8a47d81ba0bb292dedf616ad226e2d72e27390fa2079392bb6b1a887fe6` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g85406787a3ba.r5a580102.kpb51197a.ndk26.3.11579264#1` | `20b1bbe19f29c0ce4d59419b88d89e2c0fe374313e1d60a212ba6e2b454fb3fe` |
| abi5 | `re_kernel_static-8.0.0_abi5+g85406787a3ba.r694ab61c.kpb51197a.ndk26.3.11579264#1` | `b40f556e38305d8dec46a8322aa9df063c40e6f405a927f48dbc302acda345d6` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g85406787a3ba.r4b1418a7.kpb51197a.ndk26.3.11579264#1` | `9a42e3b6886542188f652927e419a627d14e65768b44bf10ce3228bf8f59dbc0` |
| abi6 | `re_kernel_static-8.0.0_abi6+g85406787a3ba.r81f61cfc.kpb51197a.ndk26.3.11579264#1` | `d8c33f1a407bd03c3353054800b4c783eb4d0f82cd7d5d32554d7494a0eef8da` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g85406787a3ba.r71cb8d41.kpb51197a.ndk26.3.11579264#1` | `99ba2818a0dd495d74b61e6e74d3a9ae8ed3abff3ff2082bc51855d430a1b6e1` |

## 未覆盖

未验证完整 B2N 44 字段配置、真实内核页映射/锁与回调生命期、设备上的 RPC/ACK/组播或应用解冻响应。主机 pthread 锁模型只能验证业务临界区，不能证明目标锁或映射有效。

新入口适用于已确认的 kernel-mapped data；没有原生入口、也没有这种映射的目标仍需另外适配，不能猜 pages/page_ptr 偏移。卸载生命周期继续按已约定范围暂缓，未代替任何独立角色关闭问题。
