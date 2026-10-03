# Developer 记录：RPC/code 清理规则与全 code 上报

角色 Developer。按用户继续移植的要求接入 ADD_FREE_ASYNC/DEL_FREE_ASYNC，按后续明确指示删除异步 Transaction 的 code 29～32 硬编码过滤。UID 继续使用固定数组，规则使用独立的 32 项数组。本轮是实现方探索自检，不是独立审计、冻结候选或真机结论。

## 身份

完整基础提交 `40d33aca895cc4778deb1925ec12e4a635b5612f`，source_dirty=true；实际构建输入指纹 `0fbf9fb64c6302da2576f78e2cb885ef46959ebbf02de066fde86501972d55dc`。SDK 为 KP 0.13.9 `b51197aaba8f2272dd8a3e30c85698a29aa928c9`，工具链 ndk26.3.11579264。完整登记见 [探索清单](handoffs/2026-10-02-re-kernel-static-free-async-exploration.json)。统一构建入口使用 --target baselines --allow-dirty --no-archive --handoff；旧产物移入 local/stale 保留，未改维护者元数据、未提交或签名。

| 变体 | instance_id | SHA-256 |
| --- | --- | --- |
| abi3 | `re_kernel_static-8.0.0_abi3+g0fbf9fb64c63.r457e2cc4.kpb51197a.ndk26.3.11579264#1` | `58d337294d032941cef343c9b5d2bf45bf6db254ac22f69044d6f2ab2d1b3d84` |
| abi3_debug | `re_kernel_static-8.0.0_abi3_debug+g0fbf9fb64c63.rf1ec8ef9.kpb51197a.ndk26.3.11579264#1` | `f40db909b9d700370eff4e2ed432a57b77c08006b8cd98c4b200d0563a1aee05` |
| abi4 | `re_kernel_static-8.0.0_abi4+g0fbf9fb64c63.r1dcad499.kpb51197a.ndk26.3.11579264#1` | `238b2fb77435e36132b2cbb2888876931fcef679deafd28752544718a827bd4f` |
| abi4_debug | `re_kernel_static-8.0.0_abi4_debug+g0fbf9fb64c63.rbd5cdb61.kpb51197a.ndk26.3.11579264#1` | `23eab40d44d3abdee53fac4b5e28f0851646523145bbbaeb9ce59b189365658f` |
| abi5 | `re_kernel_static-8.0.0_abi5+g0fbf9fb64c63.r7610c627.kpb51197a.ndk26.3.11579264#1` | `99061da9df89ad32a495d76d982238b98d64ab3c374ac9209b90d1ebd5d932dd` |
| abi5_debug | `re_kernel_static-8.0.0_abi5_debug+g0fbf9fb64c63.r80be7f2d.kpb51197a.ndk26.3.11579264#1` | `69dfda1a30a113b812eb6c9cab346d3d4db593fb1061d7393606d1379f4ebde7` |
| abi6 | `re_kernel_static-8.0.0_abi6+g0fbf9fb64c63.r6607d33a.kpb51197a.ndk26.3.11579264#1` | `1a157ede3157e83ee337173a0dd87cf688760ec701109c357fb487ba53d01f20` |
| abi6_debug | `re_kernel_static-8.0.0_abi6_debug+g0fbf9fb64c63.r4e25cadc.kpb51197a.ndk26.3.11579264#1` | `ab3a6f8713eca0619a3b9916dd20729581a62b329793294d07f90d6ecdadc2a1` |

## 本轮行为

命令编号与 [上游 rkx_genl.c](https://github.com/myflavor/ReKernel-X/blob/8c217319d7d73c40667650a43a485e9f185e3a92/LKM-Source/rkx_genl.c) 及 [规则实现](https://github.com/myflavor/ReKernel-X/blob/8c217319d7d73c40667650a43a485e9f185e3a92/LKM-Source/rkx_free_async.c) 对齐，访问日期 2026-10-02：ADD=4、DEL=5；STRATEGY=41/u8、RPC_NAME=42/NUL 字符串、CODE=43/s32。添加需要三个参数，删除需要 RPC_NAME 与 CODE。名称非空且最多 139 字节，code >= -1；-1 通配，精确 code 优先。重复添加更新策略，删除不存在项返回成功；容量满返回 -ENOSPC。删除以尾项填补空位，匹配不依赖顺序。

支持 SKIP=1 与 BY_CODE=2；BY_DATA=3 返回 -EOPNOTSUPP，不偷偷退为 BY_CODE。默认无规则/无匹配沿用基础 code 去重。SKIP 在取得 Binder node/inner 锁之前返回，保留原队列、计数及 buffer/transaction 关联。BY_CODE 保留最早事务，仅摘除第二条匹配事务；既有对象/FD、额外缓冲区、proc 退出及 Binder 冻结保护和原生释放顺序保持。

RPC 匹配读取 Binder 已复制的缓冲，不依赖发送方可变用户内存或 task_ext。使用可选的内核 binder_alloc_copy_from_buffer，函数签名与上游使用方式一致；在 init 解析，缺少时打印功能提示，ADD 返回 -EOPNOTSUPP，基础去重仍可使用。内核函数返回错误、Token 截断、无 NUL、空名称或非 ASCII UTF-16 时保留消息。PARCEL_OFFSET=16 沿用模块既有协议约定；完整最多 139 字符匹配，禁止截断后当成完整名称。无额外结构体偏移，偏移表保持 43 项/86 字节。

低版本缺少此内核读取函数时，本轮规则功能明确未覆盖，后续需单独实现静态布局的缓冲读取兼容。没有把上游针对 5.10/5.15 的页映射代码直接抄到 4.4，也没有猜页/alloc 偏移。只读取小范围上游源码，共六个 C/h 文件及提交信息，未克隆内核。已有 B2N 符号语料未找到该函数，已有 5.15 语料包含；这不是本轮设备能力判定或全量内核回归。

异步 Transaction 事件不再按 code 29～32 过滤，完整保留所有 u32 code 位值；其它已有发送过滤保持。RPC 上报读取前缀扩大为 PARCEL_OFFSET + 140*2，输出仍最多 139 字节，与外部规则名称上限一致。规则控制清理策略；SKIP 不表示停止事件上报。

## 自检

最终八个登记产物逐个核对 SHA、来源输入未变及保存副本字节；真实 ELF 的 18 个导入全部在当前 KP SDK 导出源码中找到，无 task_ext 依赖，无裸 memcpy/memset/其它直接 C 字符串导入，实际 ARM64 指令无 FP/SIMD/SVE。格式按 .clang-format，dry-run 与 git diff --check 通过。编译保留原有 SDK 五类警告，没有模块新警告。

持久 test_static.py 对最终登记字节通过：八 ELF JSON/blob 替换边界；全 code 值及 139 字节 RPC 上报；原协议、上下文、Genl UID 与生命周期；规则 wire 参数、精确/通配优先、更新、删除、满容量仍可更新、无读取函数降级、重复/缺失/错误长度/标志/NUL 属性、20000 个随机规则报文、8 个规则写线程。四 ABI 生产清理函数在 ASan/UBSan 下验证 SKIP 保留队列/计数、BY_CODE 保留最早事务、缓冲读取错误与异常 Token 保留消息，并继续通过原对象/FD、释放顺序、proc 死亡与八发送方测试。

断言语义随用户明确要求调整：原 code=28 不上报的检查改为 0、28、29、32、33、0x7fffffff、0xffffffff 都上报；同步/冻结/同 UID/无上下文和读取失败过滤检查保留。新增 ELF 断言拒绝裸 C 运行库导入，其余检查未缩小。

探索检查发现结构体赋值会生成未导出的裸 memcpy；已在最终构建前改为显式 SDK memcpy 封装，并增加持久导入拒绝断言。此前探索产物未交接或上机；原始探索日志与字节保留，不用早期产物替代最终登记实例。主机测试直接抽取生产函数，属于同源自检，锁用 pthread 模拟，不验证目标 DAIF 锁或内核调用 ABI。

证据在 local/static-free-async-20261002-01/ 的 registered-build.log、registered-tests.log、identity-selfcheck.json、upstream.json，以及 registered/ 保存副本与 JSON。没有执行设备加载、解冻响应测试或卸载，不能据此保证应用不会假死。目标静态偏移、实际 ACK/规则下发与应用行为仍需后续独立审计及真机核验。卸载生命周期与 DEV-004 的 KP 后缀匹配观察继续保留为未解决项。
