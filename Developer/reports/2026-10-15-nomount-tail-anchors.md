# NoMount：补齐五份目标的末端尺寸与静态适配

本轮把目标机器码取得的成员位置、整对象操作长度作为主要依据。参考源码只补充锚点之后的连续尾部、预留槽及类型对齐，完整布局不从参考头文件照搬。新增五份静态配置，已有13份≤6.1镜像均已生成对应静态派生件。新增目标尚待独立审计和实机测试；动态模式仍只有前轮八份目标的布局准备覆盖。

这是 Developer 的离线分析、宿主自检与构建结果，不是独立审计或实机结论。

## 冻结身份

- 源码：`ebad05883bcd6173d5e2a867559aa6bcb3e45810`。
- KernelPatch：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。
- 构建：`python3 tools/build_candidate.py nomount --toolchain ndk26.3.11579264 --target all --kind candidate --handoff Developer/reports/handoffs/2026-10-15-nomount-tail-anchors.json`；工具链及独立布局输出目录通过入口捕获的环境参数指定。
- [交接清单](handoffs/2026-10-15-nomount-tail-anchors.json)；[逐项证据与派生件回执](data/2026-10-15-nomount-tail-anchors.json)。候选未导入 metadata，由维护者导入。

| 模式 | instance_id | KPM SHA-256 |
| --- | --- | --- |
| base | `nomount-2.1.1-20261014+g9f323cd3deaa.r33de5496.kpb51197a.ndk26.3.11579264#1` | `1ab36727b82cab1723da56f6f82273ff1fee57071836b8992f4e3d26ad40e1fa` |
| baselines | `nomount-2.1.1-20261014_baselines+g9f323cd3deaa.r98bc011c.kpb51197a.ndk26.3.11579264#1` | `b45ea0e0f0dca680fe33430f12b0006ce473c5bf25bb5a3a15a7a96fdba4dc43` |

两个候选均从干净提交构建，`verify_build(profile=candidate)`通过。现行版本仍为`2.1.1-20261014`。配套ZIP本轮没有重建。

## 尺寸的证据链

离线工具为[derive_operation_tails.py](../../nomount/tools/derive_operation_tails.py)。输入为原始镜像、符号表、目标IKCONFIG、参考声明及cache／lockdep宏。证据JSON保留实际指令字、窗口位置、反汇编、尾部原文与每项宽度；参考文件按URL和内容哈希记录。源码提交仅标识参考输入。

| 类型 | 目标锚点 | 含锚点的尾部 |
| --- | --- | --- |
| inode_operations | set_posix_acl中的i_op→set_acl加载 | set_acl指针；部分目标另有4个u64预留槽 |
| super_operations | super_cache_count中的shrinker→sb→s_op→nr_cached_objects | nr_cached_objects／free_cached_objects两指针；部分目标另有4个u64 |
| dentry_operations | d_set_d_op检查d_real后设置DCACHE_OP_REAL | d_real、可选canonical指针、可选4个u64 |
| key_type | unregister_key_type中的link地址及next／prev自指写回 | list_head 16字节；目标未启用LOCKDEP，参考lock_class_key为空 |

公式为`align_up(目标成员偏移 + 含成员的尾部宽度, 类型对齐)`。解析丢弃锚点之前的声明；未知尾部和未覆盖的条件声明拒绝计算。

下表每格为“锚点 + 尾部 → 按对齐取整后的尺寸”，单位字节。

| 目标 | inode（对齐） | super | dentry（对齐） | key |
| --- | --- | --- | --- | --- |
| 米8 4.9 | 176+8→256（128） | 216+16→232 | 96+16→128（128） | 112+16→128 |
| 米9 4.14 | 176+8→256（128） | 224+16→240 | 96+16→128（128） | 120+16→136 |
| 米10 4.19 | 176+8→192（64） | 224+16→240 | 96+16→128（64） | 120+16→136 |
| 米11 5.4 | 160+40→256（64） | 224+48→272 | 96+40→192（64） | 152+16→168 |
| Android12 5.10 | 160+40→256（64） | 192+48→240 | 96+48→192（64） | 168+16→184 |

米11的dentry尾部没有canonical槽，Android12有；相同的最终192字节不代表相同尾部。两者4个u64预留槽为32字节。米11的预留宏无条件保留，Android12由目标`CONFIG_ANDROID_KABI_RESERVE=y`启用。key尾部按实际`CONFIG_LOCKDEP`核对，不以DEBUG_LOCK_ALLOC单项代替。

米8、米9的cache宏链为128字节，原生inode／dentry操作表地址也均满足该对齐；米10存在只按64、未按128对齐的原生表。地址用于交叉核对，不能单独推定sizeof。前轮研究草稿统一按64字节模拟的inode尺寸192现由上述256替代；历史草稿保留，未作为那两份目标的候选交接。

前轮取得的目标字段差异继续保留：米9的i_fop／i_data／i_private为376／392／624；米10为368／384／648，address_space为208，file_operations为288（原生tty_default_fops的完整复制长度）。参考模型的整体布局不覆盖这些目标证据。原证据见[内核扩展研究](../proposals/2026-10-15-nomount-kernel-extension/README.md)。

## 实现与自检

- 私有directory／dentry代理头改为128字节对齐，满足新增目标的表要求；已有目标继续沿原生表尺寸定位第二张表。分配请求仍由原有nm_zalloc向二次幂取整，原表复制长度取对应静态配置。
- `test_tail_derivation.py`：五组真实窗口、37个断链／错标志／未知尾部反例通过；前部声明变化不影响尾部宽度，分别核对64／128对齐和预留槽启用条件。
- `test_proxy_alignment.py`：基于前轮完整内存Oracle，int／bool各保留693条原断言；仅代入当前两个私有结构定义，宿主vzalloc夹具补足页对齐、slab夹具按请求的二次幂对齐。新增128字节头部、192／256字节inode表、128／192字节dentry表、反查与完整快照检查。ASan／UBSan无诊断。既有工具及断言未改写。
- `test_static_targets.py`：13份完整配置均通过生产布局与回调范围校验；JSON与blob替换一致，恢复基线逐字节一致。派生只改变92字节配置段。
- 两个新候选的ELF元信息、静态布局、全部未定义导入与实际SDK导出比对通过；反汇编未发现FP／SIMD／SVE指令。原生运行端导出和CFI就绪仍由Tester确认。
- 两份4.4静态件及共用动态件另生成旧KP导入变换件，共3个；父候选实例、源提交、工具哈希、原字节和派生哈希、完整命令均在回执。源码和Makefile沿用当前KP输入。

BTF查询和动态短窗口本轮未修改，沿用[前轮八目标报告](2026-10-15-nomount-kernel-extension.md)的相应自检范围。私有代理对齐改变了两个模式的字节，之前的实机结论不能直接绑定到本轮产物。

## 方案复核

### 结论：修改（Modify）

**有效性。** 末端锚点加连续尾部能补齐这五份静态配置，但统一64字节对齐的假设漏掉米8／米9。一次有界反例复核核对目标窗口、锁配置与宏链后，按128字节修正尺寸和代理头部。

**简洁性。** 五份镜像没有可用BTF，直接编译整份参考头文件又会带入已观察到的布局差异。离线取得四个锚点并只解释尾部，比复制完整参考结构或新增目标专用业务实现更少耦合；已有配置段即可承载结果。

**后果。** 该方法仍依赖参考尾部契约，短窗口不能排除未使用的隐藏厂商追加字段。完整复制范围及该契约交独立审计复核，`AUD-001`保持开放；新增配置不扩展运行时动态解析声明。

**实施建议。** 已按修正后的对齐完成冻结和构建；使用下表绑定的静态派生件安排目标实机测试。动态无BTF形态另行扩展，超出6.1的镜像维持原范围。

## 目标派生件

表中哈希对应普通静态适配字节，路径为`artifacts/binary-port/nomount/<SHA-256>/NoMount_2.1.1-20261014_baselines.kpm`。相同配置可得到同一派生字节；目标身份分别记录在回执。4.4需要旧KP导入处理时，改用回执中的legacy派生哈希，并同时保留其父实例身份。

| 目标 | 配置 | 静态派生SHA-256 |
| --- | --- | --- |
| `B2N-416G_boot.img` | [`B2N-416G-v4.json`](../../nomount/configs/B2N-416G-v4.json) | `94bafae7efafcabaaf20e7db119672c0e48d215513a0a5fb961a64c04547a581` |
| `kernel_mi6-4.4` | [`kernel_mi6-4.4-v4.json`](../../nomount/configs/kernel_mi6-4.4-v4.json) | `f4c1c21940a09a2c071b3071712d66d353fc0a40c21a26a1c4aec28ca975647b` |
| `boot_los23.2.img` | [`boot_los23.2-v4.json`](../../nomount/configs/boot_los23.2-v4.json) | `4b6fe6266ace0918f5d294380eb9650df8673a429ea613844a8c9b834e92054e` |
| `boot_67.2.A.3.178.img` | [`boot_67.2.A.3.178-v4.json`](../../nomount/configs/boot_67.2.A.3.178-v4.json) | `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d` |
| `kernel_android13-5.10` | [`kernel_android13-5.10-v4.json`](../../nomount/configs/kernel_android13-5.10-v4.json) | `dfa3e6e99349d60fea428822583b9be8912714513fc12e2de81018a902384c29` |
| `kernel_android13-5.15` | [`kernel_android13-5.15-v4.json`](../../nomount/configs/kernel_android13-5.15-v4.json) | `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d` |
| `kernel_android14-5.15` | [`kernel_android14-5.15-v4.json`](../../nomount/configs/kernel_android14-5.15-v4.json) | `8d497f8fdf2ff2667498b350735f6ae117fa829144cc5f73f21d5595e50a299d` |
| `kernel_android14-6.1` | [`kernel_android14-6.1.json`](../../nomount/configs/kernel_android14-6.1.json) | `b02dc587cb51726f40c17a03bf0b9d081908eba6922cadb1a7907044ca40a08a` |
| `kernel_mi8-4.9` | [`kernel_mi8-4.9-v4.json`](../../nomount/configs/kernel_mi8-4.9-v4.json) | `781e053bda096c774cb9434c0fbf55605c6abc5705f256413421962236d57684` |
| `kernel_mi9-4.14` | [`kernel_mi9-4.14-v4.json`](../../nomount/configs/kernel_mi9-4.14-v4.json) | `09a49a36faba1e25078785848d652a9e787543eb1762a75eb99e77b1591f0c38` |
| `kernel_mi10-4.19` | [`kernel_mi10-4.19-v4.json`](../../nomount/configs/kernel_mi10-4.19-v4.json) | `a2b54956913b128f228509bb0c7d55155911d3d6ecc29cdd21a880ff67c12de9` |
| `kernel_mi11-5.4` | [`kernel_mi11-5.4-v4.json`](../../nomount/configs/kernel_mi11-5.4-v4.json) | `bc69619694faa8f30a783c394317f19fbfd4930f6a6810bb9481bd0bd7001431` |
| `kernel_android12-5.10` | [`kernel_android12-5.10-v4.json`](../../nomount/configs/kernel_android12-5.10-v4.json) | `dfa3e6e99349d60fea428822583b9be8912714513fc12e2de81018a902384c29` |

`AUD-001`、`TST-001`和`DEV-042`的关闭继续由相应发现方复核。本轮没有操作设备或代写审计／测试结论。

## 冻结后复核

严格门禁完成：14项检查，0项失败，2类警告。警告分别为历史zram交接资料缺登记字段，以及历史／当前handoff实例尚未导入metadata；本轮候选已单独通过candidate身份重算，仍由维护者导入。报告、清单、配置和源文件已读回核对，工作树干净。

构建没有错误；SDK的rwonce.h与既有包含链出现READ_ONCE／WRITE_ONCE宏重定义警告（每个模式各两条），本轮未屏蔽或修改SDK。clang-format检查与差异空白检查通过。are-you-sure复核结果及修改依据见上文；no-negative-echo与respect-the-oracle按最终文件检查，历史证据和原断言均保留。
