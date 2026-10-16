# NoMount：新增镜像适配与布局缺口

本轮检查仓库中不高于6.1的13份镜像。新增米6的静态配置及动态短入口，已有7目标的配置保留。其余5目标的完整表尺寸尚未证实，研究输入已隔离，未生成设备适配件。**全部13目标适配尚未完成。**

这是Developer实现方自检，不是独立审计，也不是实机结论。本轮未操作设备；既有测试报告仍绑定原实例。

## 冻结身份

- 完整源码提交：`39a55fa3b6b7be4a4bbe85818b2810fdbbc51188`
- KernelPatch输入：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`；仅记录本次构建输入。
- 动态实例：`nomount-2.1.1-20261014+gf2cbe74cd5db.rfd51b64e.kpb51197a.ndk26.3.11579264#1`
- 动态SHA-256：`ffece7d1954ce2bb76d2f783ec9f68f5b4f2d321e92387583c0ba5198250e533`
- 静态基准实例：`nomount-2.1.1-20261014_baselines+gf2cbe74cd5db.r87f3a981.kpb51197a.ndk26.3.11579264#1`
- 静态基准SHA-256：`bcf20a3c924afacb796840bd0ab88db6f62d986a769822314268a150d5db68ca`

统一构建命令：`python3 tools/build_candidate.py nomount --toolchain ndk26.3.11579264 --target all --kind candidate --env ANDROID_NDK="$ANDROID_NDK" --env LAYOUT_DIR=../local/nomount-extension-20261015-01/extension-layout-01 --handoff Developer/reports/handoffs/2026-10-15-nomount-kernel-extension.json`。使用NDK 26.3.11579264；构建仅有SDK既存READ_ONCE／WRITE_ONCE重定义警告。

两实例分别通过candidate档的来源、配方与产物核验。入口见[候选清单](handoffs/2026-10-15-nomount-kernel-extension.json)和[逐项回执](data/2026-10-15-nomount-kernel-extension.json)。维护者尚未导入本次清单。

## 范围

| 镜像 | 本轮离线结果 | 交接范围 |
| --- | --- | --- |
| B2N-416G_boot.img / 4.4 | 原动态准备及边界自检通过 | 静态件、动态件及旧KP派生件待审／待测 |
| kernel_mi6-4.4 | 新增；完整动态布局准备通过，45项与静态参考一致，key采用512字节自建容量 | 新增静态件、共用动态件及旧KP派生件待审／待测 |
| kernel_mi8-4.9 | 可见字段已分析，完整复制范围待补 | 研究草稿 |
| kernel_mi9-4.14 | 可见字段已分析，3个inode成员与参考声明不同 | 研究草稿 |
| kernel_mi10-4.19 | 可见字段与参考存在5处差异，其他表完整复制范围待补 | 研究草稿 |
| boot_los23.2.img / 4.19 | 原动态准备及完整尺寸自检通过 | 新字节静态／动态候选待审／待测 |
| kernel_mi11-5.4 | 原生内联地址判断已补；无BTF、无sdcardfs锚点，完整复制范围待补 | 研究草稿；地址判断代码纳入本轮候选 |
| kernel_android12-5.10 | 无BTF、无sdcardfs锚点，含PAC／BTI，完整复制范围待补 | 研究草稿 |
| kernel_android13-5.10 | 真实BTF，46项一致 | 保留静态配置及BTF路径 |
| boot_67.2.A.3.178.img / 5.15 | 真实BTF，46项一致 | 保留静态配置及BTF路径 |
| kernel_android13-5.15 | 真实BTF，46项一致 | 保留静态配置及BTF路径 |
| kernel_android14-5.15 | 真实BTF，46项一致 | 保留静态配置及BTF路径 |
| kernel_android14-6.1 | 真实BTF，46项一致 | 保留静态配置及BTF路径 |

带BTF目标的结果来自生产查询代码与宿主API夹具，不证明运行端KP查询、CFI调用或完整初始化。原7目标本轮同样没有新实机结论。6.6及以上不在本轮范围。

## 实现与证据

米6的register_key_type前19条保存原始type与链表容器，并在name@0到strcmp实参之间核对来源；super_cache_count前13条核对shrinker、sb、s_op及间接回调。没有按版本号增加偏移分支。完整表末端符合既有4.4尾部几何契约；这仍不能证明任意未使用厂商尾部不存在，AUD-001保持开放。

米11缺少独立is_vmalloc_addr。候选在该接口不可用时，从实际kvfree首14条恢复其内联地址范围：入口保留x0、两个无符号比较、范围常量、vfree／kfree目标与分支均须匹配。提取放nm_offsets.c，新增MOVK解码放kpm_utils.h。业务分配和RCU释放仍使用原路径，vmalloc交vfree_atomic，slab交kfree；未知形态失败。两种编译模式均包含这项补充，**新静态SHA与旧静态件不同，需要重新审计**。

厂商头文件只作语义参考。米10的tty_default_fops调用memcpy，长度288，ADRP／ADD来源核对为tty_fops；旧声明sizeof为256。其i_fop、i_data、address_space和i_private也不同。米9另有3个inode成员差异。完整复制／清零长度、实际成员链与原生调用优先于声明；内核版本标记或build-id不用于识别布局。

五份未完成输入保存在[研究提案](../proposals/2026-10-15-nomount-kernel-extension/README.md)，inode／super／dentry／key四个未确认尺寸为-1，声明值单独记为reference_values。它们没有进入本轮静态适配件。厂商新增的未访问尾部不能靠可见成员或相邻符号距离排除；不能将宿主sizeof或同树源码当成该镜像完整尺寸。

## 自检

- 原4.4、4.19的动态布局Oracle与三表尺寸、BTF路由、保护页用例通过；B2N实际局部符号、绝对链接边界与拒绝路径通过。原工具与断言未改。
- 新增GCC短窗口测试：真实19／13条、32个NOP拒绝变体、strcmp目标、SUB移位拒绝与窗口末端保护页通过。
- 新增地址范围测试：独立原生接口、内联上下界、依赖缺失、14个NOP拒绝变体、保留编码／位宽拒绝、保护页及生产RCU释放分派通过。
- 完整int／bool历史内存Oracle及私有分配测试通过；五份BTF均与各自现有46字段配置一致。
- 八份有效静态配置通过生产布局校验、回调越界拒绝、JSON／blob往返。派生字节只改92字节偏移段；代码、符号、重定位及元信息保持基准原样。
- 两种基准的全部未定义导入与本次KP导出逐项对应，反汇编未发现FP／SIMD／SVE寄存器指令。旧KP转换单独记录工具哈希、父件和修改范围。
- strict仓库检查退出0；仅有历史交接字段与候选未导入警告。这不产生验收结论。

本轮原生准备工具test_native_memory.py的既存假设是is_vmalloc_addr必须有独立符号。新增实现允许从kvfree取得同等判断，因此另增test_vmalloc_range.py核对两条依赖路径；既有Oracle未改写、未删除断言，也未将旧工具称为本轮通过。

## 静态适配件

以下均由上述静态基准派生，路径、父实例与完整命令见逐项回执。三份5.15布局字节相同，复用同一哈希目录并分别绑定目标。

| 目标 | SHA-256 |
| --- | --- |
| B2N-416G_boot.img | `075ff271b2d025d8eeef16dc94f4065a9ec4c8612dfc9dc3b99c43b0a706223f` |
| kernel_mi6-4.4 | `49ebea51be781068a52ed54e0e84f4b9e53f9482ffc3d3e4739e15abe9943e6b` |
| boot_los23.2.img | `e09d474dd101c0ee760dbf99c3c6166774457887b800ebbbc451acf33a897d4d` |
| boot_67.2.A.3.178.img | `ec4a0607ef06978dc7a9eb8a362a49d2afa6b1d20ec90e7b5e1c7f42d6959de9` |
| kernel_android13-5.10 | `b3caa8973c36c7c25328a38fbe113b4095169bf3cc31a93fe492585d53df67fb` |
| kernel_android13-5.15 | `ec4a0607ef06978dc7a9eb8a362a49d2afa6b1d20ec90e7b5e1c7f42d6959de9` |
| kernel_android14-5.15 | `ec4a0607ef06978dc7a9eb8a362a49d2afa6b1d20ec90e7b5e1c7f42d6959de9` |
| kernel_android14-6.1 | `027075173b6926c03bdcc4fe592a11f7bb1130755cf21b5af76e79de8513c811` |

4.4旧KP派生件（源码／Makefile保持最新SDK）：

| 目标与模式 | SHA-256 |
| --- | --- |
| B2N-416G_boot.img / static | `860bc08872c69d19cb382540c7e8e7eadf3d76716dd16009e4b178f181582961` |
| kernel_mi6-4.4 / static | `267f532b96d14f217c607dcc168e4c1cf16c4e055bb2294cdcd3c3bf53320f45` |
| B2N-416G_boot.img、kernel_mi6-4.4 / dynamic | `0f58b8ab59a064264bb7b49af9b94f540437bde16e203554fda79cad0c4d6d0c` |

## 后续核验

先由Auditor复核新增两种GCC形态、kvfree内联判断及两种产物差异，再由Tester按新实例执行定向测试。TST-001／DEV-042及AUD-001由相应独立角色复核，本轮不关闭。

其余五目标仍需可靠的原生表完整范围与控制对象写入范围证据；已有立即数扫描只提供候选，未发现可确认这三类操作表整对象长度的入口。可见槽与参考尾部不足以排除厂商扩展。继续取得匹配的目标类型信息／完整对象操作，或另行评估减少整表复制的实现；在此之前维持失败。

配套ZIP的用户态、协议、安装与启动脚本本轮未变，未重建ZIP。正式发布仍须维护者完成身份导入、独立审计和目标测试绑定。

## 方案复核

**修改（Modify）**。有效性：本轮完成8份目标配置的候选字节与宿主检查，5份新目标仍缺完整范围；总体任务尚未完成。简单性：复用既有静态／动态路径和原生释放接口，只补已观察短入口。后果：静态基准字节改变，需要重新审计；厂商声明不等于目标布局，未确认值以-1保留。三项指定技能的最终复查未发现旧提案残留或既有断言修改。
