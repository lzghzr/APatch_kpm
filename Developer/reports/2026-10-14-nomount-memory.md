# NoMount 0.4.3 小对象分配

Developer第一阶段冻结候选，供独立审计复核；不是实机或验收结论。

## 身份

源码提交：`0ebd44d5a6378ad1260b9cd3a1ac51e1e9e43265`。SDK保持b51197aaba8f2272dd8a3e30c85698a29aa928c9，上游保持7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.4.3+g3d2ac8297e9f.r47d6d68a.kpb51197a.ndk26.3.11579264#1` | `bfe4d5766a4faf4bc12a9c15c01f4ed90c1f9a6731f7345b3e556ce8ba305f27` |
| baselines | `nomount-0.4.3_baselines+g3d2ac8297e9f.r6ea8fecf.kpb51197a.ndk26.3.11579264#1` | `73b4e2f858c5577b003f5739508374ceb59aa7070588885791cee37ae569811d` |
| baselines_debug | `nomount-0.4.3_baselines_debug+g3d2ac8297e9f.r195e0ce6.kpb51197a.ndk26.3.11579264#1` | `9ebfef1f1529b7f23084acc09663b2759c28a7759ff279f729611329bdbb9ba0` |
| debug | `nomount-0.4.3_debug+g3d2ac8297e9f.rcc6e6dc2.kpb51197a.ndk26.3.11579264#1` | `b1c7eac492886d9e9cf5519aa7c42c8cec07e4b2abc7d69cbe3bab88fb2fad72` |

[基础清单](handoffs/2026-10-14-nomount-0.4.3.json)、[7目标派生](handoffs/2026-10-14-nomount-0.4.3-target.json)、[ZIP](data/2026-10-14-nomount-0.4.3-zip.json)、[自检](data/2026-10-14-nomount-0.4.3-selfcheck.json)。16条派生记录对应12份独立字节；B2N含可选旧KP二进制转换，基础源码与构建仍面向当前SDK。

## 实现

私有1～1024字节分配先调用原生__kmalloc(size,0)，请求向上取至少64字节二次幂并清零，保证操作表头部对齐。失败和大对象保留vzalloc。零大小返回NULL。整个包装器仍允许睡眠；0不是GFP_NOWAIT或GFP_KERNEL的别名，也不使用跨版本宏位猜测。

普通释放走原生kvfree，RCU回调按is_vmalloc_addr分配来源使用kfree或vfree_atomic。路径释放留在进程上下文；原生memdup_user载荷继续kfree。规则、批次和inode引用语义保持，46项92字节配置未变。

接口声明参考SDK的__kmalloc/kvfree及Linux原生实现；目标现存符号缓存核对7/7。符号存在本身不证明目标运行。分配与释放机制见[Linux分配说明](https://docs.kernel.org/core-api/memory-allocation.html)及[原生kvfree](https://github.com/torvalds/linux/blob/v4.4/mm/util.c#L303)。各目标新增函数地址、输入哈希已记录自检。

## 自检

- 完整int/bool Oracle和新增分配用例在ASan/UBSan下通过，旧assert表达式及顺序保留。旧夹具选择slab未命中的合法后端，独立用例验证slab成功、回退成功、总失败、零大小、清零、对齐和普通／RCU释放配对。32份既有测试脚本逐字节保留。
- 14项原生依赖缺失逐项拒绝，7目标新增函数符号齐全；四ARM64候选构建与candidate指纹复算通过。
- 基础和派生ELF导入均来自当前SDK导出，可执行指令未使用FP/SIMD/SVE及x18；静态配置仅92字节变换，JSON/blob一致并还原基础字节。
- ZIP使用相同冻结上游用户态及WebUI，仅配套版本更新；没有新增安装操作。

## 方案复核

决定：保留（Retain）。有效性：小对象成功走slab时减少原有按页分配，失败回退保留旧行为；宿主用例仅证明控制流。简洁性：直接使用原生分配／释放，不引入池、对象头或新偏移。后果：新增原生函数依赖和slab占用，缺依赖拒绝初始化；RCU释放明确异步处理vmalloc来源，实机压力及性能仍由Tester记录。一次有界反例复核要求补零大小、对齐、回退和引用用例，已落实；这是开发自检，不替代Auditor结论。

下一阶段单独解耦inode绑定，现有本阶段产物和记录保留。
