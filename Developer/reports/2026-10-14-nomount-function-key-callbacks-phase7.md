# NoMount：key 回调的有界核对

4.4与4.19各新增key_callbacks=24，现在各完成42/46项离线核对。还缺inode_ops_size、super_ops_size、dentry_ops_size、key_type_size；完整无BTF初始化仍未完成。

源码冻结提交：`2014db6b2bc2456707e399de3607b9f8e0e62bfb`。上一段见[原生操作回调与ABI](2026-10-14-nomount-function-operation-callbacks-phase6.md)。本轮是Developer探索构建和宿主自检，没有独立审计或实机结论。

## 实现依据

两份已核对的key_type声明都无条件含name、def_datalen、preparse／free_preparse／instantiate及link。这些成员互不重叠，在ARM64中大小合计56字节，因此完整对象至少有56字节。字段重排和填充只可能增加该下界。

生产推导只扫描原生静态key_type_user的这段前缀，候选起点为16、24、32，最后一次读取止于字节55。三个已知原生回调必须连续且唯一，指针核对复用核心代码区内的单B跳板识别。缺符号、未匹配、歧义或槽不一致均失败。这个下界不写入key_type_size，不用于完整对象分配或复制。

另外核对register_key_type前18条：原始类型指针保存在callee-saved寄存器，name@0作为strcmp实参。key_instantiate_and_link前22／26条从原始key取得type，核对def_datalen@8及preparse槽。原生槽必须与前缀中的回调组起点一致；共同头部和连续回调定义仍放nm_structs.h，推导和存储在nm_offsets.c，BTF路径保持原查询。

固定源码与窗口沿用前段身份：Sony源码提交与镜像版本标记一致；B2N镜像4.4.192使用Nokia4.4.196语义参考，字段以实际镜像机器码核对。声明、原生实现和静态初始化的固定URL及文件哈希见[阶段数据](data/2026-10-14-nomount-function-key-callbacks-phase7.json)。

## 自检

新工具test_function_key_callbacks.py直接编译生产推导代码，在两份真实镜像的重定位窗口及表上各核对42项。ASan／UBSan通过。新增缺符号、逐条未知指令、指针位宽、来源覆写、字段错位、原生调用目标、分支落点、槽不一致及CFI落点反例；以56字节后紧邻不可访问页的夹具核对读取边界。

原50个工具逐字节保持，上一阶段155条断言文本全部保留。新字段用独立符号组启用；旧场景保持原有可用符号及失败断言。新场景取得回调后，完整控制校验仍因尺寸缺项返回错误。

首次新增保护页夹具假定宿主页为4096字节，mprotect在16KiB宿主因地址未对齐而失败；现使用sysconf取得实际页大小，仍要求保护设置成功并完成同样边界检查。两份首次失败日志保留在本地探索目录，生产代码未据此改变。

Sony5.15真实BTF的46项查询及拒绝断言回归通过，使用上一段相同的私有API适配副本，原Oracle文件保持。以上均为Tier3宿主证据，未执行原生内核函数或完整初始化。

## 构建身份

统一入口冻结144个输入，两种KPM构建通过。探索档复算冻结源码blob、参数、配方和产物哈希通过，ELF和92字节默认偏移表通过；静态JSON校验后独占创建于新归档。静态件与上一阶段逐字节相同，构建只有SDK已有READ_ONCE／WRITE_ONCE重定义警告。

完整记录见[构建清单](handoffs/2026-10-14-nomount-function-key-callbacks-phase7.json)。两件均为exploration。

| 模式 | instance_id | SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+ge92f664fa0bc.rc01ab88b.kpb51197a.ndk26.3.11579264#1` | `dbfd5937e48c992079cf0a38bd65ea23c7d8dc624f3acc35a55219038b7232dc` |
| static | `nomount-2.1.1-20261014_baselines+ge92f664fa0bc.r870f495d.kpb51197a.ndk26.3.11579264#1` | `b922daa76f010c4a623a3b32f8f35d6055cc2f3fa209bf34808923b66f7d3c7f` |

## 复核决定（Decision）

**保留（Retain）**。

### 有效性

辅助只读挑战确认56字节下界不受成员重排、LOCKDEP或额外填充影响；共同头部和原生preparse槽另行核对。实现后的两目标正反例及保护页自检通过。完整类型尺寸仍未知，不能据此宣称动态件可加载。

### 简洁性

使用已有连续回调定义和单B核对，只增加固定前缀扫描与两个原生短入口；不需要继续读取link之后的未知尾部。既有BTF查询继续优先。

### 后果

回调被拆开、移到前缀外或编译形态改变时拒绝推导。该范围只覆盖当前两目标匹配的原生形态，不构成其他内核的兼容承诺。辅助挑战属于Developer复核，不代替Auditor。

### 后续工作

下一段继续查四类完整尺寸及尚依赖BTF的其他接口ABI。inode、super、dentry存在整表复制，源读取范围必须有证据；key_type目前只创建零表，其分配容量可另评估，但本段保持完整尺寸字段的原语义。当前完整动态入口仍先停在操作表尺寸阶段，旧KP派生件待完整修复候选再生成。

respect-the-oracle核对旧工具、保留断言和Tier3边界；no-negative-echo回读源码、报告和清单。没有设备操作、发布或问题关闭。
