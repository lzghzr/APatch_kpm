# NoMount：从立即数反查完整尺寸

反查立即数能找到有效锚点。本轮在Sony 4.19额外找到`full_proxy_open`对`file_operations`的296字节分配，但尚未取得另外四类完整尺寸的新证据；两目标仍各为42/46项，完整无BTF动态初始化尚未完成。

本轮只做Developer离线分析，没有新构建、设备操作或问题关闭。此前源码及探索产物身份见[阶段7报告](2026-10-14-nomount-function-key-callbacks-phase7.md)：源码`2014db6b2bc2456707e399de3607b9f8e0e62bfb`，dynamic实例`nomount-2.1.1-20261014+ge92f664fa0bc.rc01ab88b.kpb51197a.ndk26.3.11579264#1`，SHA-256为`dbfd5937e48c992079cf0a38bd65ea23c7d8dc624f3acc35a55219038b7232dc`。该旧实例仍是探索件。

## 检索与判读

选定输入为`boot_los23.2.img`和`B2N-416G_boot.img`。先以静态参考中的六种尺寸寻找MOVZ、逻辑立即数、ADD/SUB及标量字面量加载，再找附近的分配、复制、清零调用，核对长度实参与对象来源。六种尺寸包括剩余四项，以及已知的file_operations、address_space两个对照。数字仅作检索条件，不写回生产偏移。

核心代码区和初始化代码区分别检索，Sony共20,205次数值命中，B2N共15,224次。核心区附近内存调用候选分别为1,701／609条；仅保留常量直接位于相应长度实参寄存器的初筛候选后为263／563条。该筛选尚未执行完整寄存器活跃性和控制流证明，数字不是有效证据条数。

按候选函数反查固定源码，Sony扫描54,012个C／头文件，匹配240个函数名、1个未解析；B2N扫描43,024个文件，匹配374个函数名、27个未解析。Sony使用镜像版本标记对应源码；B2N仍只用4.4.196作为4.4.192镜像的语义参考，不能直接继承其布局。输入哈希、源码提交、代表性指令窗口及检索边界见[数据](data/2026-10-15-nomount-immediate-size-search.json)。

| 目标与入口 | 数值 | 追踪结果 |
| --- | ---: | --- |
| Sony `tty_default_fops` | 296 | 传入memcpy的x2，完整复制file_operations |
| B2N `tty_default_fops` | 216 | 传入memset的x2，完整清零file_operations |
| Sony／B2N `address_space_init_once` | 264／152 | 传入memset的x2，与已核验address_space尺寸一致 |
| Sony `full_proxy_open` | 296 | 请求分配`sizeof(*proxy_fops)`，对象为file_operations；有效的新对照 |
| Sony／B2N `proc_pid_limits` | 256 | 复制rlimit数组 |
| Sony `alloc_pipe_info` | 136 | 分配pipe_inode_info |
| Sony `erofs_fill_super` | 192 | 分配erofs_sb_info |
| B2N `inode_doinit_with_dentry` | 256 | SELinux上下文缓冲，INITCONTEXTLEN为255，再加终止字节 |
| B2N `loop_set_status64` | 232 | loop_info64用户数据及其缓冲处理 |
| Sony `make_empty_dir_inode`／B2N `is_bad_inode` | 256／128 | ADRP后的地址计算，不是长度 |

另检查了Sony与B2N的`init_sdcardfs_fs`及直接缓存初始化函数。它们建立sdcardfs私有inode、dentry等缓存并注册文件系统，未提供所需操作表尺寸。源码中的isofs_dentry_ops确为同类型数组，但两个镜像配置都关闭ISO9660_FS，不能作为这些镜像的运行时锚点。

## 复核决定（Decision）

**修改（Modify）**。

### 有效性

有界辅助复核指出初始脚本遗漏初始化代码区，并会漏掉内联复制、元素计数、端点差及间接helper。已补查两目标初始化区和指定sdcardfs入口。已知对照及原始指令断言通过，新增file_operations分配对照说明方法有效；剩余四项不能因数字相同而采纳，也不能据这轮搜索断言不存在其他证据。

### 简洁性

保留“数字候选→实参及对象来源→短窗口”的顺序。目前没有新增生产解析器：新的命中仍属于已有完整尺寸，重复增加同类锚点不能解决当前缺项。

### 后果与边界

初始化代码可能在运行时已被回收，即使在那里取得尺寸，也要另证其可用于动态加载的取值来源。内联访存、展开和余数、移位后的元素计数、跨helper传播及端点差仍未穷尽。整表复制仍需可信源读取范围；本轮没有据候选扩大读取或分配范围。

辅助复核属于Developer自检，未代替独立审计。respect-the-oracle核对本轮未改变生产断言或既有Oracle；no-negative-echo回读本报告与数据。没有新增可用动态KPM的结论。
