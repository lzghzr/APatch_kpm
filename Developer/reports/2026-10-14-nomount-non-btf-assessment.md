# NoMount：无 BTF 动态初始化与旧 KP 转换响应

角色：Developer。分析绑定提交 `d3da1117da53c5d886d7667bc56d342e893cadd3`；其 NoMount 源码、Makefile、布局及自检与发布候选提交 `e9ab619ea75e7fd611c28dcc0328dbb99ebf1dfb` 相同。本轮完成初始化路径复核与动态 legacy-kp 派生件；尚未实现完整非 BTF 降级，也未生成修复候选。

这是开发走查、目标镜像离线分析与转换自检，不是独立审计或新增实机结论。用户编辑的两处 README、旧报告、源码、测试和归档基础件保持原样。

## 实际失败位置

响应[维护者开发请求](../../docs/records/2026-10-14-nomount-dynamic-non-btf-fallback-request.md)。[发布轮实机报告](../../Tester/reports/runs/2026-10-14-nomount-2.1.1-20261014-live%231.md)的日志证明基础字段推导成功，随后返回 -61；日志没有标注返回错误的具体准备阶段。

源码调用顺序为：

```text
nomount_init
  nm_prepare_control_engine
    nm_prepare_backing_queries
      nm_prepare_path_rules
        nm_prepare_directory_view
          nm_prepare_materialization
            calculate_offsets                 已有非 BTF 推导
            calculate_btf_rule_prefixes        首个后续 BTF 硬依赖
            nm_prepare_file_layout
            nm_prepare_operation_sizes
            ... inode、directory 与原生 ABI 准备
    calculate_btf_control_layout               backing 成功后才调用
```

[nm_inode_entry.c](../../nomount/nm_inode_entry.c)第35～52行表明基础推导之后立即调用规则前部查询；[nm_control_entry.c](../../nomount/nm_control_entry.c)第16～20行要求 backing 准备成功后才查 control。当前基础偏移校验只检查已取得的七项字段及对齐，其4.19日志值均满足校验。因此源码路径将首次 -ENODATA 定位到规则前部，不能从现有日志直接归因为 control。

维护者请求与 Tester 报告的定位需分别由所有者追加更正；已有日志和启动成功事实仍保留。问题提案见[登记建议](../proposals/2026-10-14-nomount-non-btf/README.md)。

## 已有推导与剩余缺口

4.19实机基础推导取得 file objects=32/32、mapping=240，inode sb=40、ino=64、size=80、nlink=72/72，dentry ops=96。它们已经写入配置表，并供后续业务访问；这些代码有实际作用。

| 阶段 | 当前非 BTF 路径 | 尚需取得的证据 |
| --- | --- | --- |
| 基础 file/inode/dentry | 已接入并有4.19日志 | B2N通过旧KP符号解析后仍需实际验证；不同 kstat 前部需核对 |
| 规则前部 | 无 | path/dentry共同片段、full_name_hash参数来源与ABI |
| 文件布局 | 只有对象字段入口推导 | open/release/mmap/splice_read槽、完整表尺寸及实际回调契约 |
| 操作表尺寸 | 无 | file/inode/super/dentry/key_type五个完整尺寸 |
| inode布局 | 无 | i_fop/i_data/i_hash/i_blocks、address_space范围、getattr/drop/evict槽及调用ABI |
| 目录布局 | 无 | d_lock、iterate/shared、d_init/release和actor ABI；共同片段校验 |
| 虚拟目录、topology、backing | 无 | 实际原生函数和嵌套回调ABI、权限／挂载上下文 |
| control | 无 | mutex的可用空间和lockdep契约、key回调和预解析数据起点、注册写入范围 |

上述后续缺口为源码走查结果，并非全部在设备上逐一触发。当前维护者方案“只补 control”不足以实现无 BTF 完整加载。

## 对最大分配空间的评估

用户提出参照 genl_family，在尺寸不可用时分配最大空间。这可用于模块新建对象，但分配空间和从原生对象读取的长度必须分别处理。

[rek的genl_family](../../re_kernel/re_structs.h)使用1024字节存储；[创建代码](../../re_kernel/re_kernel.c)分配清零后，只填写取得偏移的成员，不复制已有family。NoMount的key type及专用文件／inode／dentry表同样有新建场景，完整sizeof未必必须作为这些分配的输入；仍需证明容量上限、每个必填位置、原生初始化写入范围和ABI。

NoMount同时存在四种完整原生表复制：

- [nm_inode.c](../../nomount/nm_inode.c)的nm_install_super_proxy复制super_operations，仅替换drop/evict。
- [nm_directory.c](../../nomount/nm_directory.c)的nm_install_directory复制父目录的inode_operations和file_operations，保留原生回调。
- 同文件的nm_cached_dentry_table复制并比较完整dentry_operations，保留原生release等行为。

已有目标声明／配置参考的完整尺寸如下。本次读取既有参考，未重新编译这些声明：

| 目标参考 | file | inode | super | dentry | key_type |
| --- | ---: | ---: | ---: | ---: | ---: |
| Nokia4.4参考 | 216 | 256 | 232 | 128 | 128 |
| Sony4.19匹配源码 | 296 | 256 | 280 | 192 | 136 |

4.19 file/super表有条件成员及厂商KABI尾部，inode/dentry表带对齐。一个回调槽的访问只给出所需长度下界，不能证明类型的最后成员和padding。若把super的最大280同时用于复制4.4的232字节对象，会读取对象后的48字节。只复制已知前部并将剩余置零，则可能丢失原生回调。相邻kallsyms符号间隔也不能直接当作类型尺寸。

因此可以继续评估“新建对象采用有证据的容量上限”，但当前代理表还需要可信的复制范围。扩大分配不会自动解决这个缺口；本轮没有据此放宽源码校验或修改旧Oracle。若改变代理机制或允许目标绑定布局作为补充，应先落实具体范围，再由维护者调整请求并安排独立审计。

## 文件操作表的完整尺寸锚点

用户建议继续查整对象循环、分配、清零与复制。本轮随后找到了tty_default_fops；这证明不能把“现有锚点没有尺寸”推成“目标机器码无法取得尺寸”。其他表仍需分别寻找，不因搜索未命中就判定不存在。

匹配4.19源码的[tty_default_fops](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/drivers/tty/tty_io.c)执行完整file_operations赋值。实际镜像有以下有界证据：

| 目标 | 函数裸内核偏移 | 长度准备 | 实际调用 |
| --- | --- | --- | --- |
| Sony4.19 | 0x8e7a38 | 入口索引5，mov w2,#0x128 | 索引6 BL到memcpy，长度296 |
| B2N4.4 | 0x50e40c | 入口索引2，mov x2,#0xd8；索引1将w1置零 | 索引6 BL到memset，长度216；随后填写各回调 |

长度与已有目标声明参考一致；本次从镜像重新读取并核对BL目标的memcpy／memset别名，不只看立即数。4.19保存与恢复x18属于目标SCS编译，不表示模块可以使用x18。完整指令字、目标镜像／内核哈希及调用目标见[锚点数据](data/2026-10-14-nomount-file-ops-size-anchors.json)。尚未把这一锚点接进生产代码。

这类证据优先于内存边界推测：同类型数组的可靠步长、完整结构赋值、带sizeof的复制／清零／分配，均可成为目标尺寸来源；普通链表循环或部分字段初始化只证明它实际访问的范围。

对已经分配的对象，匹配4.19的[__ksize](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/mm/slub.c)返回slab_ksize或整页大小，不等同原始sizeof。对象若是静态操作表，也不能交给ksize。内存中的NULL、连续零和相邻符号只能作辅助；没有自然终止标记的操作表允许合法空回调及padding。当前还未找到另外三种操作表的同等完整尺寸证据。

## control目标短锚点

本轮只读分析选定的boot_los23.2.img和B2N-416G_boot.img，按boot头kernel段解包。新增诊断存于local/nomount-non-btf-20261014-01；以下是候选锚点，不是已实现的生产算法或完整尺寸证明。

| 目标 | 锚点与裸内核偏移 | 本次观察 |
| --- | --- | --- |
| 4.19 | __mutex_init，0x2d09fc | 7条指令：owner清零、8/12处32位清零、16/24处自指链表、RET |
| 4.4 | __mutex_init，0x80178 | 10条指令：count=1、4/6处半字清零、8/16处自指链表、24处owner清零、32处osq清零、RET |
| 4.19 | user_preparse，0x6ad67c | 入口索引4读datalen=48，索引9读data=40，随后检查NULL；后续memcpy使用相同data和长度 |
| 4.4 | user_preparse，0x2721a8 | 入口索引5读datalen=48，索引9读data=40，随后检查NULL；后续复制使用这份输入 |
| 4.19 | register_key_type，0x6a7344 | 链表遍历从内部link回退120读取name；需要再核对成功分支及注册写入范围 |
| 4.4 | register_key_type，0x26c908 | 成功分支将link设于112/120；完整尾部仍需目标声明与配置证明 |

现有诊断遇到首个RET停止；register_key_type含返回后的另一个分支，因此它不能当作所有分支的完整控制流证明。生产推导需另设包含所需块的固定窗口，并核对基址、条件分支和寄存器覆盖。不能把最后一次store直接当成sizeof。

## 动态旧 KP 派生件

请求B已完成。由已冻结发布基础件转换，不重建或覆盖原件：

- source_commit：`e9ab619ea75e7fd611c28dcc0328dbb99ebf1dfb`
- base instance：`nomount-2.1.1-20261014+gba09058a01e9.r72c71e2f.kpb51197a.ndk26.3.11579264#1`
- base SHA-256：`d78b11a936b7781909118a66bdc104cee2925b5db8d6288c9137e08d1e7f41c0`
- patch_offsets.py SHA-256：`97a51b293af447b3cd6608c953cec95cdfc62f985346463f2285b28ab3c86033`，逐字节等于基础提交中的工具。
- 派生SHA-256：`bfb85fd646159d97e5d8b2f48ac19ead454a74b87355f60f24c88300ba39b010`，154720字节。
- [完整命令、回执及交接](handoffs/2026-10-14-nomount-dynamic-legacy.json)，[字节检查](data/2026-10-14-nomount-dynamic-legacy-checks.json)。

变换将suffix函数导入定义为12字节本地adrp/ldr/br转接，调用KP原名查找函数指针。已核对原有程序节及重定位不变、92字节布局表仍全为-1、模块元信息不变、修改范围符合回执、基础件哈希不变。现有test_legacy_kp_adapter.py在本件上通过：汇编器字节、指针调用模型、原节保持、重复输出拒绝、重复转换拒绝。

此件只解决旧KP符号导入，不补布局，也不提供suffix匹配能力。尚无本件实机结果。请求A落地后必须从新候选重新转换，再交Tester；本件供转换复核与问题定位，不是完整非BTF修复交接。

## 方案复核（Decision）

**修改（Modify）**：沿用现有短函数推导方向，将补齐范围覆盖实际初始化链；最大空间用于新建对象时单独核验，原生表复制范围另行取得。

### 有效性

基础推导已有真实4.19日志，首个后续失败由源码路径定位为规则前部。控制层之后还有多处必要布局和ABI，因此control单项改动无法满足完整加载目标。

### 简洁性

优先复用共同结构、现有短入口与原生接口。完整复制／清零锚点可直接提供尺寸，tty_default_fops已在两目标取得证据。扩大自有对象容量可以减少不必要的精确尺寸依赖；当前静态件可用，但不能替代用户要求的无BTF动态支持。

### 后果

原生表复制长度猜大可越界读取，猜小可丢失原生行为。改变代理策略还涉及已审计的VFS及生命周期，需明确范围并独立复核。发布继续遵循维护者暂停决定；本报告不关闭任何问题或宣布无BTF动态可用。
