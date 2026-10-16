# NoMount：非 BTF 文件字段与表尺寸推导

本阶段将真实目标的文件字段和完整file_operations尺寸接入生产推导，并补充初始化阶段日志。源码检查点为 `40653f93ba61416e2bc1bad6c69c97aa04a168d4`。角色：Developer。

这是冻结输入的探索构建及开发自检，**尚不是完整非BTF修复候选**。实际初始化仍先受规则前部BTF查询阻挡，后续操作表、inode、目录、ABI和control缺口仍按[前一轮分析](2026-10-14-nomount-non-btf-assessment.md)记录。没有实机操作或新的Tester结论，DEV-039/040登记提案仍待维护者采纳。

## 实现

生产修改在[nm_offsets.c](../../nomount/nm_offsets.c)，统一使用[kpm_utils.h](../../kpm_utils.h)。BTF查询与46项／92字节配置表不变，协议、回调集合、准备顺序和驻留生命周期不变。

- tty_default_fops限定前7条，核对x0仍为入口对象、x2长度、memcpy／memset实际调用目标。复制源须等于解析到的tty_fops，清零填充值须为零。
- 尺寸窗口只接受目标已观察的序言和参数设置。辅助挑战发现STXR/CAS的隐式目的寄存器会绕过粗略低5位判断，已改为白名单并追加反例；这项挑战是Developer辅助，不是独立Auditor结论。
- Sony的tty_fops名字带LLVM后缀，使用最新KP的后缀查找接口。B2N旧KP仍按已构建二进制转换，不加入源码或Makefile兼容分支。
- simple_open允许x0承载已读出的i_private，仍要求同一结果经CBZ后写入入口file；nonseekable_open支持相邻AND／STR及中间只设置返回值W0=0的形态，遇分支停止。
- B2N的file_ns_capable核对入口保存、CMP W2、建立frame pointer和B.LS，分支目标必须落在12条窗口内并直接从原x0读取f_cred。没有线性穿越告警块或跟踪任意全函数分支。
- 公共宏新增SUBS immediate、B.cond条件及imm19、STP宽度getter；原指令识别与解码行为保留。
- 日志分别指出BTF不可用后的对象／文件推导、推导错误，以及规则前部查询失败。有效BTF错误继续传播，未用短函数覆盖。

## 目标结果

以下均由新增工具直接执行生产函数片段、读取两份真实镜像指令，并与绑定配置参考核对：

| 字段 | B2N 4.4 | Sony 4.19 |
| --- | ---: | ---: |
| inode_private | 536 | 704 |
| file_private | 208 | 200 |
| file_position | 112 | 104 |
| file_flags | 64 | 64 |
| file_cred | 152 | 144 |
| file_ops_size | 216 | 296 |

目标镜像／内核哈希、每段窗口指令、原始参考哈希、生产输入哈希及自检回执见[本阶段数据](data/2026-10-14-nomount-function-file-phase1.json)。B2N源码仍只是Nokia4.4.196语义参考，不改称镜像的准确构建源码。

## 自检与冻结构建

- 新工具test_function_file_layout.py两目标通过ASan／UBSan。覆盖存储值、布局消费者、必要回调槽缺失拒绝、有效BTF错误不降级、缺符号、错误源表／填充值／调用目标、长度位宽和边界、寄存器覆盖、STXR/CAS、条件分支及窗口末端。查询API由夹具提供；部分回调槽由目标参考预置以检查消费者，另有未取得槽仍失败用例，不表示完整动态加载成功。
- 原re_kernel指令Oracle通过；39个既有NoMount Oracle工具逐字节未改。
- 原test_target_layout.py以Sony5.15真实BTF执行全部46项查询及既有拒绝断言，通过。旧query-fixture缺0.5.2引入的nm_log_info声明，首次编译失败；只在新的私有输入副本增加日志宏别名后通过，原工具、原夹具及断言保持。
- 统一构建入口从上述干净提交冻结138个输入并构建两件。首次默认布局JSON在模块目录引起输入集合变化，事务拒绝且未登记；保留失败日志，将输出移至独立LAYOUT_DIR后重新构建，输入复核不变。
- 构建只有SDK既有READ_ONCE／WRITE_ONCE重定义警告。探索档核验复算了源提交、配方指纹、有效参数与产物哈希；ELF及92字节表检查通过。参数复核须传入相同NDK与LAYOUT_DIR，未传环境的一次核验按参数不一致返回失败，按原环境复核通过。
- 静态件与已发布轮冻结基础件逐字节相同；动态件改变。字节一致性由Developer检查，不替代维护者验收或独立结论。

统一构建清单见[阶段身份](handoffs/2026-10-14-nomount-function-file-phase1.json)，kind均为exploration；尚未请求Tester加载这些中间件。

| 模式 | instance_id | KPM SHA-256 |
| --- | --- | --- |
| dynamic | `nomount-2.1.1-20261014+ga0ccee2cd032.r8a9c4598.kpb51197a.ndk26.3.11579264#1` | `cb549d7782a663131a6e246d8ac114bbafa72588059765529bc10ca597e653c3` |
| static | `nomount-2.1.1-20261014_baselines+ga0ccee2cd032.re6b83c18.kpb51197a.ndk26.3.11579264#1` | `76e220cd0c7a6c2f5002d5f26148483baa06ccccad61f4838060159b7f2adac2` |

## 方法与下一阶段

按用户本轮直接授权，更新[kernel-offset-derivation技能](../../.agents/skills/kernel-offset-derivation/SKILL.md)：分配、复制／清零、整结构赋值、字节／字循环、数组步长、外层相邻成员及原始ELF／调试信息的尺寸来源。区分完整尺寸、容量和访问下界；数组须还原单元素步长，指针数组只能给出指针宽度。quick_validate校验通过。

对其余inode_operations、super_operations和dentry_operations，公开源码搜索暂未找到等价整对象尺寸锚点；搜索使用默认分支，仅用于寻找候选，不能作为绑定两目标“没有此类函数”的证明。还需从目标源码的分配／整表操作／数组用途继续定位，并以实际机器码确认。当前没有采用相邻kallsyms间隔或最大复制长度。

are-you-sure本段结论为修正后保留（Retain），两项具体反例已修正并自检；no-negative-echo回读最终源码和记录；respect-the-oracle核对旧工具未改，新增用例只证明组件及有界路径。发布继续遵循维护者暂停决定。
