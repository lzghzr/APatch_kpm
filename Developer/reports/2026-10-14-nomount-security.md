# NoMount 0.5.1：系统 APK 读取与安全标签

已定位到“APK 已被系统登记，ART／应用仍无法读取”的故障。0.5.1 为新虚拟 inode 继承原生安全上下文，并补齐 WebUI 空列表表情 `_(._.)_`。新字节完成 Developer 自检，等待独立审计及真机复测。

## 冻结身份

源码提交：`cfb971d195d997808b68567b8ffc61a4dcd32b90`。上游 `7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`、SDK `b51197aaba8f2272dd8a3e30c85698a29aa928c9` 保持冻结。

| 产物 | instance_id | SHA-256 |
| --- | --- | --- |
| base | `nomount-0.5.1+g17d96f6cff64.r512871f4.kpb51197a.ndk26.3.11579264#1` | `4676fe436e4cdf0e405ff158d80d983b35fd79fc6c0d5ae63f196017adf0725b` |
| baselines | `nomount-0.5.1_baselines+g17d96f6cff64.rf55be15b.kpb51197a.ndk26.3.11579264#1` | `1062ee65515eeed841a423cdab68f7c20de233861266a7f88eb59ccfa628fea8` |
| baselines_debug | `nomount-0.5.1_baselines_debug+g17d96f6cff64.r5f96b882.kpb51197a.ndk26.3.11579264#1` | `d73f812c952e439f7f8dd81234442f367bde7399356e848cf40d1ef46eaf8401` |
| debug | `nomount-0.5.1_debug+g17d96f6cff64.r0b80f597.kpb51197a.ndk26.3.11579264#1` | `9f0f91cb32d7a237f25a8abc1465c31ff57f70283e04fe60614135efbceeb03e` |
| ZIP | `nomount-zip-0.5.1+gd59432122045.ndk26.3.11579264#2` | `3c101a96ddb42b6ca1ce33d9d2f17270f918704bcfdf19ee4da64b066c0490e8` |

四基础件见 [候选清单](handoffs/2026-10-14-nomount-0.5.1.json)，七目标的16条派生记录／12份唯一字节见 [目标清单](handoffs/2026-10-14-nomount-0.5.1-target.json)。Sony 5.15 普通静态测试件为 `artifacts/binary-port/nomount/abe50c726bb7c42a4b21edf8485aef89cf98208c3324a49be5d2877166d9d134/nomount_0.5.1_baselines.kpm`，SHA-256 `abe50c726bb7c42a4b21edf8485aef89cf98208c3324a49be5d2877166d9d134`；其 base instance 是上表 baselines，基准哈希及转换命令均在清单中。ZIP身份与输入见 [ZIP清单](data/2026-10-14-nomount-0.5.1-zip.json)。

## 手机现场

用户明确授权读取连接的手机。设备指纹 `48b7ee2f`，Android15，Sony5.15.189，SELinux Enforcing。当前boot分区哈希与 [Tester的0.5.0启动记录](../../Tester/reports/runs/2026-10-14-nomount-0.5.0-5.15-boot-live%231.md) 一致；安装的nm、metamount.sh、WebUI三个文件分别与0.5.0冻结ZIP逐字节哈希一致。没有从运行内存重新提取KPM；模块身份依现有启动记录、boot哈希及控制版本绑定。

既有规则已经加载，多项相关APK已被PackageManager登记为SYSTEM，部分还存在数据分区更新。现有日志显示artd打开虚拟系统APK返回Permission denied；应用类加载则出现空DexPathList及ClassNotFoundException。源文件0644、父目录0755，标签system_file；对应虚拟APK标签为unlabeled。未取得与每次EACCES一一对应的完整AVC，因此仍需以新字节的实际应用／ART访问验证因果链。

关联原候选：源码 `773385757fcaaa6588e7946862e6784842c1901c`；base `nomount-0.5.0_baselines+g6e270f8a5698.r71a1a5a7.kpb51197a.ndk26.3.11579264#1`／`fd5340662be4a36cb4bb63c86e33754d79a63aea23ac3fed3ae032e02eee3b9d`；Sony派生哈希 `d908196e2d889888863196b04fe285b4ad3d012d35a5523868b43999ab8c0ca9`；ZIP `nomount-zip-0.5.0+g3294dedbfe67.ndk26.3.11579264#1`／`b6271dde3dda3ff2e1edf1330add61add12d03457ee6aa4b4cc73a8ea44100e3`。

读取只取得状态、文件属性、既有日志和哈希，未加载新模块、重启、安装或改策略。raw日志仅存本地忽略目录，公开记录只保留摘要。先前Tester的UID读取探针处于magisk SELinux域，不能据此证明普通应用域可读。

## 实现

原物化代码复制mode、uid、gid等属性，却没有初始化LSM标签；mmap后按原版清除S_PRIVATE，使后续LSM检查面对unlabeled inode。普通文件的真实来源权限检查及原版mmap契约保留。

新增 `nm_security.c` 调用security_inode_getsecctx、security_inode_notifysecctx、security_release_secctx与security_inode_getsecid。文件和backing目录取源inode，纯虚拟目录取实际父inode。先设置mode，再初始化新inode的独立LSM上下文。getsecctx可能睡眠，在iget/hash锁及模块RCU范围外执行。目录在原生I_NEW阻挡使用者时由初始化者独占；普通文件尚未发布dentry。notify成功后核对真实SID，避免LSM把“不支持标记”转换为成功却没有更新对象。

私有info加入来源SID和init_error，46项／92字节布局表、七目标配置与ABI分派不变。目录cache test比较已经取得的SID；ref-walk重验证读当前来源／父SID。获取完整上下文同时完成原生标签初始化，不能把仅返回已存SID的getsecid当成它的替代。目录失败记录错误、发布初始化完成、unlock_new_inode，已命中的等待者也检查错误并iput，失败inode由正常模块evict释放path/node和私有info。LSM原有blob继续由原生inode分配及销毁管理。

原生API以 [Linux4.4声明](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v4.4/include/linux/security.h)、[Sony4.19声明](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/include/linux/security.h)、五目标真实BTF核对。4.4 getsecid的inode形参含const，ARM64传参相同；其余接口共用相同参数与返回值。七目标均具备新增原生符号。SELinux的mode/class初始化、notify无效成功及getsecid非分配读，依据 [Linux5.15实现](https://github.com/torvalds/linux/blob/v5.15/security/selinux/hooks.c)。原生接口和符号证明不替代目标运行端CFI及并发验证。

## 自检及Oracle

[selfcheck数据](data/2026-10-14-nomount-0.5.1-selfcheck.json) 包含完整回执。新增 [test_security_context.py](../../nomount/tools/test_security_context.py) 读取冻结0.5.0的int/bool Oracle，每种735条旧断言中733条原文及顺序保留，2条只增加SID参数。迁移逐字登记，需Auditor复核；35份既有测试脚本全部保持冻结字节。源码新增51个assert，每套共786个；完整宿主程序经ASan／UBSan运行通过。数量是代码断言数，不是运行时通过计数。覆盖复制后的SID／mode、mmap后标签保留、源／父改标签、目录缓存复用、缺接口、空标签、分配／notify失败、无效成功、重标记竞争及I_NEW等待者清理。

四基础件candidate指纹核验4/4；四基础件及12份唯一派生字节通过ELF、SDK导入、指令寄存器和布局检查。静态配置JSON／blob一致，恢复基准逐字节一致；修改范围92字节。4.4可选旧KP处理仍只作用于派生二进制。编译仅有SDK既有READ_ONCE／WRITE_ONCE重定义警告。格式检查通过；第一次源码检查点的include排序编译错误已由本冻结提交修正，失败构建未登记。

ZIP脚本15种宿主流程通过，打包与解包逐字节一致，JavaScript语法检查通过。四处空列表都生成 `_(._.)_`，上游gitlink不变。与0.5.0 ZIP相比只有NOTICE、module.prop、WebUI index.js变化，原用户态二进制及加载脚本保持相同字节。重新冻结后ZIP使用实例#2；实例#1保留原样。

常规仓库门禁0失败，1项历史zram_zstd交接字段警告。当前0.5.1源码自洽；metadata版本及新实例导入由维护者处理。

## 方案复核决策（Decision）

**修改（Modify）**：原生上下文继承需同时处理SID确认、标签缓存和I_NEW失败等待者。

### 有效性

继承原生上下文针对未标记inode及后续LSM读取失败。实际SID核对、错误等待者处理及标签缓存失效的宿主反例均通过，真实应用／ART访问尚待新字节验证。

### 简洁性

使用原生接口，无需取得LSM私有布局；新增状态仅承担缓存身份与I_NEW错误传播。getsecid仅返回已存SID，无法代替getsecctx完成来源标签初始化。

### 后果

上下文读取可分配，失败向VFS传播；放进RCU或hash锁会产生睡眠风险。上下文在锁外取得，每个新inode保有独立LSM对象，错误路径经原生iput/evict回收；实际CFI和并发由独立角色验证。

### 修订建议

交接本报告绑定的原生标签继承候选，先独立复核生命周期及Oracle迁移，再用Sony5.15的真实应用／ART访问确认修复，并回归已有低版本目标。

## 交接与关闭条件

[DEV-036提案](../proposals/2026-10-14-nomount-0.5.1/issues.json) 记录已交接候选的缺陷，Developer不关闭。Auditor复核原生LSM ABI、对象类、独立security生命周期、未发布／I_NEW独占条件、缓存失效、失败waiter与两条Oracle迁移；Tester以新KPM和ZIP身份完成Sony5.15普通应用／artd读取、APK映射、实际DEX／类加载与开机存活，并回归4.4／4.19已有用例后，由另一角色复核关闭。

本次设备读取不是新候选实机通过。ZIP模块能看到、PackageManager能登记与实际应用能运行分别记录；UID切换后的magisk域探针不能代替应用／ART域。虚拟目录保留原版S_PRIVATE，其ls -Z显示不能单独作为读取成功判据；重点核对完成mmap后的APK标签及真实进程访问。6.1无实机，5.10／其他GKI目标仅有已有离线证据。
