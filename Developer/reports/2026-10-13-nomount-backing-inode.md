# NoMount：backing 目录 inode 接入

本轮将 backing 查找、合并枚举和 seek 接到共用目录回调。显式规则优先；原有普通文件及子目录通过原生路径解析读取，子目录可递归进入。源目录与普通文件打开前增加原生读取权限检查。没有显式规则的缓存条目强制重新查找，覆盖源子项替换、删除以及负项变为存在的情况。

角色为 Developer。源码检查点为 `19a8f31739f7c994b145728d4d7c46df7608053b`，本轮 ARM64 探索对象从该提交编译。尚无可加载 KPM、Build ID 或 instance_id；以下是实现方自检，不是独立审计或真机结论。

## 输入和结构

目标仍为 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 匹配内核源码：`LineageOS/android_kernel_sony_sm8250`，`7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。
- NoMount 上游：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- KP 编译输入：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。

新增 nm_backing_inode.c，将上一轮的 path 查询与目录封装接入现有 inode 生命周期。纯虚拟与 backing 目录共用完整操作表和 iget5_locked 缓存，通过 rule 类型分派。布局访问仍放在 nm_offsets.c，没有新增结构体偏移或扫描。属性复制抽成公共函数；文件继续借用 backing mapping，目录保留自身 i_data。目录 getattr 使用源路径的原生 stat，再替换虚拟 ino/dev。

新 inode 解锁前取得 rule/node 引用，缓存命中只释放本次预分配 info。fallback 的独立 path 转交私有规则，普通文件复用现有物化，子目录持有新建空节点并递归走相同引擎。私有规则不进管理索引，published 标志阻止再次发布到叶节点。类型拒绝和分配失败释放取得的 path；原生 splice 消耗 inode 引用，沿用已有 alias 检查。

目录 lookup 对 blocked UID 先返回负项，与 pinned 上游的规则一致。无显式 leaf 的 owned positive／negative 仍由既有 revalidate 摘哈希并重新查找；源路径的旧 inode 可以由先前打开的对象继续持有，直到引用结束。

## 方案复核

**保留（Retain）**：采用下述权限边界修正后的共用目录引擎。

### 有效性

匹配目标的 [may_open](https://github.com/LineageOS/android_kernel_sony_sm8250/blob/7fc8455b2fa84be76364c2457e6503b867ceb12a/fs/namei.c#L3111) 执行 inode_permission2，而 dentry_open 的 do_dentry_open 不负责这项 DAC 检查。只复制 mode/uid/gid 无法保留源 ACL 或 Android permission2 的拒绝条件，因此完整引擎先解析原生 inode_permission2，打开普通文件和目录前执行 MAY_OPEN | MAY_READ。目标声明、符号和 CFI 跳板均已核对；BTF ABI 核对独立放在 nm_btf.c。被排除 UID 在 fallback 之前停止查找。

### 简洁性

沿用共同结构、完整目录操作表、规则引用、iget5 和 RCU 回收，偏移表保持不变。原生路径查询负责 source 路径处理；既有 revalidate 强制刷新派生缓存。

### 后果

只读 Developer 辅助挑战回看后未发现本段新的实质缺陷，范围限于 backing 根目录、递归子读取、源权限调用和初始化清理。完整准备成功后才开放 backing 目录规则；失败清理已分配且尚未发布的私有表，并清空引擎、拓扑准备状态和权限入口。文件独立对象入口仍供分段开发使用，实际 KPM 入口必须准备完整引擎。

按 are-you-sure 完成本段挑战；按 no-negative-echo 回读源码和说明；按 respect-the-oracle 核对之前 17 个测试脚本与上一文档检查点逐字节一致。本轮新增两个脚本，完整保留旧 backing 及布局 Oracle。宿主结果不能外推成真实 ACL、挂载点、CFI、并发或设备结论。

## 自检与对象

证据保存在新的 `local/nomount-backing-inode-20261013/` 子目录。

- selfcheck-03：通过 ASan/UBSan。覆盖根目录物化／缓存复用、splice 与 alias、源读取权限拒绝、共用回调枚举和 seek、显式覆盖、递归查找、源替换／删除／出现后的重查、blocked UID、fallback 分配失败和类型拒绝、普通文件 read_iter 转交、规则撤销后引用释放、私有表清理。
- layout-01：完整执行既有 backing 布局 Oracle，编译核对匹配目标 inode_permission2 的三个参数及返回值，执行生产 BTF 的参数数量、位宽、返回类型和缺符号拒绝边界，ASan/UBSan 通过。
- prior-regression-01：未修改的 backing 查询／枚举及其旧拓扑、目录、inode Oracle 通过。
- compile-01：dynamic／static ARM64 对象从冻结源码编译通过。每份对象有两条 SDK 既有 READ_ONCE/WRITE_ONCE 重定义警告，其余按 Wall/Werror 检查。全部未解析导入与当前 KP 导出对应；动态 12611 条、静态 7272 条指令的操作数检查未发现 FP/SIMD/SVE 或 x18。
- freeze-binding-01：本段自检、工具和对象输入哈希与冻结 Git blob 匹配，17 个已有 Oracle 未变。
- 初次 selfcheck-01 的初始化清理 const 限定错误已修正；新增夹具中的 puts 名称遮蔽也已修正。selfcheck-02 暴露新增夹具继承了前一 Oracle 的模块 f_op 标记；只重置新夹具的原生操作表，保留生产递归拒绝与旧 Oracle。
- 常规仓库门禁 13 项：0 失败，1 项既有 zram_zstd 交接字段警告（handoff_by／handoff_at）。

| 证据 | SHA-256 |
| --- | --- |
| selfcheck-03/receipt.json | `932e9e74bd522586256567d20e1f7d40daa986ca1595eb517180437950b290b2` |
| layout-01/receipt.json | `27af45eadb81baa669c896413e9987fc12894e50b70aae7599c94960dc1d1994` |
| freeze-binding-01/receipt.json | `7917cf96d3126c52c9197bf2cbb17eb147e08bcdfdc1d68cf9cd62152f716815` |
| compile-01/receipt.json | `b8966cdd5979fb2741a0ad7fd7cc40b6321287f558ef10ea661fbd2c4e91e51f` |
| compile-01/dynamic.o | `d45ff3134290be790d15c39c65809a2bf76987be8e183173c03504bb08a628d7` |
| compile-01/static.o | `308c451fce652ad427ed788accafdebad308a714cff58ddfb842144bfcd4e82c` |

当前支持已登记 backing 目录下的直接规则，以及源子目录的递归读取。递归产生的子目录节点尚未进入管理索引；在这些目录中继续新增规则的采用流程仍需接入。fallback 符号链接／特殊文件、完整源 ACL 效果、规则并发修改、实际管理锁、keyring、KPM 初始化和 Android 扫描尚未验证。真实内核及设备证据继续由 Auditor／Tester 分别给出。
