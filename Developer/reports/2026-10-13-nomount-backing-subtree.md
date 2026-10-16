# NoMount：backing 子目录规则管理

本轮接通已有 backing 目录中深层子规则的新增、替换和删除。自动父目录在查找时继承实际父 inode 的来源，因此不同 UID 使用各自的源子目录。显式规则查找和缓存重验证同时检查源父目录的搜索权限。

角色为 Developer。源码检查点为 `e7013a5782a8fb05aedbd65dcc7fc6fa4a6b5b68`，ARM64 探索对象从该提交编译。当前没有可加载 KPM、Build ID 或 instance_id；以下为实现方自检，不是独立审计或真机结论。

## 输入与实现

目标仍是 `kernel_img/boot_los23.2.img`，内核 `4.19.325-cip134-st18-perf-g7fc8455b2fa8`。沿用上一轮已核对的输入：

- boot SHA-256：`199658639f7389153ee8a7efe00154f0892e272ddc872728ea326e3e1ce2383b`。
- 有界提取内核 SHA-256：`299f7e2580c54684c3b825bea57f1b16c53055f485ebd2b937593ac57ff9b0d2`。
- 匹配内核源码：`LineageOS/android_kernel_sony_sm8250`，`7fc8455b2fa84be76364c2457e6503b867ceb12a`。
- 配置 SHA-256：`5a03d694a8a1fb015c1e977ada538e8eb7b259dc119a7a771e577481e1d9d450`。
- NoMount 上游：`1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。
- KP 编译输入：`b51197aaba8f2272dd8a3e30c85698a29aa928c9`。

nm_topology.c 在已登记目录下建立私有自动父链，沿用原有单边界发布、失败清理和目录裁剪。不在管理阶段解析这些前缀的 UID 视图。继承标志属于模块私有规则；控制协议及内核偏移表保持原有格式。

新增 nm_backing_subtree.c，复用已核对的 vfs_path_lookup 和 inode_permission2。查找自动目录时，从实际父 inode 的规则取得 backing path，查询同名源子目录，再把独立 path 引用交给私有规则。派生 inode 持有管理节点，所以可以继续读取原内容并查找新增子规则。ENOENT 保留纯目录，源为普通文件时返回 ENOTDIR，其余原生错误保留。继承项的缓存强制重新查找，覆盖源目录暂缺后出现及路径变化。

显式 backing 目录有子规则时，撤销来源仍保留管理节点，后续查找恢复对应父来源。删除最后子规则裁剪自动父链；存活 inode 持有空节点和来源引用直到 evict。建管理父链前已打开的 fallback 目录继续持有原节点，新路径查找进入新管理节点；现有 FD 的视图保持到引用结束。

完整 nm_prepare_backing_queries 在 backing 引擎准备后接入继承与搜索权限。backing 父目录的 lookup 和 ref-walk revalidate 在模块 RCU 外调用 inode_permission2(MAY_EXEC)，保留 source mount；原有 open 检查继续使用 MAY_OPEN | MAY_READ。被排除 UID 仍返回负项，LOOKUP_RCU 仍要求 ref-walk 重试。

## 方案复核

**保留（Retain）**：保留按实际父视图继承来源，并检查源搜索权限的实现。

### 有效性

宿主用例验证同一管理路径下的 UID 1000／2000 分别继承来源 A／B，也验证多层子规则可以查询、替换和撤销。目标 fs.h 定义 MAY_EXEC=1；目标 namei.c 的路径解析使用原生搜索权限。源父目录的搜索检查覆盖显式规则与缓存路径，避免仅靠读取权限遗漏此边界。READ 允许而 EXEC 拒绝的夹具同时阻止两处入口。

### 简洁性

复用现有管理树、私有规则、目录缓存和原生路径解析；新增范围是一个私有标志和两个目录引擎回调。结构体偏移、BTF ABI 和短函数推导均沿用已有依据。原有只读 fallback 节点没有管理身份，无法直接承担深层规则管理；私有父链使用既有发布与回收机制。

### 后果

已打开目录保留原视图，重新按路径查找进入当前管理树。源路径取得、类型拒绝、分配失败和最终 inode 回收均检查了引用配对。一次有界 Developer 辅助只读复核未发现本段新的实质缺陷；它不构成 Auditor 的独立结论。

建议继续接管理锁和用户态控制协议，实际 KPM 初始化调用完整准备入口。独立对象入口用于分段开发。

## 自检与探索对象

证据放在新建的 `local/nomount-backing-subtree-20261013/` 子目录。

- prior-regression-01：未修改的 backing inode Oracle 及其已有 backing、拓扑、目录、inode 用例通过。
- selfcheck-03：ASan／UBSan 通过。再次完整执行已有 Oracle，追加多 UID 来源、深层规则、显式／缓存搜索权限、blocked UID、源暂缺恢复、类型与原生错误、继承分配失败、规则替换、17 个管理父链分配失败点、自动裁剪、存活旧节点及显式目录撤销恢复来源。
- selfcheck-01：新增夹具手写路径长度错误，找不到管理记录；已改用 strlen。生产代码和已有断言未改。selfcheck-02 通过；随后增加显式目录撤销恢复来源的用例，selfcheck-03 通过。失败输出保留。
- compile-01：dynamic／static ARM64 对象从源码检查点编译通过。每份有两条 SDK 既有 READ_ONCE／WRITE_ONCE 重定义警告；其余按 Wall／Werror 检查。导入符号均匹配当前 KP 导出；动态 12937 条、静态 7596 条指令操作数中未发现 FP／SIMD／SVE 或 x18。
- freeze-binding-01：自检源码、工具及对象输入与冻结 Git blob 一致；已有 19 个测试脚本与前一文档检查点逐字节相同。本轮新增一个自检脚本，读取匹配同一源码状态的 Oracle 输出，保留其断言。
- 本轮七个 C／头文件通过项目 clang-format 检查。
- 常规仓库门禁 13 项：0 失败，1 项既有 zram_zstd 交接字段警告（handoff_by／handoff_at）。

| 证据 | SHA-256 |
| --- | --- |
| prior-regression-01/receipt.json | `bd82a53578afa3f2aefa183491b21f1842426be46722860da8bc23ca50f375f0` |
| selfcheck-03/receipt.json | `be803e549d25090fe3ed73267b48e17231ec0e69e5bdc5ff48e77a114354b58a` |
| freeze-binding-01/receipt.json | `291fcb87b433b3710654aabcc349d63b545f06dfceb7a1ff889c4a8482893ac0` |
| compile-01/receipt.json | `6d7d064d03da710f93490fb0c234e446c00005da1eec559f3c34967e41a13b5c` |
| compile-01/dynamic.o | `5ad50a6a06776e2cefb50e092432daf74b66bc352f86b94dbd539cffdf0078fa` |
| compile-01/static.o | `4f11e721aad0152d48295d448b3b3abe2036d96a117766fd053aa550f8c7ede7` |

按 are-you-sure 完成本段挑战；按 no-negative-echo 回读源码与说明；按 respect-the-oracle 保留已有基准。宿主夹具只证明本段调用契约和基础状态路径，真实 ACL、CFI、原生 VFS 并发及 Android 应用扫描仍待独立审计／测试。fallback 符号链接与特殊文件、实际管理锁、keyring、KPM 入口尚未接入。
