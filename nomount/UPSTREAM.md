# 上游基线与差异

- 仓库：<https://github.com/maxsteeel/nomount>
- 配套 ZIP 冻结上游：`v2.3.1`，完整提交 `dcd77d03e9912f397a586d7da81694d1628f170e`。
- KPM 上一轮核对的上游内核提交：`00e7c5d4fdbf1e58decea3522b8eb7207a46d413`。
- 上游内核版本标记：`NOMOUNT_BASE_VERSION = 23`；KPM 使用协议 23，配套 ZIP 兼容 22/23，保留 v22 的线格式与连接契约。
- 内核实现：[`kernel/src/nomount.c`](https://github.com/maxsteeel/nomount/blob/00e7c5d4fdbf1e58decea3522b8eb7207a46d413/kernel/src/nomount.c) 与 [`kernel/src/nomount.h`](https://github.com/maxsteeel/nomount/blob/00e7c5d4fdbf1e58decea3522b8eb7207a46d413/kernel/src/nomount.h)。
- 用户态工具和元模块使用同一冻结提交，控制协议与 KPM 一起核对。KPM业务实现单独维护，管理索引保留独立规则及进程上下文退役；inode持有独立path和目录节点。小对象优先原生slab分配，目录缓存按绑定及属性核对。

上游 README 声明 `kernel/` 为 GPL-2，其余部分为 GPL-3；根目录保留上游 LICENSE。移植文件保留来源与适用许可证。

KPM 的内核实现整体沿用 GPL-2.0-only；线协议取自 GPL-2 的 `kernel/src/nomount.h`。公共辅助代码中 GPL-2.0-or-later 的部分在本 KPM 中按 GPL-2 使用。许可证全文见 [上游内核许可证](upstream/nomount/kernel/LICENSE)。

配套 ZIP 的用户态工具、脚本与 WebUI 沿用 GPL-3.0-only，包内附完整许可证、适配后的用户态源码、补丁及编译脚本。KPM 与 ZIP 分开构建，通过 keyring 系统调用通信；GPL-3 用户态实现不链接进 KPM。

原作者：maxsteeel。KPM 移植与配套改造：Codex（OpenAI，AI 开发贡献）。上游其他贡献者的署名保留；配套修改范围和日期见 [来源说明](module/NOTICE.md)。

Git 子模块位于 `nomount/upstream/nomount`，由父仓库 gitlink 冻结上述提交。

## 当前差异清单

实现状态核对日期：2026-11-19（Developer）。差异按待处理、已处理、有意保留分类；已处理项另注明候选、复核和验收状态，独立结论引用对应角色的记录。

下文的角色报告路径标识本地证据，不随 `main` 发布；复核时从本地 `dev` 分支或维护者提供的归档取得。实现范围、验证阶段与已知边界直接列在本清单中。

### 比较基线

- **2026-11-19：v2.3.1 评估**。本地对照为 `dev` 的 `9786fc731f711d3dd96900ecdcd84396926589db`；起点评估的 ZIP 为 `v2.3.0-20261116`、KPM 为 `2.3.0-20261114`。[上游 v2.3.1](https://github.com/maxsteeel/nomount/releases/tag/v2.3.1) 指向 `dcd77d03e9912f397a586d7da81694d1628f170e`，[相对上一版冻结提交的差分](https://github.com/maxsteeel/nomount/compare/00e7c5d4fdbf1e58decea3522b8eb7207a46d413...dcd77d03e9912f397a586d7da81694d1628f170e) 为 48 个提交、15 个文件（+882／−510）。发布页以较早的 v2.3.0-720 为对照；统一扫描、白化归属、路径引用及主题取色已有落地，不重复计入本轮收益。

- 2026-11-16 配套 CLI/WebUI 的冻结上游：`00e7c5d4fdbf1e58decea3522b8eb7207a46d413`；相对 `611f2420abfd49c716e7e1ca685a7b6143eb2cae` 新增 9 个用户态／脚本提交，内核与协议无差分。配套 ZIP 更新为 `v2.3.0-20261116`；KPM 保持 `2.3.0-20261114`。逐提交评估（本地 `Developer/reports/2026-11-16-nomount-dev-assessment.md`）与实现记录（本地 `Developer/reports/2026-11-16-nomount-dev-implementation.md`）。
- 性能结果采用源码：`c69e4cbeb8ccd86dd44b9a196edc86d3692e2677`；保留异步退役，物化与查找恢复基线。单项候选身份与自检（本地 `Developer/reports/responses/2026-11-15-nomount-async-selected.md`），差分审计与点测采纳（本地 `Developer/reports/2026-11-15-nomount-async-confirmation.md`）。
- DEV-108／DEV-109 联合候选源码：`f9965b9e20be04f8831cde7a5738de0bf62f06b9`；包含 DEV-107 修复。KPM 与 ZIP 版本标记保持，实例身份见联合回执（本地 `Developer/reports/responses/2026-11-15-nomount-dev108-109.md`）。
- KPM 虚拟 backing／枚举续读源码：`834c7b813681abcfc67601b5bfce8fe128705ec6`；DEV-107 空虚拟目录回收候选源码：`89003bee2149e4d4562ee527f2979d21bbb69ed5`。
- 模块 CLI 初版源码：`ed32e6425767ba2a6068efce4eca58d0924800f9`；DEV-106 修复源码：`03ada11138df5bf84f7ad691e622b586f50490f6`；配套 ZIP 版本 `2.3.0-20261115`，KPM 版本仍为 `2.3.0-20261114`。
- 迁移前查询记录：master 为 `7914458ca71dfa3a8c162fa97fdb69332db7a690`，相对旧冻结提交 `ab93ee32a589ccb021257b3c1f280e058520d844` 仅修正上游 `update.json` 下载 URL；dev 为上述 `611f2420…`。以上为迁移前查询快照。

### v2.3.1 对照

| 范围 | 相对冻结提交新增的差异 | 可行性与必要性 |
| --- | --- | --- |
| ZIP：CLI 列表与 WebUI | `nm module list --json` 从返回模块、链接与规则明细，改为仅返回带 `fileCount`／`hasInjectable` 的 `mods`；归属计数移入 CLI。WebUI 同步调整列表、首页状态缓存、应用列表和渲染。 | **已适配配套 ZIP**，保留列表格式与 WebUI 归属计数；上游性能数据不作为本地收益。 |
| ZIP：解析与扫描 | UID／参数校验、路径归一化与保留 backing 末尾斜杠语义；列表为空时减少扫描。加载时新增白化子树剪枝，撤销仍下钻；xattr 查询失败一律视为没有 opaque 标记。 | **采用输入校验**；保留本地目录标记顺序（非空 `.replace`／opaque 优先于 `.remove`）、load／unload 对称和 DEL 去重。区分缺少 xattr 与权限／I/O 错误，保留成功规则和失败汇总。 |
| KPM：VFS 生命周期 | 上游 LKM 改在 `put_super` 恢复操作表，处理恢复期间的回调，延迟释放代理 xattr 表；虚拟对象拒绝文件句柄编码，原生对象继续走原回调。 | **仅记录，不移植。** NoMount KPM 禁止运行时卸载，驻留到重启；KernelPatch 未提供可依赖的卸载拦截。上游 LKM 的卸载与回调恢复流程不纳入本轮。 |
| KPM：路径及属性正确性 | 规则路径、flag／UID 校验，目录项按实际类型输出，open／write 后刷新代理 inode 尺寸，失效 backing 子项重验证；另有虚拟对象的 rename／hardlink 防护、异步直接 I/O 拒绝及 mmap 标志更新。 | **仅作差异记录。** 本地已有虚拟对象修改防护、异步 I/O 拒绝与 mmap 按位更新；保留固定 backing 身份、旧 FD 和本地错误码。 |
| KPM：协议与性能 | 控制协议仍为 23，线格式未改；上游规则分页改用桶内游标，扩大叶节点哈希和 UID Bloom，并复用路径哈希、自动父规则及目录叶节点。 | **不需同步升级 KPM**。CLI 从 0 开始并原样回传内核回复的游标；保留本地分页与显式规则可见性，ZIP 回归覆盖 22／23。性能改动无本地负载证据，暂缓。 |
| 启动、构建与发布 | 上游改启动文件锁、孤儿锁及 UID 失败日志，更新 LKM 启动脚本及构建流程、Kconfig、构建选项、版本与更新源。 | **不随 ZIP 迁入**。继续用现有 KPM 启动和回执方式；Android 17 CLI 发布工具链按 DEV-117 单独处理。 |

**迁移前复现**：用旧版 `build_zip.py` 分别处理冻结提交和 v2.3.1 的原始输入。冻结输入的三项生成转换均通过；v2.3.1 的 `cli-module.patch` 有 8／11 个补丁块失败。`nm.c` 与 WebUI 的文本替换仍能执行，但生成版 `readModules()` 还读取 `data.rules`。用两版各自的空列表格式运行该函数：冻结版正常，v2.3.1 抛出 `TypeError: data.rules is not iterable`。这两项为形成候选前的宿主差分证据。

### 已处理

- **v2.3.1 配套 ZIP（Developer 更新）**：冻结用户态及 WebUI 输入至 v2.3.1，ZIP 版本为 `v2.3.1-20261119`；KPM 保持 `2.3.0-20261114`。采用路径与参数校验、首页和模块列表复用、应用列表缓存等上游变更；保留原列表 JSON 和本地标记、批次及协议契约。CLI 与 WebUI 适配绑定到同一冻结输入。Zig/musl 候选已通过 CLI 回归和实际 ZIP 的浏览器自检；实例、哈希及验证边界见开发记录（本地 `Developer/reports/responses/2026-11-19-nomount-v231-zip.md`）。独立审计与设备验证待对应角色执行。

- **dev 用户态增量（独立复核／实测完成，DEV-111 维护者已关闭）**：采用上游公共扫描／批次、单次模块元数据收集与每模块 `links`／`hasInjectable`；新列表向 WebUI 提供白化归属。同步上游所有模块路径的 shell 引用和 Material You 种子色检测。保留本地标记选择、DEL 去重／UID 范围、协议入口探测及成功规则保留；删除旧遍历器适配。源码 `b8868ef50aed42c9d82c5866ab028295a7964c54` 的 ZIP `nomount-zip-2.3.0-20261116+g45cbbcc2c8ae.zig0.17.1#2` 已完成独立审计（本地 `Auditor/proposals/2026-11-15-nomount-zip-20261116/report.md`）与真机聚焦验证（本地 `Tester/reports/2026-11-15-nomount-zip-20261116-device.md`）：纯白化模块显示已激活、计数为 1，混合模块计数为 3，DEV-106～109 回归通过。维护者已登记该 ZIP 为 `device-tested` 并关闭 DEV-111。实现与完整身份见本轮记录（本地 `Developer/reports/2026-11-16-nomount-dev-implementation.md`）。

- **主题与特殊字符补测（Tester 已完成，维护者已登记）**：上述 ZIP 在 XQ-DQ72／5.15.189 上完成浅色／深色主题取色采样，以及含空格、单引号模块 ID 的列表、标记落点与加载／撤销验证；结果见补测回执（本地 `Tester/reports/2026-11-15-nomount-zip-theme-shell-device.md`）。主动更换壁纸种子色未执行；4.4／6.12 内核与 fastboot 路径仍未覆盖。

- **DEV-110 点测报告更正（维护者已关闭）**：Tester 在 `aec70aba5ca147be890e069500eef1de278747c2` 追加报告 §九（本地 `Tester/reports/2026-11-15-nomount-add-del-point.md#九更正dev-110`），Developer 对照执行器与原始 CSV 独立确认，维护者登记关闭。三项口径更正与补充 p99 已完成，计数、延迟和 P4 记录保留；关闭回执（本地 `Developer/reports/2026-11-15-nomount-async-confirmation.md#后续状态dev-110-已关闭`）绑定更正后的报告身份。

- **异步退役（差分审计／点测完成，dynamic 已验收）**：`c69e4cb` 只保留 `nm_topology.c` 的原生 async 提交、RCU 等待与进程上下文释放。单项候选在 XQ-DQ72／5.15.189 的 A/B/A 点测中，DEL 返回延迟 p50 下降约 63%～92%，P4 删除可见性 100/100、旧 FD／重加通过；原 ADD p50 退步在本次点测未复现。维护者已登记 dynamic 验收，static 模板验收仍由维护者处理。原序列归因和尾延迟边界见结果采纳（本地 `Developer/reports/2026-11-15-nomount-async-confirmation.md`），不外推到其它内核。

- **DEV-108／DEV-109（独立复核／实测完成，维护者已关闭）**：CLI 将本地三阶段扫描改为父先子后的单次遍历，进入目录先决定标记，再处理子项；修复组合标记导致的 ENOTDIR。KPM 按规则记录自动父来源，允许显式规则升级自动骨架时接收新的 UID 排除集合，修复 EEXIST；其他显式规则冲突仍保留。真实 CLI 批次与生产拓扑联测、DEV-106／DEV-107 和 TST-004 自检通过。实现、候选身份与验证边界（本地 `Developer/reports/responses/2026-11-15-nomount-dev108-109.md`）。
- **DEV-107 空虚拟父目录回收（独立复核／实测完成，维护者已关闭）**：上游在最后一个子项删除后修剪规则全为虚拟目录的空父链；本地原先只修剪 automatic 且单规则父节点，导致已降级的显式目录残留。现已对齐上游条件，继续采用本地预先准备边界数组、统一发布和 RCU 退役机制。有子项或非虚拟规则的父节点保留；CLI 与协议不变。实现与候选身份（本地 `Developer/reports/responses/2026-11-15-nomount-dev107.md`）。
- **虚拟 backing 入口防护**：对应上游 [0548f9e](https://github.com/maxsteeel/nomount/commit/0548f9e0647283b141192df31a96f3d459e7bdc1)，[nm_alloc_rule](nm_rules.c) 按实际解析出的 inode 私有操作表身份拒绝 NoMount 虚拟来源；原生来源保持可用。
- **并发枚举位置恢复**：[nm_directory_nodes.c](nm_directory_nodes.c) 的 64 位 cookie 已加入 hash 片段恢复，compat 保留原编码与溢出检查。碰撞、零片段及锚点删除仍为尽力恢复，具体契约见 [开发约定](AGENTS.md#虚拟-backing-与枚举续读2026-11-15)。
- **模块管理迁入 CLI**：启动与 WebUI 共用 `nm module load/unload/list`，移除 shell 规则扫描流水线；采用静态 musl 构建，保留现有 NDK 构建入口。已接入扫描／批次失败传播、目录链接、白化／opaque 和模块列表处理，继续支持协议 22/23 与 UID 排除；加载顺序及自动父范围冲突已由上述 DEV-108／DEV-109 候选处理。用法与实现边界见 [开发约定](AGENTS.md#模块-cli2026-11-15)。
- 已同步 2.3.0 WebUI／CLI、名称文本构造、模块识别与缓存、规则日志入口；配套实现 22/23 探测。
- 已处理虚拟对象 mutation 防护、kernfs／伪文件系统边界、排除 UID 的 opaque backing 枚举及 `d_path` 当前路径显示；tmpfs 新 inode 边界独立修复。
- SUID／SGID 清除、非空 opaque 和 WebUI 失败传播已回移；本地已有范围边界检查、跨 superblock 查询、xattr 原生安全链和 RCU 退役机制。

根据维护者登记的审计与设备结论，DEV-104／DEV-105／DEV-106 已关闭。DEV-106 修复让模块卸载只发送加载会生成的路径，并按最终虚拟路径去重；真实删除错误继续上报。该 ZIP 已完成审计与 XQ-DQ72／5.15.189 复测。复测同时发现 DEV-107：退出码为 0，但含子文件的 opaque 目录卸载后残留虚拟目录；该项后续随 DEV-108／DEV-109 联合候选完成独立复核与同用例实测，维护者已关闭 DEV-107／DEV-108／DEV-109，并对基线 dynamic／static 模板登记相应范围的验收。

结论来源：DEV-104／DEV-105 审计检查点 `ee09c6b9f8a16a4d3f090642409bbbccca5ae564`、Tester 检查点 `4bf9380403ffc332d65ac9ce2f9b1e64536d2959`；DEV-106 的 审计报告（本地 `Auditor/proposals/2026-11-15-nomount-dev106-fix/report.md`）、实测报告（含判据 2 更正）（本地 `Tester/reports/2026-11-15-nomount-dev106-fix-device.md`），DEV-107／DEV-108／DEV-109 的 联合审计（本地 `Auditor/proposals/2026-11-15-nomount-dev107-109/report.md`）、实测（本地 `Tester/reports/2026-11-15-nomount-dev107-109-device.md`），以及 `metadata/modules/nomount.json` 的维护者关闭／验收登记。

### 待处理

2026-11-16 选定的上游增量已完成。DEV-111 与 ZIP dev 迁移的状态见上文；既有候选身份及交接见开发回执（本地 `Developer/reports/responses/2026-11-15-nomount-documentation-closeout.md`）。

**后续验证**：ZIP 候选按冻结提交、构建实例和产物身份交独立审计及目标实测；继续在本清单记录复核结果。

- **DEV-117 发布 CLI**：维护者已确认 NDK 发布件在 Android 17 因 Bionic TLS 对齐无法执行；官方发布改用既有 Zig/musl 内层字节。Developer 已实现安装可执行探测与分层报错，并提供 Zig 出件／发布门禁补丁；CI 采纳、发布资产核对及 Android 17 候选实测待对应角色完成。

- **WebUI 手动规则转储**：上游按钮从 common.sh 调用 `dump_all_rules_logcat`，本地只提供 `nm_dump_rules`，该入口尚待适配。开机 metamount 已直接调用本地函数；本轮 ZIP 收录清理不改运行脚本或 WebUI，手动入口需另行修复、复核与实测。

当前 KPM 的 static 模板验收及最终交付手续归维护者；dynamic 已验收，实机覆盖限 XQ-DQ72／5.15.189，4.4／6.12 未被本轮测试覆盖。

原联合实验的收益、代价与选择过程保留在采纳记录（本地 `Developer/reports/2026-11-15-nomount-perf-decision.md`）；新候选的差分确认（本地 `Developer/reports/2026-11-15-nomount-async-confirmation.md`）区分本次 ADD 未复现、原序列归因未定及 p99 尾部差异。读路径绝对耗时受原生对照漂移影响，未据此宣布提速。

### 有意保留的差异

- **启动锁与回执**：上游新增 flock→mkdir 锁及孤儿锁清理；本地 KPM 配套没有 flock／LKM 装载锁，保留当前启动与开机回执流程，不引入对应清锁机制。信号处理不扩大为清空成功规则。
- **固定 backing 身份**：删除或同名重建不自动换源，须删除规则再添加；上游会重新绑定。现有 FD 和 inode 保持原对象。
- **虚拟对象修改保护**：本地在公共 security_inode 前置入口拒绝相关 unlink、rmdir、link、rename；不以删除虚拟文件隐式删除规则，原生对象照常处理。
- **文件系统支持边界**：kernfs 和 debugfs／tracefs／bpffs／securityfs 拒绝建立代理；tmpfs 拒绝新建虚拟 inode，保留原生目录内直接 WHITEOUT。扩展支持须先完成对应生命周期适配。
- **配套协议与失败范围**：ZIP 接受已核对的 22/23；默认规则 UID 排除、成功规则保留及错误汇总继续沿用本地契约。普通运行日志仍写 `nomount.log`，规则转储另外接 logcat。
- **删除不存在的规则**：上游 DEL 对不存在的路径或 UID 范围返回 0；本地返回 `ENOENT`，供调用者区分匹配删除与未匹配。DEV-106 的 CLI 去重按此契约适配，DEV-107 保持该返回值。
- **虚拟来源错误码**：拒绝已有 NoMount 虚拟 inode 作为 backing 时，本地返回 `ELOOP` 表示递归来源，上游返回 `EINVAL`；拒绝范围均按虚拟 inode 身份判断。
- **规则范围扩展**：本地允许默认规则携带 UID 排除，显式规则相同 UID 范围但排除集合不同时返回 `EEXIST`；上游默认范围排除校验不同、同范围采用替换。自动父规则按来源标记允许升级，显式规则继续按此契约判断冲突。
- **模块目录标记顺序**：上游已采用目录入口检查，但先选 `.remove`，且目录白化后仍下钻；本地保留 DEV-108 已验收的优先级与子树选择。非空 `.replace`／opaque 优先于同目录 `.remove`；空 `.replace`／opaque 或单独 `.remove` 白化整个子树。load/unload 采用同一选择，避免依赖 readdir 顺序。
- **普通文件与 backing FD**：三项联合实验未建立 inode 缓存的独立收益，已恢复基线 `new_inode()`；目录已有缓存保留。各次 backing FD 独立打开，保持凭据、seek／ioctl 文件状态；不采用上游共享 FD。以后有针对性负载证据再评估，不维持必做迁移待办。
- **查找结构**：撤回实验 child_hint，保留基线 hash／Bloom／二分查找；本次未建立提示的独立收益，B3 无关前缀未命中也不经过该提示。不直接采用上游 inode 持有 leaf 或新版 buckets。
- **异步接入方式**：通过原生 async API 提交退役链，不复制配置相关的 work_struct 布局；不可用时沿用同步回收。生命周期与语义继续按本地模型维护。
- **KPM 架构**：静态／动态偏移与驻留生命周期独立维护。禁止运行时卸载是操作约束，不是内核中的拦截开关；更新或停用 KPM 通过重启生效。上游 LKM 装载、运行时卸载及操作表恢复流程只登记差异。

### 如何维护

本节是差异状态的唯一清单。发现移植实现与上游不一致时即登记，不只记录准备移植的功能；每项归入「待处理」「已处理」或「有意保留」。待处理写明影响与下一步；已处理注明实现提交与验证阶段，候选完成不等于问题关闭；有意保留说明取舍依据与适用边界。每次评估上游、移动 gitlink 或处理差异时同步更新，Developer 提供实现事实，维护者维护验收状态，独立结论引用对应角色记录。行为细节保留在模块开发约定中。分支前进后重新比较，不将本次快照称为最新状态。

## KPM 移植与配套适配

- 2026-10-22：参照上游 `6564660d0d8b4e636676649573d63115ddcf3958` 和
  `e240bb031820fd3f7de5dadb007281b33bb70634`，修正 dentry 操作表与标志的发布顺序。
  KPM 保留自身完整操作表快照及驻留生命周期。
- 同步 v22 的 UID 范围、排除范围和 opaque 目录语义；规则仍使用本仓库的独立引用与进程上下文退役模型。
- ZIP 中的 CLI 生成副本增加 v22 协议探测，并修正上游默认规则单独使用 `--uid-excluded` 时的范围检查。
  冻结子模块不修改，实际构建的适配后源码与编译脚本随 ZIP 提供。
- 2026-11-08：选择性回移 `95cf3d013d4dfd888708df124c8a25aaf7ac2ebc` 的虚拟 inode
  SUID/SGID 清除语义，统一新建、属性返回、setattr 同步及缓存匹配。
  配套生成副本回移 `71883de7ab2e2468bbbaf78ef64ac44a33069531` 的非空 opaque 目录处理，
  及 `43ddd47b9dabf30b5f8249f6d08a1cd95dcbd297` 的 WebUI 操作失败传播，并检查 find 管道失败。
  当时上游 gitlink 冻结在 v2.2.0 基线，默认规则的 UID 排除行为保持。

- 2026-11-12：配套启动按上游的非事务规则语义保留成功项，普通添加／扫描错误汇总返回，
  诊断列表失败不清空规则；UID 恢复仍先于发布。KPM 在实际拓扑发布边界准备 xattr 接入，
  仅直接原生父目录内、不新增虚拟父链的纯白化跳过无关接入。上游 gitlink 与 v22 线协议不变。

- 2026-11-14：冻结 gitlink 升至 v2.3.0-720。ZIP 采用新版 CLI、WebUI、路径解析；
  删除已由上游包含的非空 opaque 文本补丁，支持 v22/v23 探测，保留默认规则 UID 排除与失败状态传播。
  KPM 接入虚拟对象 mutation 安全检查、kernfs 目标拒绝和 blocked UID 的 opaque FD 回源。
  mutation 使用公共 security_inode 前置入口，覆盖跨父目录 hardlink、RENAME_EXCHANGE 和虚拟目标父目录；
  仅修改原生父目录 i_op 的上游方案不能覆盖全部路径。普通原生操作保留。
  规则列表通过 `d_path` 显示已绑定 backing 对象的当前路径；重命名后随对象更新，删除后保留原对象及原生 ` (deleted)` 注记。
  同名重建不自动换源，须删除对应规则后重新添加。该轮尚未采用 backing 自动重绑定、普通文件与 backing FD 缓存、hash cookie 恢复和异步回收。
  TST-004 修复在发布与物化层拒绝 tmpfs 目标的新建虚拟 inode，保留原生目录下的直接 WHITEOUT。

- 2026-11-15：按差异清单完成虚拟 backing 入口防护、64 位枚举续读恢复及配套模块 CLI 迁移，候选状态见上文。配套 gitlink 升至 `611f2420abfd49c716e7e1ca685a7b6143eb2cae`；ZIP 独立更新至 `2.3.0-20261115`，KPM 版本与协议保持。

- 2026-11-16：配套 gitlink 升至 `00e7c5d4fdbf1e58decea3522b8eb7207a46d413`，ZIP 更新为 `2.3.0-20261116`；统一扫描和列表格式、白化归属、路径引用与主题检测已迁移，本地合同差异见清单。KPM 源码与版本保持。
