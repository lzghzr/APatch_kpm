# NoMount 配套元模块工程约定

本目录由 Developer 维护，遵循上级 AGENTS.md。README 仅保留安装动作、可见状态和必要署名；脚本行为变更需要独立审计及实机覆盖，文档核对属于 Tier-3。

## 机制与链接顺序

- `module.prop` 的内部 ID 为 `nomount`、`metamodule=true`。KPM 提供内核接口，ZIP 的 metamount 才发布普通模块文件规则；只加载 KPM 不会发布规则。
- 先使 KPM 可连接并重启，再安装 ZIP。`customize.sh` 通过包内 `nm version` 与 `nm uid block_isolated` 查询接口，版本回复首项须精确为线协议号22或23，失败即中止；不以 KPM 发布版本或 uname 选择兼容分支。
- 升级顺序为先覆盖支持22/23的ZIP，再安装KPM23并重启；回退时先回KPM22，再按需回旧ZIP。WebUI复用common.sh只读API检查显示连接状态，写命令仍由CLI每次探测。
- 安装确认接口后创建 `/data/adb/ap/bin/nm -> /data/adb/modules/nomount/bin/nm`；APatch 安装器完成 metamodule 链接。顺序是 KPM 注册 → ZIP 接口检查及 CLI 链接 → 开机 metamount → 普通 post-fs-data → boot-completed 回执。
- metamount 先清理旧规则、恢复 UID/isolated 配置，再遍历普通模块；跳过 `disable/remove/skip_mount`，保留分区映射、`.replace`、opaque 与 NUL 分隔路径契约，准备失败停止发布；普通扫描或添加失败保留成功规则、继续处理并汇总返回非零。诊断列表失败只记录警告。
- `.booting` 记录 boot_id，boot-completed 后删除；部分规则发布成功但返回非零时也保留标记。上次回执未完成时暂停注入，不据此判定崩溃归因。安全模式在下次开机生效。
- 更新可覆盖安装 ZIP，内部 ID 保持不变；停用配套后重启停止自动发布。卸载清当前规则、配套数据和属于本模块的 CLI 链接，KPM 仍遵守驻留到重启的生命周期。

## 排查（供需要查看日志的人）

- 控制接口：`nm version` 返回线协议号及 KPM 发布版本；版本查询和隔离 UID 状态查询都须成功。
- 设置页的 Dump rules 开关启用开机 logcat 规则列表；metamount 调用 common.sh 的 `nm_dump_rules`，查询或 logcat 失败不改变规则。
- 规则发布日志为 `/data/adb/nomount/nomount.log`；检查 `[OK] 文件加载完成`、接口可用与开机完成回执，确认无 `[ERROR]`。规则列表可以为空，不把非空作为通用成功条件。
- 安装方式另查 `kpm info NoMount` 的 `load_source=file`、`load_event=post-fs-data`，以及 `/data/adb/ap/kpm/nomount/nomount.kpm` 对应目录加载 `rc=0`；事件为 `post-fs-data` / `before`。
- CLI 链接目标缺失、KPM 接口未就绪、规则发布失败分别定位；APatch 显示已加载不等于普通模块文件已发布。完整身份与本轮实机范围引用上级工程约定及 Developer 报告。

## 打包与发布

- 本地文件按 `build_zip.py` 的 `MODULE_PACKAGE_FILES` 显式收录；上游 `webroot/`、用户态源码和安装入口从冻结提交展开，另加入构建脚本、补丁、CLI 与所用运行库许可证。打包前及解包后都核对完整白名单，缺项、多项或重复项即失败。`README.md`、`NOTICE.md` 随包提供；`CHANGELOG.md` 只作版本校验输入，`AGENTS.md` 留在仓库。

- 上游 nm、WebUI、metainstall、路径处理与许可证取自冻结 gitlink；包中保留 `sources/`、许可证和署名，KPM 与 ZIP 分别绑定完整 source_commit、instance_id 和 SHA-256。
- `build_zip.py` 从干净冻结提交构建 ZIP，使用指定的 Zig 静态 musl 工具链，并保留 NDK 静态 libc 构建入口；实际工具字节与参数由清单捕获。输出 `NoMount-kpm_<版本>.zip`，归档仍放每次新实例目录，版本由 module.prop、Build ID 和清单表达。
- `release_zip.py` 的 `PACKAGE` 从 module.prop 的版本生成 `NoMount-kpm_<版本>.zip`，发布副本清单在实际 ZIP 名后追加 `.json`，更新入口仍为 `NoMount-kpm.json`；下载 URL 绑定发布标签与实际文件名，用户 README 使用 `NoMount-kpm.zip` 简写。
- `CHANGELOG.md` 的第一条必须为 `module.prop` 声明的当前 ZIP 版本；开发期间仅维护这一条待发布记录，未发布改动合并其中。历史条目只保留已发布版本，并以发布 tag 中的原文为准，不改名或改写；开发流水留在 `Developer/reports/`，不随 ZIP 发布。打包器继续在冻结构建输入上核对首条版本；发布更新 JSON 的 changelog 指向该发布 tag 中的仓库文件。
- prepare / merge / publish_update 在新目录处理发布副本，保持旧归档及 MANIFEST 不可覆盖；KPM/ZIP 来源提交、版本、哈希与参数一致性判据沿用既有契约。
- 构建与发布继续使用带版本号的包名，用户简写与实际资产命名分开；已有 release 资产及登记身份保持原样。
