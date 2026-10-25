# NoMount 配套元模块工程约定

本目录由 Developer 维护，遵循上级 AGENTS.md。README 仅保留安装动作、可见状态和必要署名；脚本行为变更需要独立审计及实机覆盖，文档核对属于 Tier-3。

## 机制与链接顺序

- `module.prop` 的内部 ID 为 `nomount`、`metamodule=true`。KPM 提供内核接口，ZIP 的 metamount 才发布普通模块文件规则；只加载 KPM 不会发布规则。
- 先使 KPM 可连接并重启，再安装 ZIP。`customize.sh` 通过包内 `nm version` 与 `nm uid block_isolated` 查询接口，版本回复首项须为线协议号22，失败即中止；不以 KPM 发布版本或 uname 选择兼容分支。
- 安装确认接口后创建 `/data/adb/ap/bin/nm -> /data/adb/modules/nomount/bin/nm`；APatch 安装器完成 metamodule 链接。顺序是 KPM 注册 → ZIP 接口检查及 CLI 链接 → 开机 metamount → 普通 post-fs-data → boot-completed 回执。
- metamount 先清理旧规则、恢复 UID/isolated 配置，再遍历普通模块；跳过 `disable/remove/skip_mount`，保留分区映射、`.replace`、opaque 与 NUL 分隔路径契约，任一发布操作失败则清规则。
- `.booting` 记录 boot_id，boot-completed 后删除；上次回执未完成时暂停注入，不据此判定崩溃归因。安全模式在下次开机生效。
- 更新可覆盖安装 ZIP，内部 ID 保持不变；停用配套后重启停止自动发布。卸载清当前规则、配套数据和属于本模块的 CLI 链接，KPM 仍遵守驻留到重启的生命周期。

## 排查（供需要查看日志的人）

- 控制接口：`nm version` 返回线协议号及 KPM 发布版本；版本查询和隔离 UID 状态查询都须成功。
- 规则发布日志为 `/data/adb/nomount/nomount.log`；检查 `[OK] 文件加载完成`、接口可用与开机完成回执，确认无 `[ERROR]`。规则列表可以为空，不把非空作为通用成功条件。
- 安装方式另查 `kpm info NoMount` 的 `load_source=file`、`load_event=post-fs-data`，以及 `/data/adb/ap/kpm/nomount/nomount.kpm` 对应目录加载 `rc=0`；事件为 `post-fs-data` / `before`。
- CLI 链接目标缺失、KPM 接口未就绪、规则发布失败分别定位；APatch 显示已加载不等于普通模块文件已发布。完整身份与本轮实机范围引用上级工程约定及 Developer 报告。

## 打包与发布

- 上游 nm、WebUI、metainstall、路径处理与许可证取自冻结 gitlink；包中保留 `sources/`、许可证和署名，KPM 与 ZIP 分别绑定完整 source_commit、instance_id 和 SHA-256。
- `build_zip.py` 从干净冻结提交及固定 NDK 构建 ZIP；输出 `NoMount-kpm_<版本>.zip`，归档仍放每次新实例目录，版本由 module.prop、Build ID 和清单表达。
- `release_zip.py` 的 `PACKAGE` 从 module.prop 的版本生成 `NoMount-kpm_<版本>.zip`，发布副本清单在实际 ZIP 名后追加 `.json`，更新入口仍为 `NoMount-kpm.json`；下载 URL 绑定发布标签与实际文件名，用户 README 使用 `NoMount-kpm.zip` 简写。
- README 更新记录的第一条必须为当前发布版本；打包器直接对完整 history 执行版本一致性断言。文档说明合并到当前版本条目，ZIP 内 CHANGELOG 提取该版本内容，全部既有版本条目保留。
- prepare / merge / publish_update 在新目录处理发布副本，保持旧归档及 MANIFEST 不可覆盖；KPM/ZIP 来源提交、版本、哈希与参数一致性判据沿用既有契约。
- 构建与发布继续使用带版本号的包名，用户简写与实际资产命名分开；已有 release 资产及登记身份保持原样。
