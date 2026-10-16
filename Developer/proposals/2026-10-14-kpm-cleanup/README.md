# KPM 构建与命名配套更新

NoMount 0.5.2 使用 `NoMount` 注册名与文件前缀，用户态 keyring 类型和 ZIP 内部 ID 保持 `nomount`。NoMount、zram_zstd、run_cmd_demo 的 `all` 均生成动态、静态两件；rek/rekx 保留实际调试用途的 debug 目标。新模块默认只提供普通件。

## 已落地的工具机制适配

[identity-mechanism.patch](identity-mechanism.patch) 支持目录 ID 与产物前缀仅大小写不同的文件发现；版本和扩展名仍精确匹配。原有自检断言保持原样，追加六个正反例。现行工具自检 33/33 通过。

依据 [角色规则](../../../docs/process/02-roles.md) 的“共享工具机制适配（标准授权）”直接实现，须由维护者同轮逐字节复核采纳或回退。

## 维护者配套补丁

[maintainer-policy.patch](maintainer-policy.patch) 调整现行模块目录 ID 与 KPM 展示名的大小写关系；历史归档仍核对冻结源码的精确注册名。产物文件名必须与内嵌名精确一致，大小写冲突注册名被拒。

CI 对双模式模块运行 `all`，有 debug 目标的模块再运行 `debug`；加入 NoMount 的静态 JSON 收集。根 AGENTS 与开发技能记下新模块的默认构建约定。

[version.patch](version.patch) 仅将 NoMount 的两个当前版本声明更新为 0.5.2，保留历史构建记录。候选由交接清单导入。

副本验证保留原有 33 组工具自检；另覆盖 NoMount 大小写匹配、错误注册名、错误版本、错误模块集合、大小写冲突、文件前缀不符，以及普通构建、实际 debug、debug 失败退出。证据见 [验证摘要](policy-checks.json)，运行 `python3 Developer/proposals/2026-10-14-kpm-cleanup/verify_policy.py` 可在临时副本重现。这是 Developer 自检，配套判据、CI 与规则补丁待维护者采纳，尚未在仓库门禁生效。
