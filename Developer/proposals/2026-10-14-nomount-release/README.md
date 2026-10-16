# NoMount 发布登记

本轮将版本统一为上游 2.1.1 加日期后缀：`2.1.1-20261014`，配套 ZIP 文件使用 `NoMount-kpm_<版本>.zip`，显示名称为 `NoMount-kpm`。内部 ID 和控制协议保持 `nomount`。

[version.patch](version.patch) 仅更新两个当前版本声明。历史构建、审计、测试和验收保持原样；新候选身份由新交接清单导入，旧结论通过独立的版本差异复核绑定。

用户本轮明确要求自动发布增加任务，因此工作流已准备独立 ZIP 构建任务和统一发布任务。编译任务只读仓库；发布任务依赖两类编译成功，核对下载哈希、完整源码提交及 NoMount 版本，最后合并发布清单。新增 ZIP 单件下载与完整身份包，KPM 的既有筛选判据及断言保持原样。此处准备本地配置，实际发布和签名交付由维护者执行。

源码、版本差异、自检和候选身份见本轮 [发布准备报告](../../reports/2026-10-14-nomount-release-preparation.md)。

module.prop 的 updateJson 指向正式 Release 中的 NoMount-kpm.json。更新 JSON 和说明在发布任务里从实际 ZIP 生成，zipUrl 绑定该次发布标签和版本化文件名；遵循 [KernelSU 模块指南](https://kernelsu.org/zh_CN/guide/module.html) 与 [Magisk 更新 JSON 格式](https://topjohnwu.github.io/Magisk/guides.html)。新建 Release 先以草稿上传齐全再公开；上传错误必须使任务失败，签名／实际发布仍由维护者安排。

更新入口的发布语义采用每轮新标签、已公开发布不覆盖。原工作流的 allowUpdates/replacesArtifacts 无法保证更新 JSON 与 ZIP 上传失败时一致，本轮改为 allowUpdates=false；此项配套规则需维护者随发布配置复核。
