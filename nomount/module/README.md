# NoMount-kpm

NoMount 必装的配套 ZIP，负责加载普通模块的文件，并提供 WebUI。

1. 在 APatch 的内核模块页面「安装」或「嵌入」适合设备的 NoMount KPM，重启。
2. 安装 `NoMount-kpm.zip`，重启。

本次要用的 KPM 若已安装或嵌入并成功加载，可直接进行第 2 步。

**从旧版升级**：先覆盖安装本 ZIP（兼容控制协议 22 与 23），再更新协议 23 的 KPM 并重启。旧 ZIP 只接受 22，不能用于新 KPM。

在 APatch 中确认 NoMount 已加载，打开 NoMount 的 WebUI 查看状态和文件规则。

用户态工具和 WebUI 来自 maxsteeel/nomount（GPL-3），KPM 移植及配套改造由 Codex（OpenAI）完成，详见 [NOTICE.md](NOTICE.md)。
