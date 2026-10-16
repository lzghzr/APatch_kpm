# NoMount-kpm

NoMount 的配套元模块，负责开机加载普通模块中的系统应用和文件，并提供 WebUI。

## 安装

1. 在 APatch 中嵌入适合设备的 NoMount KPM，参数留空，加载时机用默认设置，然后重启。
2. 在支持元模块的 APatch 中安装 `NoMount-kpm_<版本>.zip`。
3. 安装需要的普通 ZIP 模块，再重启。

提示“无法连接 NoMount”时，先确认 KPM 已嵌入，并且已经重启。当前支持 arm64。

## 使用与更新

WebUI 可以查看加载状态、管理文件规则，以及选择不使用注入文件的应用。安全模式在下次开机生效。

更新配套模块时，可以在管理器中检查更新，也可以直接安装新版 ZIP。更新 KPM 时，替换嵌入的模块后重启。模块内部 ID 保持 `nomount`，已有安装可以覆盖更新。

停用配套模块后重启，会停止自动加载文件；卸载会清空当前规则和配套设置。移除 KPM 时先取消嵌入，再重启，请勿直接卸载已加载的 KPM。

用户态工具和 WebUI 来自 [maxsteeel/nomount](https://github.com/maxsteeel/nomount)，遵循包内 GPL-3 许可证。原作者为 maxsteeel，KPM 移植和配套改造由 Codex（OpenAI）完成，详细来源见 [NOTICE.md](NOTICE.md)。
