# 来源、署名与许可证

原版 NoMount 作者为 **maxsteeel**。本 ZIP 使用其 GPL-3 用户态工具、元模块路径处理及 WebUI，基于提交 `7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3`。

**Codex（OpenAI）**完成 KPM 移植及配套 ZIP 改造；这里记录 AI 开发贡献。原作者及其他贡献者的署名保留，未将此署名作为新增的版权归属声明。

按上游致谢保留贡献说明：WebUI 设计来自 ZQZCC，代码优化来自 backslashxx，项目受到 Kasumi 启发；感谢 KernelSU 及原项目测试者和贡献者。

本配套 ZIP 遵循 GPL-3.0-only，完整文本见 `LICENSE`。单独发布的 NoMount KPM 遵循 GPL-2.0-only，上游内核部分的许可证不因 ZIP 改造而改变。

修改日期：2026-10-13、2026-10-14。改造范围包括安装／启动／卸载脚本、控制接口检查、UID 恢复顺序、开机回执及 WebUI 连接状态标签、空列表表情和规则路径显示。同步上游2.1.1的列表错误返回、JSON路径转义、WebUI跳过模块按钮和翻译。KPM配套WebUI的空列表表情为 `_(._.)_`。WebUI 的 JavaScript、语言文件和运行脚本均以源码形式随包提供。原版用户态源码与编译脚本在 `sources/`，可用 Android NDK 重新编译。

编译命令：`ANDROID_NDK="<NDK根目录>" sh sources/build-nm.sh ./nm`。本包使用 NDK 26.3.11579264；其他编译器版本的产物可能不同。

本软件按 GPL 许可证中的无担保条款提供。来源：[maxsteeel/nomount](https://github.com/maxsteeel/nomount/tree/7046c7ad3ee0bf4ae66e80f6b93b1e30db0cb4e3)。
