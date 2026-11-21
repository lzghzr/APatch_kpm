# 来源、署名与许可证

本 ZIP 基于原作者 **maxsteeel** 的 NoMount 提交 `dcd77d03e9912f397a586d7da81694d1628f170e` 修改，使用其 GPL-3 用户态工具、元模块路径处理及 WebUI；修改日期最早为 2026-10-13，最近为 2026-11-19。

**Codex（OpenAI）**完成 KPM 移植及配套 ZIP 改造；这里记录 AI 开发贡献。原作者及其他贡献者的署名保留，未将此署名作为新增的版权归属声明。

按上游致谢保留贡献说明：WebUI 设计来自 ZQZCC，代码优化来自 backslashxx，项目受到 Kasumi 启发；感谢 KernelSU 及原项目测试者和贡献者。

本配套 ZIP 遵循 GPL-3.0-only，完整文本见 `LICENSE`。单独发布的 NoMount KPM 遵循 GPL-2.0-only，上游内核部分的许可证不因 ZIP 改造而改变。

修改范围包括安装／启动／卸载脚本、控制接口检查，以及 WebUI 与 CLI 适配。

WebUI 的 JavaScript、语言文件和运行脚本均以源码形式随包提供。适配后的用户态源码、模块扫描补丁与编译脚本位于 `sources/`。

编译命令：`ZIG="<zig路径>" sh sources/build-nm.sh ./nm`，使用 Zig 0.17.1 生成 aarch64-linux-musl 静态程序。现有 NDK 入口 `ANDROID_NDK="<NDK根目录>" sh sources/build-nm.sh ./nm` 编译同一源码，使用 Android 静态 libc。产物身份按实际工具链区分，所链接运行库的许可证随包置于 `licenses/`。

本软件按 GPL 许可证中的无担保条款提供。来源：[maxsteeel/nomount](https://github.com/maxsteeel/nomount/tree/dcd77d03e9912f397a586d7da81694d1628f170e)。
