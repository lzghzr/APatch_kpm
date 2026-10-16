# NoMount ZIP CI 工具链初始化修复

角色：维护者。问题编号 MNT-020；失败提交 `003b45028995952264359db49efb245273cd07da`。

[GitHub 作业日志](https://github.com/lzghzr/APatch_kpm/actions/runs/38855517713/job/116825967619)显示，`Install ZIP toolchain` 调用 `sdkmanager` 时命令不存在，退出127。作业尚未执行ZIP检查和构建，没有本次ZIP构建实例或产物哈希。该次push运行的KPM编译、产物门禁和上传作业成功，发布作业跳过；失败证据不扩大为模块编译或设备结论。

工作流增加 `actions/setup-java@v6`，显式选择Temurin Java 17，再使用 `android-actions/setup-android@v4` 安装 `ndk;26.3.11579264`。保持原NDK版本、ZIP构建命令和后续发布检查。直接核对[SDK action说明](https://github.com/android-actions/setup-android/tree/v4)与其 `src/main.ts`：它初始化命令行工具、配置PATH，并导出ANDROID_HOME和ANDROID_SDK_ROOT，供现有构建步骤使用。

本地检查：YAML可解析，Java→SDK/NDK→ZIP顺序与NDK版本一致；原ZIP发布测试7/7、更新入口测试3/3通过，测试断言未修改。宿主检查没有执行GitHub action、下载Linux NDK或完成Linux ZIP构建，不能当作远端修复通过。失败运行的原日志和发布事实保持，远端新运行结果待核对。

该修复另作未签名检查点，不重写已经发布的三笔签名提交；签名需用户再次确认，推送与CI触发仍由用户操作。MNT-020保留待远端验证与独立确认。
