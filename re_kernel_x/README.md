# ReKernel-X

基于 [ReKernel-X](https://github.com/myflavor/ReKernel-X) 的 KernelPatch 模块移植，配合墓碑模块，在应用收到 Binder、信号或网络事件时支持解冻，并提供异步 Binder 消息清理规则。

模块管理名称为 `re_kernel_x`。

## 下载与移植
### 这一段给 AI 看就可以，你只需要知道模块无法直接使用

GitHub Releases 提供 ABI3、ABI4、ABI5、ABI6 四个基准 KPM。基准需要按目标内核移植后使用，ABI 编号表示 Binder 函数调用方式，不对应 Linux 主版本号。

1. 分析目标内核 img，确认实际 ABI 和结构体偏移。
2. 从同一 Releases 下载对应基准 KPM 和配套 `.kpm.json`；移植工具使用该次构建提交中的版本。
3. 填写目标偏移配置，生成新的 KPM：

```bash
python3 re_kernel_x/tools/patch_offsets.py patch local/baselines/re_kernel_x_1.6_abi6.kpm --offsets local/target-offsets.json --output local/target.kpm
```

替换工具只依赖 Python 标准库，用户侧无需 NDK 或 KP SDK。debug 版保留在 Actions artifacts。运行环境建议使用 KP 0.13.9；卸载与热重载的生命周期处理仍待验证。

## 更新记录
### 1.6
版本号与 [ReKernel-X 1.6](https://github.com/myflavor/ReKernel-X/releases/tag/1.6) 对齐<br />
模块改名为 `re_kernel_x`，加入作者 `myflavor`<br />
模块描述改为 `every bit belongs to you.` 看似浪漫实则没招了<br />
Genl 控制请求仅允许 UID 1000
