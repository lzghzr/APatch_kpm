# hosts_redirect 实现约定

## 文件职责

- `hosts_redirect.c`：模块元信息、目标设置、打开前后钩子、ctl0 与生命周期。
- `hr_utils.h`：模块日志前缀。
- `../kpm_utils.h`：公共符号查找和 hook 宏。
- `struct filename` 使用 KP SDK 的 `linux/fs.h` 定义；`struct file` 和 `struct open_flags` 仅作指针传递。
  模块通过 SDK 定义访问文件名，构建为通用 KPM。

## 路径与权限契约

打开前钩子仅在调用者 UID 为 0、目标处于启用状态、传入文件名精确等于 `/system/etc/hosts` 时，
把 `pathname->name` 改为 `/data/adb/hosts/{name}`。其余路径原样交给 VFS，包括 `/etc/hosts`、相对路径和带 `..` 的路径。
匹配的是传入字符串，而非解析后的 inode。

`args->local.data0` 保存本次调用的原文件名指针；after 仅在该值非零时恢复。
`dfd`、打开参数、打开标志及 VFS 返回值保持原样；`O_WRONLY`/`O_RDWR`、截断、追加和创建均由原生 VFS 处理。
调用使用进程既有权限与 SELinux 状态。元数据操作、rename/unlink 各走自己的内核路径。

## 控制与生命周期

目标名为1～40字节的单个文件名；拒绝 NULL、空串、纯ASCII空白、`/`、包含`..`及单独的`.`。完整校验通过前不写`hosts_target`，拒绝时全部64字节不变，并记录原因；ctl0回复失败表情。
参数 `disable` 通过 `/data/adb/hosts/disable` 停用重定向，语义不变。
ctl0 成功/失败回复均为 8 个字符及结尾 NUL，共 9 字节；输出指针有效且 `outlen` 至少为 9 时复制完整回复。
输出缓冲区缺失或容量不足时跳过回复，目标设置照常执行，返回值保持 0；初始化沿用无输出调用。
README 的 CLI 示例通过 `stat` 获取主用户的 Manager UID，在 `/data/app` 递归匹配
`*/me.bmax.apatch-*/lib/arm64/libkpatch.so`，再以该 UID 调用控制程序。
`[ -x "$L" ]` 要求结果为单个可执行路径；空结果、多行结果或文件不可执行时停止调用。
初始化设置目标后查找 `do_filp_open` 并安装前后钩子；必需符号缺失沿用公共宏的 -21。
公共 `hook_func` 安装失败时不清指针，因此安装封装保留失败清零；退出在既有有效性检查后解除 hook 并清零。

## 验证与构建

正式候选从干净的冻结提交运行：

```sh
python3 tools/build_candidate.py hosts_redirect --toolchain ndk26.3.11579264 --target all
```

`all` 生成单一普通版。目标设置成功时输出目标路径日志，供排查使用。
自检覆盖路径匹配、UID、disable、调用参数传递、前后指针恢复、ctl0 以及初始化失败和退出。
ARM64编译使用`-mgeneral-regs-only -ffixed-x18`；新增行遵循 clang-format；枚举全部未定义符号并核对 SDK 导出。Developer 自检为 Tier-3，
独立审计和真机验证分别由 Auditor、Tester 完成。
