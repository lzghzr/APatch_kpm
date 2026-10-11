> 注: 此模块全程由 agent 完成，旨在验证流程是否可行，实际使用价值不大

# run_cmd_demo

执行 Android shell 命令。模块加载一次后，可以反复提交命令，并查询执行结果。

**当前版本请通过重启设备移除或更换模块。直接卸载可能导致内核崩溃。**

## 使用

动态版 `run_cmd_demo.kpm` 在加载时获取偏移；静态基线 `run_cmd_demo_baselines.kpm` 需先按目标设备适配。两版在 APatch 中都叫 `run_cmd_demo`，选择一种加载即可。

1. 在 APatch 的内核模块页面加载 `run_cmd_demo`。
2. 打开 `run_cmd_demo` 的控制入口，输入要执行的命令，例如：

   ```sh
   id > /data/local/tmp/run_cmd_demo.out 2>&1
   ```

3. 收到 `queued` 后，输入 `result` 查询执行状态。显示 `pending` 时稍后再查；显示 `ret=...` 时，命令已经结束。
4. 在已授权 root 的终端中查看输出：

   ```sh
   cat /data/local/tmp/run_cmd_demo.out
   ```

接着提交下一条命令即可。每次只执行一条，执行中提交新命令会返回 `-EBUSY`。命令最多 4095 字节；`result` 用于查询状态。

## 结果怎么看

| 响应 | 含义 |
| --- | --- |
| `queued` | 已接收命令，等待执行 |
| `idle` | 尚未提交命令 |
| `pending` | 命令尚未完成 |
| `ret=0` | 命令正常退出 |
| `ret=256` | 命令退出码为 1，查看输出文件中的错误信息 |

`ret` 使用 Linux 原始等待状态：正常退出码乘以 256，例如 `exit 7` 返回 `ret=1792`；被信号终止时含义不同，例如 `ret=11` 表示 SIGSEGV。负数表示执行接口出错。

命令的标准输入、输出和错误默认连接到 `/dev/null`。需要查看输出时，像示例一样重定向到文件。执行没有超时，长期不退出的命令会一直占用执行位置。

## 静态移植

准备目标设备的 `boot.img`、静态基线及同一构建的 `.kpm.json`。根据目标内核填写 JSON 的 `offsets` 后，在仓库根目录运行：

```sh
python3 patch_offsets.py patch run_cmd_demo_baselines.kpm --offsets target-offsets.json --output target.kpm
```

配套布局文件放在基线旁，命名为 `run_cmd_demo_baselines.kpm.json`。生成的 `target.kpm` 按上面的步骤使用。替换工具只依赖 Python 标准库；字段含义和开发要求见 [AGENTS.md](AGENTS.md)。

## 环境要求

适配目标为 Android ARM64，内核 4.4～6.6。命令通过 `/system/bin/sh -c` 执行，使用 root 身份和 `u:r:magisk:s0` 执行域；设备需要具备这个 SELinux 域。加载失败时查看内核日志。

## 更新记录

### 1.3.0

新增静态基线，支持通过配套 JSON 替换目标偏移，用户侧无需 NDK<br />
动态版和静态版共用命令执行逻辑<br />
静态版加载时使用内核提供的 SELinux blob 起点

### 1.2.0

扩展 Android 4.4～6.6 的兼容路径，支持旧内核的命令执行线程接口<br />
优先使用 BTF 获取偏移，缺少 BTF 时从内核函数推导<br />
修复旧内核凭据字段匹配，兼容 `cred` 与 `real_cred` 两种读取方式<br />
精简偏移查找条件，复用公共 BTF 查询工具
