# cgroupv2_freeze

为没有原生 freezer 的 Android 4.4～4.19 内核添加 `cgroup.freeze`，并在启动时准备 `/sys/fs/cgroup` 的 UID 分组与冻结目录。

## 嵌入使用

默认使用动态版；静态基线版须先按目标内核填表，再嵌入使用。`-1` 表示未配置，`0` 可以是合法偏移。

在 APatch 的嵌入页面选择模块，加载事件选 `pre-kernel-init`（默认值）。移除时从嵌入列表删除模块，应用变更后重启；不要在运行中卸载。

重启后检查 `/sys/fs/cgroup` 下是否有 `uid_*`、`frozen` 和 `unfrozen`，后两组的 `cgroup.freeze` 应分别为 `1` 和 `0`。

## 更新记录

### 1.1.0

提供可离线填表的静态基线版。

KPM 在 APatch 启动事件后绑定 ROM 已有的 UID 层级，不执行 shell、不修改 SELinux。只为新建的 `frozen`、`unfrozen` 及其控制文件设置 UID/GID 1000，保留原有 UID 分组和挂载根目录的权限。

### 1.0.12

适配更多内核

### 1.0.11

适配更多内核<br />
优化挂载脚本

### 1.0.10

优化 `MIUI` 内核

### 1.0.9

v2 检测函数由 `do_freezer_trap` 改为 `cgroup_freeze_write`

### 1.0.8

修复冻结失效

### 1.0.7

临时 hook `call_usermodehelper_exec`

### 1.0.6

为高版本内核禁用 `CONFIG_STATIC_USERMODEHELPER`

### 1.0.5

补全uid模式<br />
不再需要附加模块

### 1.0.4

使用其他方式替代所有内核版本判断条件<br />
变更 task_struct->jobctl 获取方式

### 1.0.3

支持 4.19

### 1.0.2

支持 4.9

### 1.0.1

不再修改内核配置文件
