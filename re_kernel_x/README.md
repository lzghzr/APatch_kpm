# ReKernel-X

基于 [ReKernel-X](https://github.com/myflavor/ReKernel-X)，向配套墓碑应用报告应用活动，帮助它判断何时解冻，并清理重复消息；需要支持 ReKernel-X 的墓碑应用。

## 选哪个文件

- `re_kernel_x.kpm`：普通版；实际文件名可能带版本号。
- `re_kernel_x_baselines.kpm`：须由 AI 为设备准备后使用，原始模板不能直接安装。

只选一个版本。

## 安装与查看

1. 在 APatch 的内核模块页面为适配设备的文件选择「安装」，然后重启。
2. 打开配套墓碑应用并连接模块，按应用说明完成设置。

## 更新与停用

- 更新：确认新版适配自己的设备，替换已安装文件后重启。
- 停用或移除：先取消嵌入或删除已安装文件，再重启。

适用于 Android 64 位设备，内核 4.4～6.6 须先确认设备适配。

## 更新记录

### 1.6-20261010

新增 BTF 获取偏移，动态版加载时优先查询目标内核 BTF<br />
缺少 BTF 数据或查询接口时，继续尝试内核函数推导<br />
提供动态版和静态基线两种产物

### 1.6-20261008

沿用上游 ReKernel-X 1.6，日期后缀标识本轮 KPM 移植<br />
Genl 收发、网络 UID 增删、异步清理规则及统一 Binder 释放调用配置

### 1.6

版本号与 [ReKernel-X 1.6](https://github.com/myflavor/ReKernel-X/releases/tag/1.6) 对齐<br />
模块改名为 `re_kernel_x`，加入作者 `myflavor`<br />
模块描述改为 `every bit belongs to you.` 看似浪漫实则没招了<br />
Genl 控制请求仅允许 UID 1000
