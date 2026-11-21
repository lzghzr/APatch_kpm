# cgroupv2_freeze 开发约定

## 功能基线

以 `main` 的 1.0.12 为 UID 模式基线：按 ROM 中实际存在的 UID 组选择 cgroup2 或 v1 cpuacct，保留 `uid_*`、`frozen`（冻结）和 `unfrozen`。复验先核对挂载类型与组内容，再验证实际调用方的读写、冻结/解冻和 SELinux 拒绝；空的 cgroup2 根不算通过。真机还需核对引导存活及预期事件加载成功。

模块用 `pre-kernel-init` 安装；运行期加载只覆盖其后创建的组。注册回调常驻，禁止热卸载，重启移除。

## 启动挂载

`cfv2_uid_mount.c` 仅在 `pre-kernel-init` 加载时启用启动挂载。KernelPatch 收到 APatch 上报的 `post-fs-data/after` 后派发模块事件，回调只登记一次 `task_work`。上报任务须已有 root 凭据，且与 PID 1 同一挂载命名空间；权限不足时记录失败步骤和 errno，不修改凭据或 SELinux。

优先检查 `/dev/cg2_bpf`，要求 `uid_0` 与 `cgroup.controllers` 都在该层级；只有找不到 `/dev/cg2_bpf/uid_0` 才尝试 `/acct`，后者用 `uid_0` 和 `cpuacct.usage` 核对。只绑定到空的 sysfs 目标 `/sys/fs/cgroup`，或复用已指向同一根的挂载。

仅为新建的 `frozen`、`unfrozen` 及其控制文件设置 UID/GID 1000。新目录权限为 `0775`，控制文件保留组和其他用户的权限位，确保属主可读写。已有同名组只校验，不改权限或冻结状态；原有 UID 分组和共享根不变。两组准备好后才绑定，绑定前失败只尝试清理本次新建组。

UID 1000 不替代 SELinux 授权。验收时记录实际调用方的 UID/GID 和 SELinux 域，分别验证目录遍历、控制文件读写及冻结/解冻。用 `su 1000` 运行在 `magisk` 域的探针只覆盖该探针身份；实际写者及 `system_server` 的使用情况另行取证。

## 构建与自检

默认使用 Arm GNU Toolchain 12.2.rel1；`kpm_runtime.c` 提供独立链接的 `memset`，`kf_memset` 作为未定义符号由 KP 解析到函数指针槽，槽值为空时在装钩前拒载。保留原生 freezer 的 `-EOPNOTSUPP` 拒载、CTL0 输出边界和 `-EBUSY` 退出政策。

`make -C cgroupv2_freeze` 默认只构建动态版；`all` 构建动态版、静态模板及配套 JSON，`static` 仅构建静态与 JSON。候选用 `--target all --extra-input patch_offsets.py`；两版管理名称相同，只嵌入一份。

`python3 cgroupv2_freeze/tools/test_uid_mount.py` 自检 UID 来源和挂载选择、权限失败、已存在组及回滚。其余 `tools/` 内现有夹具保留原断言。它们按对应候选的源码切片取样：复核 1.0.14 时，在冻结提交 `967b79c18c3909deb151d7e1ae1e0c9d664a5077` 中运行该提交的工具；挂载实验按各自冻结提交运行。现行 UID 模式以设备回归判据为准。

## 静态基线移植

模板的所有字段初值为 `-1`（未配置），未填全时在注册回调前拒载。`0` 可以是合法偏移，例如成员位于结构体开头；字段仍须满足对齐要求，`cftype` 槽与步长还须满足各自的布局边界。两版共用 freezer、UID 挂载和生命周期；静态版用表里的偏移、两项独立参数个数、`cftype` 的 flags/show/write 槽与步长，以及旧版 `kernfs` 属主修正开关（0/1）。移植时还须核对沿用的公共结构前缀、`css_task_iter` 的本地空间及目标的运行时符号；这些不由填表校验代替。
表和原生依赖先核对；全部 hook 成功后才启用回调及 UID 挂载。首个 hook 失败拒载；部分已挂时保留惰性实例，CTL0 返回 `-ENODEV`，重启后再试。KP 的摘钩不等待在途回调，不能返回 init 失败让加载器释放已发布代码。

将镜像绑定配置 `nokia-b2n-4.4.192.json` 和原始回归配置集 `static-profiles.json` 放入模块的 `local/configs/`。前者须与输入镜像的裸内核 SHA-256 匹配，后者供静态补丁回归使用。在新目录构建和应用配置：

```sh
out=$(mktemp -d)
make -C cgroupv2_freeze all OUT_DIR="$out"
baseline=$(printf '%s' "$out"/*_baselines.kpm)
mkdir "$out/nokia"
python3 patch_offsets.py patch "$baseline" \
  --offsets cgroupv2_freeze/local/configs/nokia-b2n-4.4.192.json \
  --output "$out/nokia/$(basename "$baseline")"
python3 cgroupv2_freeze/tools/test_baselines.py \
  --image kernel_img/B2N-416G_boot.img --baseline "$baseline"
```

自检用目标镜像的真实指令运行现有动态解码，以静态补丁的实际表值对照字段、调用选择及注册表，并核对补丁未改动配置段外的字节。真机嵌入、冻结/解冻与实际调用方权限须另行验证。
