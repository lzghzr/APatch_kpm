# NoMount 上游接入

将原版源码以 `nomount/nomount` Git 子模块接入，冻结到 `1ded61dc908c511072162fa0bee44e6ccdb7b4c7`。本提案仅涉及根目录 `.gitmodules` 和模块 gitlink（落地时路径取 `nomount/nomount`，与 `zram_zstd/zstd` 惯例一致），移植文件在 `nomount/` 中单独维护。

`submodule.patch` 待维护者落地后，执行 `git submodule update --init nomount/nomount` 取得冻结源码。开发阶段已读取同一提交的隔离检出；上游安装脚本未执行。

原版 `setup.sh` 只添加源码链接和 Kconfig/Makefile 项，没有修改原生 VFS 调用点。KPM 的操作表布局、权限和引用管理仍须单独实现与核验。
