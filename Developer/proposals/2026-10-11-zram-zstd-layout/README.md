# ZSTD 子模块路径迁移配套补丁

将当前源码目录移至 `zram_zstd/zstd`，保留固定提交与子模块逻辑名。先用 `git submodule absorbgitdirs` 保存稳定对象库，再移动工作树并更新当前来源清单、构建路径和模块文档。

`identity.patch` 属维护者工具补丁建议：

- 历史子模块工作树路径消失时，从冻结父提交的 `.gitmodules` 查找原逻辑名，在共享 Git 对象库读取冻结 gitlink 提交。
- 修正 `git cat-file --filters` 的参数：该模式接受单个对象表达式，原命令额外传入 `blob` 会被 Git 拒绝。
- 保留按冻结提交读取、缺失对象拒绝和哈希核验。历史来源记录、归档产物和既有测试判据保持原字节。

`check_relocation.py` 在临时 Git 仓库验证六项行为：旧路径原始读取、旧路径过滤读取、当前路径冻结读取、缺失文件拒绝、错误提交拒绝、原子模块提交保留。使用脏工作树和不同子模块提交验证读取不依赖当前文件。修正前冻结过滤读取失败；补丁副本自检 6/6 通过。

```sh
python3 Developer/proposals/2026-10-11-zram-zstd-layout/check_relocation.py tools/identity.py
```

维护者已于本轮明确授权落地此配套补丁，当前实现与建议一致。这是 Developer 工具复现，独立复核仍由对应角色完成。路径参与源树指纹，迁移后的构建使用新身份；原有审计与设备结论继续绑定原实例。
