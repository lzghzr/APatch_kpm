# 双模式构建的维护者补丁建议

rek 与 rekx 分别由各自的 Makefile 构建两种模式。本补丁由维护者落地，涉及 `AGENTS.md`、`.github/workflows/build-kpm.yml`、`tools/artifact_gate.py`、`tools/identity.py` 与 `.agents/skills/kpm-static-binary-port/SKILL.md`；所有权依据 `docs/process/02-roles.md`。

- 根目录 AGENTS 固化全项目偏移模式规范。
- Actions 对两个模块运行 `all debug`，保存四种编译产物；Releases 选取各一份普通 static/dynamic KPM 和静态 JSON，debug 留在 artifacts。
- 门禁核对 `offset_mode` 与文件名；static 必须附带匹配布局，dynamic 附带静态布局则拒绝。旧基线继续沿用原有判据。
- 静态移植技能使用仓库根目录 `patch_offsets.py`，生成布局时读取 `re_kernel_x/re_offsets.c`。
- 身份工具 CLI 增加模式及 baselines 变体名称；嵌入版本仍以 `_d` 表示 debug。

全项目默认规范见 `Developer/README.md` 的「模块偏移模式默认规范」。其他有偏移依赖的模块逐个接入，没有偏移依赖的模块继续生成通用 KPM。

## 自检

在私有副本应用 `maintainer.patch` 后，原 `selftest_artifact_gate.py` 的 37 条断言、`selftest_release_assets.py` 的 4 条断言均通过，测试文件字节未改。新增 `verify_modes.py` 用本轮实际 8 份 KPM 验证发布的 4 份普通 KPM 与 2 份 JSON，并拒绝缺失静态 JSON、动态附带 JSON、模式/文件名错配、缺失任一模块动态版以及重复静态基线。

```bash
python3 Developer/proposals/2026-10-10-kpm-modes/verify_modes.py --proposal-root <补丁副本> --layouts <本轮布局目录> --output <新的空目录>
```

当前命名与探索身份见 `Developer/reports/2026-10-10-rek-naming.md`，构建入口记录见 `Developer/reports/2026-10-10-rek-project-build.md`。这是 Developer 补丁自检，仓库当前 Actions 和门禁仍由维护者接入。

动态产物沿用 `<模块>_<版本>.kpm`，静态使用 `<模块>_<版本>_baselines.kpm`，debug 增加 `_debug`。发布脚本按基线后缀和模式元信息核对两种产物，保留旧发布基线的判据。

最新源码组织、公共 BTF 查询及验证身份见 [开发记录](../../reports/2026-10-10-rek-shared-offsets.md)。
