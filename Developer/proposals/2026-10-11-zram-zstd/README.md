# zram_zstd 子模块与 legacy 候选支持

本补丁修改 `tools/identity.py` 和 `tools/artifact_gate.py`。用户已于本轮明确授权 Developer 落地这两处维护者工具修改。

身份读取沿父提交的 gitlink 取得子模块 blob，不用子模块当前 HEAD 替代冻结提交；输入捕获包含 `.gitmodules`。增加 `legacy` / `legacy_debug` 的嵌入版本后缀契约。产物门禁按 `kp_compat=legacy` 核对 `_legacy` 命名，缺少该字段的历史产物继续按 modern 检查。

`maintainer.patch` 保留本轮改动，`test_patch.py` 针对已落地工具运行：子模块 HEAD 已前移时仍读取父提交固定字节，保留 checkout filters、缺失文件错误与现有六种产物的命名正反检查。原有共享工具测试断言保持不变。

复现：

```sh
python3 Developer/proposals/2026-10-11-zram-zstd/test_patch.py \
  --scratch local/<新的空目录> --build local/<六种产物目录>
python3 tools/selftest_artifact_gate.py
python3 tools/selftest_tools.py
```

本轮版本声明、CI 静态 JSON 收集、维护者导入和问题单状态仍由维护者处理。legacy 目标由候选命令显式选择，默认 `all` / `debug` 仅生成 modern 模式，legacy 只随 artifacts 交接。
