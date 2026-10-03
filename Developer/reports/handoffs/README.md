# Developer 交接清单（handoff manifest）

Developer 用受控工具产出的**候选身份清单**，用于在不触碰 `metadata/`（维护者目录）的前提下把候选交给维护者。
工具不直接改元数据，维护者导入后才成为正式记录。

## 生成

```bash
export ANDROID_NDK=<ndk 路径>
python3 tools/identity.py record <module> \
    --toolchain "ndk26.3.11579264" \
    --build-cmd "make -C <module> all debug" \
    --by Developer \
    --handoff Developer/reports/handoffs/<module>-<版本>.json
```

- `--handoff` 只写本目录的 JSON，**不写** `metadata/modules/*.json`；产物仍按同一规则归档到 `artifacts/<build_id>/`（不可覆盖）。
- 清单内容：模块、版本、KernelPatch commit、每条构建的 `build_id` / `instance_id` / 严格 `fingerprint_sha256` /
  构建输入清单 / 有效编译参数（`make -n -B` 捕获）/ 产物哈希。
- 交接时随清单一起给出：开发报告路径、自检覆盖范围、已知可疑点（见 `docs/templates/handoff.md`）。

## 导入（维护者）

```bash
python3 tools/identity.py import-manifest Developer/reports/handoffs/<文件>.json --by 维护者
```

- 默认跳过与既有记录完全一致的条目（幂等）；要登记「同配方的一次复现」用 `--new-instance`。
- 导入只追加 `builds[]`，不改 `status` / `audits` / `issues`。

## 规则

1. 清单只追加，不覆盖；同一 `<build_id>` 的复现作为新实例（`#2`、`#3`…）登记。
2. 清单里的路径必须是仓库相对路径（工具已做脱敏），不得出现本机绝对路径。
3. 未提交改动构建出的候选：`source_dirty` 会是 `true`，按提交核验只能覆盖已提交部分——交接前请先冻结提交。
