# cgroups.json 补丁器独立夹具（Auditor 自建）

用途：为 `cgroupv2_freeze` 的 `cg_json_patch()` 全家桶（`cg_find` /
`cg_object_end` / `cg_field` / `cg_replace` / `cg_json_patch`）提供**不依赖
Developer `tools/test_cgroups_json.py`** 的反例集。

## 构成

| 文件 | 说明 |
| --- | --- |
| `cg_json_extract.inc` | 从冻结源码 `91f44c8:cgroupv2_freeze/cgroupv2_freeze.c` 第 404–544 行**逐字**截取（sha256 `d84431246449917f2e0d35d5304fb1542d1148f5e33c0aa53a5cbc52d67e78b1`），无任何改写 |
| `extract_inc.sh` | 上述截取的生成与哈希核对脚本 |
| `harness.c` | 本夹具的用例（`EXPECT` = 承诺行为；`LIMIT` = 实测包络，只记录事实） |

被测函数只依赖 `strlen/memcmp/memcpy/memmove`，宿主 libc 语义与内核侧一致；
产物里这些函数被 GCC 内联进 `vfs_read_after`（符号表无 `cg_json_patch`），
其指令序列已在报告里逐段对照源码复核。

## 运行

```sh
cd Auditor/tools/cfv2_json_fixtures
clang -O1 -Wall -Wextra -Wno-unused-parameter -o /tmp/cfv2_json_fixtures harness.c
/tmp/cfv2_json_fixtures
```

退出码 0 = 全部 `EXPECT` 用例与实测一致、且每个 `LIMIT` 用例记下的事实成立。

## 边界

- 夹具只验证**纯函数**语义；`vfs_read` 钩子侧的 `ret/count/*pos` 判定、
  用户态拷贝与日志由报告中的反汇编证据覆盖。
- 夹具不覆盖目标文件真实形态（`/system/etc/cgroups.json` 是数据事实，
  需真机或镜像侧取证）。
