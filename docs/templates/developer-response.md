# Developer 修复响应模板

> 放在 `Developer/reports/responses/<日期>-<问题编号>.md`。只写修复与证据，不写验收结论。

## 对应问题

| 项 | 值 |
| --- | --- |
| 问题编号 | `<AUD-xxx / TST-xxx / DEV-xxx / MNT-xxx>` |
| 严重度 / 归属 | `<高/中/中低/低>` / `<角色>` |
| 发现方 | `<角色>` |

## 修复

| 项 | 值 |
| --- | --- |
| 修复 commit | `<40 位 sha>` |
| Build ID | `<build_id>`（实例 `<build_id>#n`） |
| 产物 | `<文件名>` `sha256=<64 hex>` |
| 交接清单 | `Developer/reports/handoffs/<文件>.json` |
| 修复内容 | <一句话> |
| 影响面 | <哪些内核/变体/功能受影响> |

## 证据

```text
<复现命令与输出；审查点类问题要给出「修复前后的差异」>
```

- 自检命令：`make -C <module> ...` / `python3 tools/identity.py verify`
- 离线回归：`cd kernel_img/offset_harness && python3 run.py --image <名字>`
- 针对该问题单的最小验证：<命令与结果>

## 边界声明

> 本响应是**实现方自检**，不是复核结论。问题单由发现方复核后关闭。

## 未覆盖 / 需要发现方确认的点

- 

## 后续状态（追加，不改写上面）

- `<日期>`：<修复后又发现/回归的情况>
