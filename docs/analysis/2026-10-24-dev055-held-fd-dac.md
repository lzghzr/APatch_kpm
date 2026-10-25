# DEV-055 分析材料：held-FD 保留旧 DAC 属性（维护者整理，供 Developer 参考）

**性质**：分析材料，不是结论。标注了「已核实」与「待核实」，后者须由实现方或审计方给证据。

## 一、已核实的事实

| 事实 | 依据 |
| --- | --- |
| 普通文件物化使用 `new_inode(sb)` | `nomount/nm_inode.c:485` |
| 目录走 `iget5_locked` 复用 | `nm_inode.c:47` 注释与调用；`nm_btf.c:669` 有原型核验 |
| 现象：源 mode 0755→0700 且 owner 改变后，`getattr` 返回 0700、cache test 拒绝、dentry revalidate 返回 0 并 drop，但**已持有的 `file->f_inode` 仍为旧 0755** | `test_nomount_setattr_prerequisites.py`（int/bool 各 25 处断言） |

## 二、推测的机制（待核实）

**推测**：revalidate 失效后 dentry 被 drop，下一次 lookup 通过 `new_inode` 造出**一个新的 inode 对象**；
已持有的 `struct file` 仍引用**旧 inode 对象**（合法的引用计数），于是同一路径上出现**两个 inode 对象**，
held-FD 读到的是旧的那份。

对照：原生文件系统里，同一 (sb, ino) 恒为同一个 inode 对象、属性原地更新，所以持有 fd 的 `fstat` 能看到新值。
**若上述推测成立，DEV-055 的根因不是"没刷新属性"，而是"物化产生了第二份 inode"。**

## 三、必须先回答的问题（决定方案）

1. held-FD 的 `fstat` 走的是我们 `i_op->getattr`（会读源）还是 `generic_fillattr`（读 `inode->i_mode`）？
   **若走 getattr 仍返回旧值**，说明旧 inode 的 `i_private` 仍指向一条已被替换的规则/源，属另一类问题。
2. 除 `fstat` 外，**哪些内核路径会对已打开的 file 使用 `inode->i_mode`/`i_uid`/`i_gid`**？
   逐条列出并判断"陈旧值"的实际影响面（展示错误 vs 权限判断错误）。**这是定级的关键**：
   POSIX 语义下，已打开 fd 的读写**不再重做 DAC 检查**，故"旧 fd 仍可读"本身不是缺陷。
3. 虚拟 inode 是否有**稳定的虚拟 ino**？若无，`iget5_locked` 复用的 key 无法建立。

## 四、候选方案（未排序，取决于第三节结论）

**A. 文件物化改用 `iget5_locked`（与目录一致）**
- 收益：同一虚拟 ino 恒为同一 inode 对象，属性原地刷新，held-FD 与路径视图自然一致。
- 成本/风险：需要稳定 key（虚拟 ino）；规则变更/opaque/父子关系变化时 ino 若变化会造成"同一路径两个对象"的回潮；
  与既有 revalidate 失效逻辑的交互要重新论证。

**B. 保持 `new_inode`，让所有属性读取路径都从源取**
- 收益：改动局部。
- 风险：`inode->i_mode` 仍陈旧，任何**不经过我们 getattr** 的内核路径（权限检查、`execve`、`chdir`）都读旧值；
  等于把问题从"属性展示"扩到"权限判断"，需先按第三节第 2 问确认影响面。

**C. 文档化为限制**
- 适用条件：第三节第 2 问证明**所有实际影响仅为显示**，且无权限判断路径读旧值。
- 需用户确认口径（公开发布模块的承诺范围）。

## 五、给实现方的建议顺序

先答第三节三问 → 再在 A/B 之间选 → 最后才动代码。
**本轮不实施**；若第三节第 2 问暴露出权限判断路径读旧值，应立即升级为缺陷修复并重新定级。
