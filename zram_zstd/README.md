> 注: 此模块完全依据项目内流程，并由 agent 完成，以此验证可行性

# zram_zstd

为 zram 提供 ZSTD 1.5.7。模块加载、zram 就绪后，压缩算法列表会显示 `zstd-kpm`，可以通过开机脚本或管理工具选择。它可以与内核自带的 `zstd` 一起使用。

已核对仓库中 4.4～6.6 的内核镜像布局。1.0.0 增加算法列表显示，支持内建 zram 和稍后加载的 `zram.ko`；新版还需由测试者完成真机验证。模块要求 zram 使用 Crypto API，不能仅凭内核版本判断是否适用。

**嵌入后不要卸载，卸载可能导致内核崩溃。要移除模块，请取消嵌入，再重启设备。**

## 用哪个文件

通常选普通动态版，一次只加载一个版本。

| 文件 | 用途 |
| --- | --- |
| 普通 `zram_zstd.kpm` | 加载时自动获取偏移，一般用这个 |
| `zram_zstd_baselines.kpm` | 静态移植用，必须先按目标内核填写偏移，不能直接加载模板 |

旧 KP 如果提示找不到 `kallsyms_lookup_name_by_suffix`，需要先用 Python 工具转换普通 KPM。转换和静态移植的方法见 [AGENTS.md](AGENTS.md)。

## 怎么启用

1. 把 KPM 嵌入启动镜像，加载事件选 `post-kernel-init`，参数留空。这样模块能在系统配置 zram 之前加载。
2. 在设备原有的 zram 开机脚本中，先选择压缩算法，再设置容量、启用交换空间：

   ```sh
   echo zstd-kpm > /sys/block/zram0/comp_algorithm
   ```

   这条命令要放在 zram 初始化之前。如果设备用的不是 `zram0`，换成对应编号。
3. 重启后确认状态：

   ```sh
   cat /sys/block/zram0/comp_algorithm
   cat /proc/crypto
   ```

   `comp_algorithm` 里出现 `[zstd-kpm]`，表示 zram 已经选用了它。`/proc/crypto` 里应能看到 `name: zstd-kpm` 和 `driver: zstd-kpm`。

只加载模块不会自动切换已经初始化的 zram，还需要开机脚本完成第 2 步。

编译方法和源码说明见 [AGENTS.md](AGENTS.md)。

## 遇到问题

- 日志里有 `registered zstd-kpm`：模块已经注册成功，再看 zram 是否选中了 `[zstd-kpm]`。
- 日志里有 `zstd-kpm already available; skip loading`：这个算法已经注册，模块跳过重复加载。
- 提示找不到符号：检查 KP 版本，旧 KP 可能需要转换后的 KPM。
- 提示偏移获取失败：保存内核日志，需要针对这份内核重新适配。

`zstd-kpm` 表示算法可选，`[zstd-kpm]` 表示已经选中。如果列表中没有它，但 `/proc/crypto` 已有对应条目，仍可在初始化前直接写入 `zstd-kpm`；保存内核日志，检查列表显示功能是否接入成功。

## 更新记录

### 1.0.0

未选用时也在 zram 压缩算法列表中显示 `zstd-kpm`<br />
支持 zram 内建及 `zram.ko` 稍后加载，已有算法列表与选中状态保持<br />
列表显示无法接入时，仍可直接指定 `zstd-kpm`

### 0.4.0

算法名改为 `zstd-kpm`，可与内核自带 ZSTD 并存、分别选择<br />
适配仓库中的 4.19、5.4、5.10、5.15、6.1、6.6 内核布局<br />
共同结构定义集中到 `zs_structs.h`，其余字段通过 BTF 或短函数取得

### 0.3.0

ZSTD 升级到 1.5.7 内核分支，源码固定在子模块提交中<br />
改用新的静态工作区接口<br />
完成 4.4、4.9、4.14 的宿主机自检

### 0.2.0

增加 4.9、4.14 内核适配和旧 KP 支持<br />
通过 Git 子模块固定 ZSTD 源码版本<br />
控制接口沿用 rek 的彩蛋

### 0.1.0

加入 ZSTD 压缩和解压<br />
加载时检测内核是否已经支持 ZSTD<br />
提供动态版和静态基线两种构建方式
