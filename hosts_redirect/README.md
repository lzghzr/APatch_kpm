# hosts_redirect
## 模块作用
将 `/system/etc/hosts` 重定向到 `/data/adb/hosts/{name}`<br />
可使通过 `参数` 或 `kpatch` 更改 `{name}` 值<br />
例如执行 `su -c 'U=$(stat -c %u /data/data/me.bmax.apatch) && L=$(find /data/app -type f -path "*/me.bmax.apatch-*/lib/arm64/libkpatch.so") && [ -x "$L" ] && su "$U" -c "\"$L\" su kpm ctl0 hosts_redirect adblock"'` 重定向到 `/data/adb/hosts/adblock`<br />
设置为 `disable` 时禁用重定向

## 更新记录

### 2.0.2

修复目标名目录穿越：完整校验通过后才更新规则<br />
非法目标名保持原规则，日志记录拒绝原因

### 2.0.1

移除相对路径的支持<br />
移除 `set_priv_sel_allow`

### 2.0.0

变更重定向文件路径为 `/data/adb/hosts/{name}`

### 1.2.0

支持相对路径

### 1.1.0

支持使用 `kpatch` 动态调整重定向

### 1.0.0

练手模块, 灵感来源于 [hosts_file_redirect](https://github.com/AndroidPatch/kpm/tree/main/src/hosts_file_redirect)
