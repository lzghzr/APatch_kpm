# dont_kill_freeze
## 模块作用
为所有已冻结的进程拦截 `SIGKILL` 信号

## 已知 BUG
如果再次进入前台卡住, 需使用 `root` 用户强制杀死

## 更新记录
### 1.0.2
killer 黑名单改为白名单，变更 `task_struct->jobctl` 获取方式, 新增 `oom_score_adj` 过滤
### 1.0.1
拦截更加温柔
### 1.0.0
初始版本
