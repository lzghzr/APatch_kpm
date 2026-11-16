#!/usr/bin/env python3
"""Tester tool: B 节 模块 ID/路径含 shell 元字符（空格、单引号）真机验证"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO_ROOT / 'local/keep/evidence/tester-raw/zip20261116-theme-shell'
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
SERIAL = os.environ.get('ANDROID_SERIAL', '').strip()
if not SERIAL:
    sys.exit('错误: 请设置 ANDROID_SERIAL 环境变量 (例如: export ANDROID_SERIAL=...)')

def adb(cmd, check=True):
    # 通过 stdin 输送给 su，避免嵌套引号转义破坏
    full_cmd = ['adb', '-s', SERIAL, 'shell', 'su']
    r = subprocess.run(full_cmd, input=cmd + '\n', text=True, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed (rc={r.returncode}): {cmd}\nSTDOUT: {r.stdout}\nSTDERR: {r.stderr}")
    return r

def shell_quote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"

def main():
    log_lines = []
    def log(msg):
        print(msg)
        log_lines.append(msg)

    log('=== B. 模块 ID／路径含 shell 元字符真机验证 ===')

    # 1. 测前基线采样
    log('\n--- 1. 测前环境基线 ---')
    pre_mods = adb('ls -1 /data/adb/modules').stdout.strip().splitlines()
    pre_rule_count = int(adb('nm rule list | wc -l').stdout.strip())
    pre_rules = adb('nm rule list').stdout
    (EVIDENCE_DIR / 'pre_rules.txt').write_text(pre_rules)
    log(f'当前 /data/adb/modules 模块数: {len(pre_mods)}')
    log(f'当前生效规则数: {pre_rule_count} (期望 47)')
    assert pre_rule_count == 47, f"Pre-test rule count is {pre_rule_count}, expected 47"

    mod_space_dir = '/data/adb/modules/nm t1'
    mod_quote_dir = "/data/adb/modules/nm't2"

    try:
        # 2. 创建测试模块
        log('\n--- 2. 创建特殊字符测试模块 ---')
        # 2.1 空格模块
        adb(f'mkdir -p {shell_quote(mod_space_dir + "/system/etc")}')
        adb(f'echo "id=nm t1\nname=NM Test Space\nversion=1.0\nversionCode=1\nauthor=Tester\ndescription=Space test" > {shell_quote(mod_space_dir + "/module.prop")}')
        adb(f'echo "test space content" > {shell_quote(mod_space_dir + "/system/etc/nm_test_space.txt")}')
        log(f'已创建空格测试模块: {mod_space_dir}')

        # 2.2 单引号模块
        adb(f'mkdir -p {shell_quote(mod_quote_dir + "/system/etc")}')
        adb(f'echo "id=nm\'t2\nname=NM Test Quote\nversion=1.0\nversionCode=1\nauthor=Tester\ndescription=Quote test" > {shell_quote(mod_quote_dir + "/module.prop")}')
        adb(f'echo "test quote content" > {shell_quote(mod_quote_dir + "/system/etc/nm_test_quote.txt")}')
        log(f'已创建单引号测试模块: {mod_quote_dir}')

        # 检查目录
        cur_dirs = adb('ls -1 /data/adb/modules').stdout.strip().splitlines()
        log(f'创建后目录包含 nm t1: {"nm t1" in cur_dirs}')
        log(f'创建后目录包含 nm\'t2: {"nm\'t2" in cur_dirs}')
        assert "nm t1" in cur_dirs, "nm t1 not found in modules"
        assert "nm't2" in cur_dirs, "nm't2 not found in modules"

        # 3. 验证 nm module list 与 --json 解析
        log('\n--- 3. nm module list 与 --json 解析 ---')
        r_list = adb('nm module list')
        log(f'nm module list 退出码: {r_list.returncode}')
        
        # 严格 JSON 解析
        json_data = json.loads(r_list.stdout)
        mods = json_data.get('mods', [])
        mod_ids = [m.get('modId') for m in mods]
        log(f'解析到模块总数: {len(mods)}')
        log(f'包含 "nm t1": {"nm t1" in mod_ids}')
        log(f'包含 "nm\'t2": {"nm\'t2" in mod_ids}')
        assert "nm t1" in mod_ids, 'modId "nm t1" missing from JSON'
        assert "nm't2" in mod_ids, 'modId "nm\'t2" missing from JSON'

        space_m = next(m for m in mods if m.get('modId') == 'nm t1')
        quote_m = next(m for m in mods if m.get('modId') == "nm't2")
        log(f'空格模块信息: modId="{space_m.get("modId")}", root="{space_m.get("root")}"')
        log(f'单引号模块信息: modId="{quote_m.get("modId")}", root="{quote_m.get("root")}"')
        assert space_m.get('root') == mod_space_dir
        assert quote_m.get('root') == mod_quote_dir

        # 4. 验证 disable 与 skip_mount 标记落点
        log('\n--- 4. disable 与 skip_mount 标记落点验证 ---')
        # 4.1 空格模块
        # touch disable
        adb(f'touch {shell_quote(mod_space_dir + "/disable")}')
        has_disable = adb(f'[ -f {shell_quote(mod_space_dir + "/disable")} ] && echo YES', check=False).stdout.strip()
        log(f'空格模块 /disable 存在性: {has_disable}')
        assert has_disable == 'YES'

        # 检查是否截断产生野文件（例如 /data/adb/modules/nm 或 t1）
        rogue_files_space = adb('ls -1 /data/adb/modules | grep -E "^(nm|t1|disable|skip_mount)$" || true', check=False).stdout.strip()
        log(f'空格模块创建标记后野文件检查 (应为空): "{rogue_files_space}"')
        assert rogue_files_space == '', f"Rogue files found: {rogue_files_space}"

        # touch skip_mount
        adb(f'touch {shell_quote(mod_space_dir + "/skip_mount")}')
        has_skip = adb(f'[ -f {shell_quote(mod_space_dir + "/skip_mount")} ] && echo YES', check=False).stdout.strip()
        log(f'空格模块 /skip_mount 存在性: {has_skip}')
        assert has_skip == 'YES'

        # rm disable & skip_mount
        adb(f'rm -f {shell_quote(mod_space_dir + "/disable")} {shell_quote(mod_space_dir + "/skip_mount")}')
        post_rm_space = adb(f'ls -1 {shell_quote(mod_space_dir)}').stdout.strip().splitlines()
        log(f'空格模块清理标记后内部清单: {post_rm_space}')
        assert 'disable' not in post_rm_space and 'skip_mount' not in post_rm_space

        # 4.2 单引号模块
        # touch disable
        adb(f'touch {shell_quote(mod_quote_dir + "/disable")}')
        has_disable_q = adb(f'[ -f {shell_quote(mod_quote_dir + "/disable")} ] && echo YES', check=False).stdout.strip()
        log(f'单引号模块 /disable 存在性: {has_disable_q}')
        assert has_disable_q == 'YES'

        rogue_files_quote = adb('ls -1 /data/adb/modules | grep -E "^(nm|t2|disable|skip_mount)$" || true', check=False).stdout.strip()
        log(f'单引号模块创建标记后野文件检查 (应为空): "{rogue_files_quote}"')
        assert rogue_files_quote == '', f"Rogue files found: {rogue_files_quote}"

        # touch skip_mount
        adb(f'touch {shell_quote(mod_quote_dir + "/skip_mount")}')
        has_skip_q = adb(f'[ -f {shell_quote(mod_quote_dir + "/skip_mount")} ] && echo YES', check=False).stdout.strip()
        log(f'单引号模块 /skip_mount 存在性: {has_skip_q}')
        assert has_skip_q == 'YES'

        # rm disable & skip_mount
        adb(f'rm -f {shell_quote(mod_quote_dir + "/disable")} {shell_quote(mod_quote_dir + "/skip_mount")}')
        post_rm_quote = adb(f'ls -1 {shell_quote(mod_quote_dir)}').stdout.strip().splitlines()
        log(f'单引号模块清理标记后内部清单: {post_rm_quote}')
        assert 'disable' not in post_rm_quote and 'skip_mount' not in post_rm_quote

        # 5. 验证 nm module load / unload
        log('\n--- 5. nm module load / unload 验证 ---')
        # 5.1 空格模块 load
        r_load_space = adb(f'nm module load {shell_quote(mod_space_dir)}')
        log(f'nm module load "nm t1" stdout: {r_load_space.stdout.strip()}')
        log(f'nm module load "nm t1" stderr: {r_load_space.stderr.strip()}')
        assert 'nm_load_status=0' in r_load_space.stderr
        
        cur_rc = int(adb('nm rule list | wc -l').stdout.strip())
        log(f'加载后规则计数 (47 -> 48): {cur_rc}')
        assert cur_rc == 48

        # 检查规则可见性
        rule_content = adb('cat /system/etc/nm_test_space.txt', check=False).stdout.strip()
        log(f'虚拟重定向文件读取: "{rule_content}"')
        assert rule_content == 'test space content'

        # 空格模块 unload
        r_unload_space = adb(f'nm module unload {shell_quote(mod_space_dir)}')
        log(f'nm module unload "nm t1" stdout: {r_unload_space.stdout.strip()}')
        log(f'nm module unload "nm t1" stderr: {r_unload_space.stderr.strip()}')
        assert 'nm_unload_status=0' in r_unload_space.stderr

        cur_rc = int(adb('nm rule list | wc -l').stdout.strip())
        log(f'卸载后规则计数 (48 -> 47): {cur_rc}')
        assert cur_rc == 47

        # 5.2 单引号模块 load
        r_load_quote = adb(f'nm module load {shell_quote(mod_quote_dir)}')
        log(f'nm module load "nm\'t2" stdout: {r_load_quote.stdout.strip()}')
        log(f'nm module load "nm\'t2" stderr: {r_load_quote.stderr.strip()}')
        assert 'nm_load_status=0' in r_load_quote.stderr

        cur_rc = int(adb('nm rule list | wc -l').stdout.strip())
        log(f'加载后规则计数 (47 -> 48): {cur_rc}')
        assert cur_rc == 48

        rule_content_q = adb('cat /system/etc/nm_test_quote.txt', check=False).stdout.strip()
        log(f'虚拟重定向文件读取: "{rule_content_q}"')
        assert rule_content_q == 'test quote content'

        # 单引号模块 unload
        r_unload_quote = adb(f'nm module unload {shell_quote(mod_quote_dir)}')
        log(f'nm module unload "nm\'t2" stdout: {r_unload_quote.stdout.strip()}')
        log(f'nm module unload "nm\'t2" stderr: {r_unload_quote.stderr.strip()}')
        assert 'nm_unload_status=0' in r_unload_quote.stderr

        cur_rc = int(adb('nm rule list | wc -l').stdout.strip())
        log(f'卸载后规则计数 (48 -> 47): {cur_rc}')
        assert cur_rc == 47

    finally:
        # 6. 收尾清理与一致性核验
        log('\n--- 6. 收尾清理与目录回核 ---')
        adb(f'rm -rf {shell_quote(mod_space_dir)} {shell_quote(mod_quote_dir)}')
        
        post_mods = adb('ls -1 /data/adb/modules').stdout.strip().splitlines()
        post_rule_count = int(adb('nm rule list | wc -l').stdout.strip())
        post_rules = adb('nm rule list').stdout
        (EVIDENCE_DIR / 'post_rules.txt').write_text(post_rules)

        log(f'清理后模块数: {len(post_mods)} (测前 {len(pre_mods)})')
        log(f'清理后生效规则数: {post_rule_count} (测前 {pre_rule_count})')

        diff_mods = set(post_mods) ^ set(pre_mods)
        log(f'模块目录集合差异: {diff_mods}')
        assert len(diff_mods) == 0, f"Modules directory not clean: diff={diff_mods}"
        assert post_rule_count == 47, f"Post-test rules count {post_rule_count} != 47"
        assert post_rules == pre_rules, "Rules output modified after test"
        log('模块目录与系统规则集 100% 恢复原状！')

    out_log = EVIDENCE_DIR / 'step_b_shell_metachar.log'
    out_log.write_text('\n'.join(log_lines) + '\n')
    log(f'\nB 节真机验证日志已写入: {out_log}')

if __name__ == '__main__':
    main()
