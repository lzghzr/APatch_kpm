#!/usr/bin/env python3
"""Tester tool: 真机 Material You 主题字段读取、截图与像素采样比对"""
import json
import os
import struct
import subprocess
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = REPO_ROOT / 'local/keep/evidence/tester-raw/zip20261116-theme-shell'
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
SERIAL = os.environ.get('ANDROID_SERIAL', '').strip()
if not SERIAL:
    sys.exit('错误: 请设置 ANDROID_SERIAL 环境变量 (例如: export ANDROID_SERIAL=...)')

def adb(cmd, root=False):
    if root:
        full_cmd = ['adb', '-s', SERIAL, 'shell', f"su -c '{cmd}'"]
    else:
        full_cmd = ['adb', '-s', SERIAL, 'shell', cmd]
    r = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
    return r.stdout.strip()

def screencap_to_bmp(png_path, bmp_path):
    cmd = ['adb', '-s', SERIAL, 'exec-out', 'screencap', '-p']
    with open(png_path, 'wb') as f:
        subprocess.run(cmd, stdout=f, check=True)
    subprocess.run(['sips', '-s', 'format', 'bmp', str(png_path), '--out', str(bmp_path)],
                   capture_output=True, check=True)

def parse_bmp(bmp_path):
    with open(bmp_path, 'rb') as f:
        header = f.read(54)
        data_offset = struct.unpack('<I', header[10:14])[0]
        width, height = struct.unpack('<ii', header[18:26])
        f.seek(data_offset)
        data = f.read()
    stride = width * 4
    h_abs = abs(height)
    return width, h_abs, stride, data

def sample_pixels(bmp_path, target_hex=None, roi=None):
    width, height, stride, data = parse_bmp(bmp_path)
    colors = Counter()
    hits = []
    
    y_min, y_max = (roi[1], roi[3]) if roi else (0, height)
    x_min, x_max = (roi[0], roi[2]) if roi else (0, width)
    
    step = 1 if roi else 5
    for y in range(y_min, y_max, step):
        for x in range(x_min, x_max, step):
            idx = y * stride + x * 4
            b, g, r = data[idx], data[idx+1], data[idx+2]
            hx = f'#{r:02x}{g:02x}{b:02x}'
            colors[hx] += 1
            if target_hex and hx.lower() == target_hex.lower():
                hits.append((x, y, (r, g, b)))
                
    return colors, hits

def main():
    log_lines = []
    def log(msg):
        print(msg)
        log_lines.append(msg)

    log('=== A.2 设备层（真机）主题取色与像素采样 ===')
    
    # 1. 记录系统主题字段
    theme_pkg = adb('settings get secure theme_customization_overlay_packages')
    sdk_ver = adb('getprop ro.build.version.sdk')
    accent_600 = adb('cmd overlay lookup android android:color/system_accent1_600')
    accent_200 = adb('cmd overlay lookup android android:color/system_accent1_200')
    orig_uimode = adb('cmd uimode night')

    log(f'ro.build.version.sdk: {sdk_ver}')
    log(f'settings secure theme_customization_overlay_packages: {theme_pkg}')
    log(f'cmd overlay lookup android android:color/system_accent1_600: {accent_600}')
    log(f'cmd overlay lookup android android:color/system_accent1_200: {accent_200}')
    log(f'初始 uimode night: {orig_uimode}')

    # 唤醒屏幕
    adb('input keyevent 224; input keyevent 82')
    time.sleep(1)

    # 2. 浅色模式测试
    log('\n--- 2.1 浅色模式采样 ---')
    adb('cmd uimode night no')
    time.sleep(1)
    adb('am start -n me.bmax.apatch/.ui.WebUIActivity -e id nomount -e name NoMount', root=True)
    time.sleep(2)
    
    light_png = EVIDENCE_DIR / 'webui_light_live.png'
    light_bmp = EVIDENCE_DIR / 'webui_light_live.bmp'
    screencap_to_bmp(light_png, light_bmp)
    log(f'截图已保存: {light_png.name} ({light_png.stat().st_size} B)')

    # 在卡片/按钮区域采样
    roi = (120, 1580, 250, 1680)
    c_light, hits_light = sample_pixels(light_bmp, target_hex='#6b6f5d', roi=roi)
    log(f'ROI {roi} 强调色 #6b6f5d 命中像素数: {len(hits_light)}')
    if hits_light:
        sample_pt = hits_light[0]
        log(f'典型采样点坐标: ({sample_pt[0]}, {sample_pt[1]}), RGB: {sample_pt[2]}, HEX: #6b6f5d')
    log('ROI 内主要颜色分布:')
    for color, count in c_light.most_common(5):
        log(f'  {color}: {count} px')

    # 3. 深色模式测试
    log('\n--- 2.2 深色模式采样 ---')
    adb('cmd uimode night yes')
    time.sleep(2)
    
    dark_png = EVIDENCE_DIR / 'webui_dark_live.png'
    dark_bmp = EVIDENCE_DIR / 'webui_dark_live.bmp'
    screencap_to_bmp(dark_png, dark_bmp)
    log(f'截图已保存: {dark_png.name} ({dark_png.stat().st_size} B)')

    c_dark, hits_dark = sample_pixels(dark_bmp, target_hex='#cdceca', roi=roi)
    log(f'ROI {roi} 强调色 #cdceca 命中像素数: {len(hits_dark)}')
    if hits_dark:
        sample_pt_dark = hits_dark[0]
        log(f'典型采样点坐标: ({sample_pt_dark[0]}, {sample_pt_dark[1]}), RGB: {sample_pt_dark[2]}, HEX: #cdceca')
    log('ROI 内主要颜色分布:')
    for color, count in c_dark.most_common(5):
        log(f'  {color}: {count} px')

    # 4. 恢复环境
    log('\n--- 2.3 恢复环境 ---')
    if 'custom_schedule' in orig_uimode:
        adb('cmd uimode night custom_schedule')
    elif 'yes' in orig_uimode:
        adb('cmd uimode night yes')
    else:
        adb('cmd uimode night no')
    restored_uimode = adb('cmd uimode night')
    log(f'恢复后 uimode night: {restored_uimode}')
    adb('am force-stop me.bmax.apatch')
    log('已退出 APatch WebUI')

    # 清理 BMP 临时文件
    if light_bmp.exists(): light_bmp.unlink()
    if dark_bmp.exists(): dark_bmp.unlink()

    # 保存日志
    out_log = EVIDENCE_DIR / 'step_a2_device_theme.log'
    out_log.write_text('\n'.join(log_lines) + '\n')
    log(f'\n设备采样证据日志已写入: {out_log}')

if __name__ == '__main__':
    main()
