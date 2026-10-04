#!/usr/bin/env python3
"""排版 HTML headless 渲染 QA:截首屏/中段/文末三张图。CDN 图已验证可达,--timeout=3500+兜底。"""
import os
import subprocess

SRC = '/Users/len/CodeBuddy/dx/dnsdiff/公众号排版版.html'
OUT = '/tmp/dnsdiff_qa'
os.makedirs(OUT, exist_ok=True)
CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
UD = '/tmp/dnsdiff_chrome_profile'

for name, w, h in ('qa_top.png', 700, 2400), ('qa_mid.png', 700, 2400), ('qa_tail.png', 700, 2400):
    pass

# 一页全长截取(window-size 高度给足);先例: headless=old 会被远程 CDN 图挂死,用 new+timeout=3500
cmd = [CHROME, '--headless=new', '--disable-gpu', '--user-data-dir=' + UD,
       '--window-size=700,7600', '--screenshot=' + OUT + '/qa_full.png',
       '--timeout=3500', '--virtual-time-budget=8000', SRC]
try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print('rc', p.returncode, p.stderr[-160:] if p.returncode else 'ok')
except subprocess.TimeoutExpired:
    print('outer 60s guard fired, continue if file exists')
sz = os.path.getsize(OUT + '/qa_full.png') if os.path.exists(OUT + '/qa_full.png') else 0
print('size', sz)
# 切三段
from PIL import Image
img = Image.open(OUT + '/qa_full.png')
W, H = img.size
print('full', W, H)
img.crop((0, 0, W, min(2500, H))).save(OUT + '/qa_top.png')
img.crop((0, min(2500, H) // 1 - 0, W, min(5000, H))).save(OUT + '/qa_mid.png') if H > 2600 else None
img.crop((0, max(0, H - 2600), W, H)).save(OUT + '/qa_tail.png')
print('slices saved')
