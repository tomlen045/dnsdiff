#!/usr/bin/env python3
"""dnsdiff 证据图生成器 — 内容 100% 真实运行输出(2026-10-04 本机采集),排版是唯一创作。"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"
ORANGE = "#d19a66"

_fc = {}


def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]


def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·％—※' for ch in t)


def shot(name, lines, title="dnsdiff — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57")
    d.ellipse([44, 15, 56, 27], fill="#febc2e")
    d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 72
    for item in lines:
        # item: [(text,color,size,mono), ...] —— 每行一个列表,列表内多段混排
        if not isinstance(item, list):
            item = [item]
        size = item[0][2]
        mono = item[0][3]
        x = 56
        for text, color, _sz, _mn in item:
            font = F(size, mono and not has_cjk(text))
            d.text((x, y), text, font=font, fill=color)
            x += d.textlength(text, font=font)
        y += int(size * 1.8)
    img.save(os.path.join(OUT, name + ".png"))
    print(name, "OK")


# ── ① 三方对账主场景(真实运行:2026-10-04) ──
shot("01_diff", [
    [("$ python3 dnsdiff.py diff twitter.com github.com", WHITE, 22, True)],
    [("本机 resolver: 192.168.50.1 | 公共池: 223.5.5.5 119.29.29.29 8.8.8.8", GREY, 19, True)],
    [("", WHITE, 8, True)],
    [("[", RED, 22, True), ("差集", RED, 22, False), ("] twitter.com", RED, 22, True)],
    [("  本机      : ", WHITE, 22, True), ("157.240.7.20", RED, 22, True)],
    [("  池 223.5.5.5    : 174.132.167.252", WHITE, 22, True)],
    [("  多数派    : 174.132.167.252", GOLD, 22, True)],
    [("  ※ 答案完全不相交:hosts 残留 / 劫持 / 污染", GREY, 19, False)],
    [("", WHITE, 8, True)],
    [("[", GREEN, 22, True), ("一致", GREEN, 22, False), ("] github.com", GREEN, 22, True)],
    [("  本机 20.205.243.166 = 多数派", WHITE, 22, True)],
    [("", WHITE, 8, True)],
    [("== 结论: 2 域 | 差集 1 | 一致 1 | 全部失败 0 ==", WHITE, 22, True)],
])

# ── ② hosts 盘点(真实输出,深信服 VPN 条目在列) ──
shot("02_hosts", [
    [("$ python3 dnsdiff.py hosts", WHITE, 22, True)],
    [("== /etc/hosts 盘点: 5 条 ==", WHITE, 22, True)],
    [("  windows-11.shared        → 10.211.55.6      ", WHITE, 22, True), ("(私网)", ORANGE, 22, True)],
    [("  localhost.sangfor.com.cn → 127.0.0.1        ", WHITE, 22, True), ("(私网)", ORANGE, 22, True)],
    [("  broadcasthost            → 255.255.255.255", WHITE, 22, True)],
    [("", WHITE, 8, True)],
    [("※ 4 条私网映射:本机把域名写死在内网", GREY, 20, False)],
    [("  换网环境后,这类条目就是「打不开」元凶", GREY, 20, False)],
])

# ── ③ 单域快查 + CDN 去噪(真实输出) ──
shot("03_check", [
    [("$ python3 dnsdiff.py check www.apple.com", WHITE, 22, True)],
    [("  本机 192.168.50.1 → 14.215.172.33, 14.29.48.31, +10 more", WHITE, 21, True)],
    [("    ←CNAME www-apple-com.v.aaplimg.com", BLUE, 21, True)],
    [("        → www.apple.com.w.cdngslb.com", BLUE, 21, True)],
    [("  TTL: 12s ", WHITE, 21, True), ("(超短,动态解析)", ORANGE, 21, True)],
    [("  池   223.5.5.5      → 163.177.116.1", WHITE, 21, True)],
    [("  池   119.29.29.29   → 163.177.116.1", WHITE, 21, True)],
    [("  池   8.8.8.8        → 23.197.225.61", WHITE, 21, True)],
    [("", WHITE, 8, True)],
    [("※ 同一 CDN 不同边缘 = 地域调度,", GREY, 20, False), ("不是劫持,别瞎排查", GREY, 20, False)],
])

# ── ④ 自测全绿(29/29 真实结果) ──
shot("04_selftest", [
    [("$ python3 selftest.py", WHITE, 22, True)],
    [("[1] DNS 报文不变量(构造/解析/压缩指针/互指保护)", GREY, 20, False)],
    [("[2] 本地假 DNS 服务器实测(可控差集场景)", GREY, 20, False)],
    [("  [PASS] A: 不相交判 DIFF(退出码1)", GREEN, 21, True)],
    [("  [PASS] B: 一致判 CLEAN(退出码0)", GREEN, 21, True)],
    [("  [PASS] C: 本机 NXDOMAIN 判劫持嫌疑", GREEN, 21, True)],
    [("  [PASS] E4: 差集消除 → 报「已恢复」", GREEN, 21, True)],
    [("[4] 真网抽测(example.com / baidu.com)", GREY, 20, False)],
    [("", WHITE, 8, True)],
    [("== 自测结果: 29 通过 / 0 失败 ==", WHITE, 24, True)],
    [("ALL GREEN", GREEN, 24, True)],
], title="dnsdiff-selftest — zsh")

print("done:", len(os.listdir(OUT)), "shots")
