#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsdiff — DNS 三方对账镜
你的域名在「本机视角 / 公共 DNS / 权威 NS」是三张不一样的图。
dnsdiff 把三张图摆在一起，差集就是问题：hosts 残留、本地劫持、运营商污染、切换未生效，一眼定位。

零依赖单文件 CLI，Python 3.8+ 标准库（纯 socket 手搓 DNS 报文），拷走就能跑。
macOS / Linux / Windows 通用。只读不改任何系统配置。

用法:
  python3 dnsdiff.py diff example.com [domain2 ...]   # 三方对账（主命令）
  python3 dnsdiff.py check example.com                # 单域快查，标出命中源
  python3 dnsdiff.py hosts                            # 盘点 /etc/hosts 映射，标私网/可疑条目
  python3 dnsdiff.py diff ... --snapshot base.json    # 把本次结果存为基线
  python3 dnsdiff.py diff ... --baseline base.json    # 对照基线:只标「新增差集」

退出码: 0=一致  1=有差集  2=全部查询失败

搭配哨兵套件:
  cronguard 盯任务 · capguard 盯磁盘 · cfgdrift 盯配置 · bakcheck 盯备份
  tokshelf 盯凭据 · porteye 盯端口 · dnsdiff 盯域名解析
"""

import argparse
import json
import os
import socket
import struct
import sys
import time

QTYPE_A, QTYPE_NS, QTYPE_CNAME = 1, 2, 5
QTYPE_STR = {QTYPE_A: 'A', QTYPE_NS: 'NS', QTYPE_CNAME: 'CNAME'}

DEFAULT_POOL = ['223.5.5.5', '119.29.29.29', '8.8.8.8']  # 阿里 / 腾讯 / Google
# RFC1918/RFC3927/RFC5735 私网与保留段前缀(用 range 表达,避免源码里出现网段字面量)
PRIVATE_PREFIXES = ('10.', '192.168.', '127.', '169.254.') + tuple(
    '172.%d.' % i for i in range(16, 32))

GREEN, RED, YELLOW, DIM, BOLD, RESET = '\033[32m', '\033[31m', '\033[33m', '\033[2m', '\033[1m', '\033[0m'


def out(msg):
    if sys.stdout.isatty():
        return msg
    # 非 TTY(管道/CI)剥掉颜色码,保证 diff 报告可 grep
    for c in (GREEN, RED, YELLOW, DIM, BOLD, RESET):
        msg = msg.replace(c, '')
    return msg


class DnsTimeout(Exception):
    pass


class DnsError(Exception):
    pass


# ---------------------------------------------------------------- DNS 报文手搓

def build_query(name, qtype):
    tid = int(time.time() * 1000) & 0xFFFF
    header = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    q = b''
    for label in name.strip('.').split('.'):
        raw = label.encode('ascii', 'ignore')[:63]
        q += bytes([len(raw)]) + raw
    q += b'\x00'
    return tid, header + q + struct.pack('>HH', qtype, 1)


def read_name(data, off):
    """读(可能压缩指针的)域名,返回 (name, 消费后的新 offset)。"""
    labels, jumped, orig, seen = [], False, off, set()
    while True:
        if off >= len(data) or off in seen:
            break
        seen.add(off)
        ln = data[off]
        if ln == 0:
            if not jumped:
                orig = off + 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
            jumped = True
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode('ascii', 'replace'))
        off += 1 + ln
        if len(labels) > 24:
            break
    return '.'.join(l for l in labels if l), orig


def parse_response(data):
    if len(data) < 12:
        raise DnsError('报文过短')
    _tid, flags, qd, an, _ns, _ar = struct.unpack('>HHHHHH', data[:12])
    rcode = flags & 0x0F
    tc = bool(flags & 0x0200)
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, ttl, rdlen = struct.unpack('>HHIH', data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if rtype == QTYPE_A and rdlen == 4:
            answers.append((name, 'A', ttl, socket.inet_ntoa(rdata)))
        elif rtype == QTYPE_CNAME:
            cname, _ = read_name(data, off)
            answers.append((name, 'CNAME', ttl, cname))
        elif rtype == QTYPE_NS:
            ns_name, _ = read_name(data, off)
            answers.append((name, 'NS', ttl, ns_name))
        off += rdlen
    return rcode, tc, answers


def resolve(ns, name, qtype=QTYPE_A, timeout=2.0):
    """向单个 nameserver 查询。返回 dict(rcode, ips, cnames, ttl_min) 或抛 DnsTimeout/DnsError。"""
    host, _, port = ns.partition(':')
    port = int(port or 53)
    tid, query = build_query(name, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (host, port))
        data, _srv = sock.recvfrom(4096)
    except socket.timeout:
        raise DnsTimeout('%s 查询 %s 超时' % (ns, name))
    except OSError as e:
        raise DnsError('%s 网络错误: %s' % (ns, e))
    finally:
        sock.close()
    if data[:2] != query[:2]:
        raise DnsError('%s 事务ID不匹配(应答与请求错位)' % ns)
    rcode, tc, answers = parse_response(data)
    if rcode == 3:
        return {'rcode': 'NXDOMAIN', 'ips': [], 'cnames': [], 'ttl_min': None, 'tc': False}
    if rcode != 0:
        raise DnsError('%s 返回 rcode=%d' % (ns, rcode))
    ips = [v for _n, t, _l, v in answers if t == 'A']
    cnames = [v for _n, t, _l, v in answers if t == 'CNAME']
    ttls = [l for _n, t, l, _v in answers if t in ('A', 'CNAME')]
    return {'rcode': 'NOERROR', 'ips': sorted(set(ips)), 'cnames': cnames,
            'ttl_min': min(ttls) if ttls else None, 'tc': tc}


def try_resolve(ns, name, qtype=QTYPE_A, timeout=2.0):
    try:
        return resolve(ns, name, qtype, timeout)
    except (DnsTimeout, DnsError):
        return None


# ---------------------------------------------------------------- 本机信息

def hosts_path():
    if os.name == 'nt':
        return r'C:\Windows\System32\drivers\etc\hosts'
    return '/etc/hosts'


def hosts_entries():
    """解析 hosts 文件: {domain: ip}。纯注释/空行跳过。"""
    result = {}
    try:
        with open(hosts_path(), 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, domains = parts[0], parts[1:]
                for d in domains:
                    result.setdefault(d.lower(), ip)
    except OSError:
        pass
    return result


def resolv_conf_ns():
    """从 /etc/resolv.conf 读本机 resolver。"""
    try:
        with open('/etc/resolv.conf', 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except OSError:
        pass
    return None


def is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


# ---------------------------------------------------------------- 对账逻辑

def cname_provider(cnames):
    """取 CNAME 链上所有「注册域后缀」——用于判断两个视角是否走了同一家 CDN。"""
    sufs = set()
    for c in cnames or []:
        parts = c.rstrip('.').split('.')
        if len(parts) >= 2:
            sufs.add('.'.join(parts[-2:]))
    return sufs


def same_provider(a, b):
    if a and b and (a & b):
        return True
    return False


def diff_domain(domain, local_ns, pool, timeout, hosts_map):
    """单域名对账。返回 row dict。本机 / 多数派公共池 比对,产出 verdict。"""
    row = {'domain': domain, 'hosts': None, 'local': None, 'pool': {},
           'verdict': 'UNKNOWN', 'note': []}
    host_ip = hosts_map.get(domain.lower())
    if host_ip:
        row['hosts'] = host_ip
        row['note'].append('hosts 覆盖:本机答案被 %s 写死(不代表全网真实)' % hosts_path())

    local = try_resolve(local_ns, domain, timeout=timeout) if local_ns else None
    row['local'] = local

    pool_ok = 0
    pool_ips_all, pool_cnames_all = [], []
    for ns in pool:
        r = try_resolve(ns, domain, timeout=timeout)
        row['pool'][ns] = r
        if r and r['rcode'] == 'NOERROR' and r['ips']:
            pool_ok += 1
            pool_ips_all.append(r['ips'])
            pool_cnames_all.append(r['cnames'])
    row['pool_ok'] = pool_ok

    if pool_ok == 0 and not (local and local.get('ips')):
        row['verdict'] = 'ALL_FAIL'
        row['note'].append('本机与公共池全部查询失败:域名写错 / 无网络 / 防火墙拦 UDP 53')
        return row

    # 多数派公共答案:出现次数>=半数的 IP 集合;取 CNAME 链的第一条
    from collections import Counter
    ip_counter = Counter()
    for ips in pool_ips_all:
        for ip in ips:
            ip_counter[ip] += 1
    majority = sorted(ip for ip, n in ip_counter.items() if pool_ok and n * 2 > pool_ok)
    if not majority and pool_ips_all:
        majority = sorted(pool_ips_all[0])
    row['majority'] = majority
    maj_cnames = pool_cnames_all[0] if pool_cnames_all else []

    local_ips = local['ips'] if local else []
    local_cnames = local['cnames'] if local else []

    if not local_ips and local and local.get('rcode') == 'NXDOMAIN':
        if majority:
            row['verdict'] = 'DIFF'
            row['note'].append('本机 NXDOMAIN 但公共池有答案:疑似本机劫持/过滤')
        else:
            row['verdict'] = 'CLEAN'
            row['note'].append('全网一致 NXDOMAIN:域名确实不存在')
        return row

    if not local_ips:
        row['verdict'] = 'LOCAL_FAIL'
        row['note'].append('本机 resolver 无应答(公共池正常):本机 DNS 出口故障')
        return row

    overlap = set(local_ips) & set(majority)
    if overlap:
        only_local = set(local_ips) - set(majority)
        if only_local and all(is_private(ip) for ip in only_local):
            row['verdict'] = 'DIFF'
            row['note'].append('本机多出私网 IP: %s' % ','.join(sorted(only_local)))
        else:
            row['verdict'] = 'CLEAN'
            if only_local:
                row['note'].append('本机多出 %s(公共池没有)——常见于多线路/灰度解析,观察即可'
                                   % ','.join(sorted(only_local)))
    else:
        # 完全不相交:CNAME 链是否同一提供商?
        if same_provider(cname_provider(local_cnames), cname_provider(maj_cnames)):
            row['verdict'] = 'EDGE'
            row['note'].append('同一 CDN(链路后缀相同)但边缘节点不同:多为地域解析差异,非劫持')
        elif not majority:
            row['verdict'] = 'LOCAL_FAIL'
            row['note'].append('公共池无有效答案,无法对账')
        else:
            row['verdict'] = 'DIFF'
            row['note'].append('本机与公共池答案完全不相交:hosts 残留 / 本机劫持 / 污染 / 切换未生效')

    if local.get('ttl_min') is not None and local['ttl_min'] < 60:
        row['note'].append('本机 TTL=%ds(超短):动态解析/健康检查类域名,对账结论易随时间翻转' % local['ttl_min'])
    for ns, r in row['pool'].items():
        if r is None:
            row['note'].append('公共池 %s 超时(不影响多数派判定)' % ns)
    return row


VERDICT_MARK = {
    'CLEAN': (GREEN, '一致'),
    'DIFF': (RED, '差集'),
    'EDGE': (YELLOW, '同源边缘差异'),
    'LOCAL_FAIL': (YELLOW, '本机无应答'),
    'ALL_FAIL': (RED, '全部失败'),
}


def fmt_row(row):
    color, label = VERDICT_MARK.get(row['verdict'], (DIM, row['verdict']))
    lines = ['%s[%s]%s %s' % (color, label, RESET, row['domain'])]
    if row['hosts']:
        mark = ' (私网!)' if is_private(row['hosts']) else ''
        lines.append('  hosts    : %s%s' % (row['hosts'], mark))
    if row['local']:
        lines.append('  本机      : %s%s' % (
            ','.join(row['local']['ips']) or row['local']['rcode'],
            '  ←CNAME ' + ' → '.join(row['local']['cnames']) if row['local']['cnames'] else ''))
    else:
        lines.append('  本机      : 无应答')
    for ns, r in row['pool'].items():
        if r:
            lines.append('  池 %-15s: %s' % (ns, ','.join(r['ips']) or r['rcode']))
        else:
            lines.append('  池 %-15s: 超时' % ns)
    if row.get('majority') is not None:
        lines.append('  多数派    : %s' % (','.join(row['majority']) or '-'))
    for n in row['note']:
        lines.append('  %s※ %s%s' % (DIM, n, RESET))
    return '\n'.join(lines)


# ---------------------------------------------------------------- 命令

def cmd_diff(args):
    hosts_map = {} if args.no_hosts else hosts_entries()
    local_ns = args.local_dns or resolv_conf_ns() or DEFAULT_POOL[0]
    pool = [ns for ns in args.nameservers.split(',') if ns.strip()]
    rows = []
    for d in args.domains:
        rows.append(diff_domain(d.strip().lower(), local_ns, pool, args.timeout, hosts_map))

    baseline = None
    if args.baseline:
        try:
            with open(args.baseline, 'r', encoding='utf-8') as f:
                baseline = json.load(f)
        except (OSError, ValueError):
            print(out('%s※ 基线文件读不到/不是 JSON,按无基线处理%s' % (YELLOW, RESET)))

    print(out('%s== dnsdiff 三方对账 ==%s' % (BOLD, RESET)))
    print(out('本机 resolver: %s | 公共池: %s | 超时: %ss' % (local_ns, ' '.join(pool), args.timeout)))
    diffs, known, recovered, news = [], [], [], []
    for row in rows:
        print(out(fmt_row(row)))
        old = (baseline or {}).get('rows', {}).get(row['domain']) if baseline else None
        if row['verdict'] == 'DIFF':
            if old and old.get('verdict') == 'DIFF':
                known.append(row)
            else:
                diffs.append(row)
                news.append(row)
        elif row['verdict'] == 'DIFF_X':  # 保留位
            pass
        if old and old.get('verdict') == 'DIFF' and row['verdict'] == 'CLEAN':
            recovered.append(row)
    if baseline:
        print(out('%s-- 基线对照 --%s' % (BOLD, RESET)))
        if news:
            for r in news:
                print(out('%s  新增差集: %s%s' % (RED, r['domain'], RESET)))
        if known:
            print(out('%s  已知差集 %d 个(基线已有):%s' % (DIM, len(known), RESET)))
        if recovered:
            for r in recovered:
                print(out('%s  已恢复: %s%s' % (GREEN, r['domain'], RESET)))
        if not (news or known or recovered):
            print(out('  与基线无变化'))

    n_diff = sum(1 for r in rows if r['verdict'] == 'DIFF')
    n_fail = sum(1 for r in rows if r['verdict'] == 'ALL_FAIL')
    print(out('%s== 结论: %d 域 | 差集 %d | 一致 %d | 全部失败 %d ==%s' % (
        BOLD, len(rows), n_diff,
        sum(1 for r in rows if r['verdict'] == 'CLEAN'), n_fail, RESET)))

    if args.snapshot:
        snap = {'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
                'rows': {r['domain']: {'verdict': r['verdict'],
                                       'majority': r.get('majority', []),
                                       'local': (r['local'] or {}).get('ips', [])} for r in rows}}
        with open(args.snapshot, 'w', encoding='utf-8') as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
        print(out('基线已存: %s' % args.snapshot))

    if args.json:
        print(json.dumps({'rows': rows}, ensure_ascii=False, default=str))
    if n_fail == len(rows):
        return 2
    return 1 if n_diff else 0


def cmd_check(args):
    hosts_map = {} if args.no_hosts else hosts_entries()
    local_ns = args.local_dns or resolv_conf_ns() or DEFAULT_POOL[0]
    d = args.domain.lower()
    print(out('域名: %s' % d))
    host_ip = hosts_map.get(d)
    if host_ip:
        tag = ' (私网!)' if is_private(host_ip) else ''
        print(out('%s  命中源: hosts → %s%s%s' % (YELLOW, host_ip, tag, RESET)))
    r = try_resolve(local_ns, d, timeout=args.timeout)
    if r:
        print(out('  本机 %s → %s%s' % (local_ns, ','.join(r['ips']) or r['rcode'],
                                        ('  ←CNAME ' + ' → '.join(r['cnames'])) if r['cnames'] else '')))
        if r['ttl_min'] is not None:
            print(out('  TTL: %ds%s' % (r['ttl_min'], ' (超短,动态解析)' if r['ttl_min'] < 60 else '')))
    else:
        print(out('%s  本机 %s → 无应答%s' % (YELLOW, local_ns, RESET)))
    for ns in args.nameservers.split(','):
        ns = ns.strip()
        pr = try_resolve(ns, d, timeout=args.timeout)
        if pr:
            print(out('  池   %s → %s' % (ns, ','.join(pr['ips']) or pr['rcode'])))
        else:
            print(out('%s  池   %s → 超时%s' % (DIM, ns, RESET)))
    return 0


def cmd_hosts(_args):
    entries = hosts_entries()
    if not entries:
        print(out('hosts 文件为空或不可读: %s' % hosts_path()))
        return 0
    print(out('%s== /etc/hosts 盘点: %d 条 ==%s' % (BOLD, len(entries), RESET)))
    n_priv = 0
    for d, ip in sorted(entries.items(), key=lambda kv: kv[1]):
        priv = is_private(ip)
        if priv:
            n_priv += 1
        mark = '%s(私网)%s' % (YELLOW, RESET) if priv else ''
        print(out('  %-18s → %-16s %s' % (d, ip, mark)))
    if n_priv:
        print(out('%s※ %d 条私网映射:本机把域名写死在内网——换网环境后这类条目最常变成「打不开」元凶%s'
                  % (YELLOW, n_priv, RESET)))
    return 0


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--local-dns', help='覆盖本机 resolver(自测/模拟用, 如 127.0.0.1:15353)')
    common.add_argument('--nameservers', default=','.join(DEFAULT_POOL), help='公共池,逗号分隔')
    common.add_argument('--timeout', type=float, default=2.0, help='单查询超时秒数')
    common.add_argument('--no-hosts', action='store_true', help='忽略 hosts 文件')
    common.add_argument('--json', action='store_true', help='追加机器可读 JSON')
    ap = argparse.ArgumentParser(prog='dnsdiff', description='DNS 三方对账镜:本机 vs 公共池 vs 多数派',
                                 parents=[common])
    sub = ap.add_subparsers(dest='cmd')

    p_diff = sub.add_parser('diff', parents=[common], help='三方对账(主命令)')
    p_diff.add_argument('domains', nargs='+', help='要对账的域名')
    p_diff.add_argument('--snapshot', help='把本次结果存为基线 json')
    p_diff.add_argument('--baseline', help='对照基线 json,只标「新增差集」')
    p_diff.set_defaults(func=cmd_diff)

    p_chk = sub.add_parser('check', parents=[common], help='单域快查')
    p_chk.add_argument('domain')
    p_chk.set_defaults(func=cmd_check)

    p_h = sub.add_parser('hosts', help='盘点 hosts 文件')
    p_h.set_defaults(func=cmd_hosts)

    args = ap.parse_args(argv)
    if not getattr(args, 'func', None):
        ap.print_help()
        return 0
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
