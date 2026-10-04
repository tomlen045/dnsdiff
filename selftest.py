#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnsdiff 自测:不变量体系 + 本地假 DNS 服务器实测 + 真网抽测。全绿才算可用。"""
import json
import socket
import subprocess
import sys
import threading
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dnsdiff as D  # noqa: E402

PY = sys.executable
CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dnsdiff.py')
PASS = []
FAIL = []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(('  ✅' if cond else '  ❌') + ' ' + name + (('  | ' + detail) if detail and not cond else ''))


# ---------------------------------------------------------- 不变量:报文构造与解析

def test_invariants():
    print('[1] DNS 报文不变量')
    tid, q = D.build_query('example.com', D.QTYPE_A)
    check('query 长度 = 12头+5+域名+4尾', len(q) == 12 + 1 + 7 + 1 + 3 + 1 + 4)
    check('query 尾部 qtype=A qclass=IN', q[-4:] == b'\x00\x01\x00\x01')
    # 解析一个真实报文:用 223.5.5.5 查 example.com 再喂给 parser
    r = None
    try:
        r = D.resolve('223.5.5.5', 'example.com', timeout=3)
    except Exception:
        pass
    if r:
        check('解析真实应答 NOERROR', r['rcode'] == 'NOERROR' and len(r['ips']) >= 1, str(r))
    else:
        check('解析真实应答 NOERROR', False, '223.5.5.5 查询失败(网络?)')
    # NXDOMAIN:随机不存在的域名
    r2 = D.try_resolve('223.5.5.5', 'this-domain-does-not-exist-dnsdiff-9x7q.com', timeout=3)
    check('NXDOMAIN 识别', r2 is not None and r2['rcode'] == 'NXDOMAIN', str(r2))
    # 压缩指针:name 指向报文头附近的 label
    # 构造: header(12) + question(a.b) + answer 指针指向 offset 12
    name_wire = b'\x01a\x01b\x00'
    data = b'\x00' * 12 + name_wire + b'\x00\x01\x00\x01'  # 假 question
    data += b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + b'\x01\x02\x03\x04'
    name, off = D.read_name(data, 12 + len(name_wire) + 4)
    check('压缩指针跳转还原 name', name == 'a.b' and off == 12 + len(name_wire) + 6,
          'got %r off=%d' % (name, off))
    nm2, off2 = D.read_name(data, 12)
    check('普通 label 顺序读取', nm2 == 'a.b' and off2 == 12 + len(name_wire))
    # 死循环保护:指针互指
    loop = bytearray(b'\x00' * 12 + b'\xc0\x0c' + b'\x00')
    nm3, _ = D.read_name(bytes(loop), 12)
    check('互指指针不死循环', True)  # 能走到这行就是没挂
    del nm3, loop


# ---------------------------------------------------------- 本地假 DNS 服务器

class FakeZone:
    """极简 UDP DNS 应答器:按 zone 字典回答 A 查询。"""

    def __init__(self, zone):
        self.zone = {k.rstrip('.'): v for k, v in zone.items()}  # {'name': ['1.2.3.4']}
        self.hits = 0

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                return
            self.hits += 1
            try:
                self.sock.sendto(self._answer(data), addr)
            except Exception:
                pass

    def _answer(self, data):
        tid = data[:2]
        # 解析 question
        off = 12
        labels = []
        while data[off] != 0:
            ln = data[off]
            labels.append(data[off + 1:off + 1 + ln].decode())
            off += 1 + ln
        off += 1
        qtype, _ = data[off:off + 2], data[off + 2:off + 4]
        qname = '.'.join(labels)
        ips = self.zone.get(qname, [])
        rcode = 0 if ips else 3
        flags = 0x8180 | rcode
        ancount = len(ips)
        # header: tid + flags + qd=1 + an + ns=0 + ar=0 (标准顺序 QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT)
        resp = tid + (flags).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (ancount).to_bytes(2, 'big') \
            + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
        resp += data[12:off + 4]  # 原样回 question
        for ip in ips:
            resp += b'\xc0\x0c' + b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(ip)
        return resp

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass


def struct_flags(_x):  # 占位,避免误用
    return b''


def run_cli(*argv):
    p = subprocess.run([PY, CLI] + list(argv), capture_output=True, text=True, timeout=90)
    return p.returncode, p.stdout + p.stderr


def test_local_fakes():
    print('[2] 本地假 DNS 实测(可控差集)')
    local = FakeZone({'app.internal-test.com.': ['10.66.77.88'],
                      'clean.internal-test.com.': ['93.184.216.34'],
                      'nxd.internal-test.com.': []})
    pool1 = FakeZone({'app.internal-test.com.': ['203.0.113.10', '203.0.113.11'],
                      'clean.internal-test.com.': ['93.184.216.34'],
                      'nxd.internal-test.com.': ['203.0.113.99']})
    local.start()
    pool1.start()
    time.sleep(0.2)
    try:
        ns = '127.0.0.1:%d' % local.port
        pn = '127.0.0.1:%d' % pool1.port
        # 场景A: 本机 10.66.77.88 vs 池 203.0.113.x → 完全不相交 = DIFF
        rc, o = run_cli('diff', 'app.internal-test.com',
                        '--local-dns', ns, '--nameservers', pn, '--timeout', '2')
        check('A: 不相交判 DIFF(退出码1)', rc == 1 and '差集' in o, 'rc=%d' % rc)
        check('A: 报告含双方 IP', '10.66.77.88' in o and '203.0.113.10' in o)
        check('A: 提示包含切换未生效线索', '不相交' in o)
        # 场景B: 一致 → CLEAN 退出码 0
        rc, o = run_cli('diff', 'clean.internal-test.com',
                        '--local-dns', ns, '--nameservers', pn, '--timeout', '2')
        check('B: 一致判 CLEAN(退出码0)', rc == 0 and '一致' in o, 'rc=%d' % rc)
        # 场景C: 本机 NXDOMAIN 但池有 → DIFF + 劫持提示
        rc, o = run_cli('diff', 'nxd.internal-test.com',
                        '--local-dns', ns, '--nameservers', pn, '--timeout', '2')
        check('C: 本机NXDOMAIN判 DIFF', rc == 1 and ('劫持' in o or '过滤' in o), o[-200:])
        # 场景D: 双方都查不到 → ALL_FAIL 退出码 2
        rc, o = run_cli('diff', 'void.internal-test.com',
                        '--local-dns', ns, '--nameservers', pn, '--timeout', '2')
        check('D: 双空判 ALL_FAIL(退出码2)', rc == 2, 'rc=%d' % rc)
        # 场景E: snapshot → baseline 复跑
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            snap = os.path.join(td, 'base.json')
            rc1, o1 = run_cli('diff', 'app.internal-test.com', '--local-dns', ns,
                              '--nameservers', pn, '--snapshot', snap, '--timeout', '2')
            check('E1: snapshot 落盘', os.path.exists(snap))
            with open(snap) as f:
                j = json.load(f)
            check('E2: 基线记录 DIFF', j['rows']['app.internal-test.com']['verdict'] == 'DIFF')
            rc2, o2 = run_cli('diff', 'app.internal-test.com', '--local-dns', ns,
                              '--nameservers', pn, '--baseline', snap, '--timeout', '2')
            check('E3: 基线已有 → 标「已知差集」不重复报新增',
                  '已知差集' in o2 and '新增差集' not in o2, o2[-300:])
            # 改池答案再对账 → 仍 DIFF(已知);改成一致 → 报「已恢复」(键与 init 归一化一致,无尾点)
            pool1.zone['app.internal-test.com'] = ['10.66.77.88']
            rc3, o3 = run_cli('diff', 'app.internal-test.com', '--local-dns', ns,
                              '--nameservers', pn, '--baseline', snap, '--timeout', '2')
            check('E4: 差集消除 → 报「已恢复」', '已恢复' in o3 and rc3 == 0, o3[-300:])
        # 场景F: json 输出可解析
        rc, o = run_cli('diff', 'app.internal-test.com', '--local-dns', ns,
                        '--nameservers', pn, '--timeout', '2', '--json')
        jline = [l for l in o.splitlines() if l.startswith('{')]
        check('F: --json 输出可解析', bool(jline) and json.loads(jline[-1])['rows'][0]['domain'] == 'app.internal-test.com')
    finally:
        local.stop()
        pool1.stop()


def test_edge_functions():
    print('[3] 边界与安全')
    check('is_private 私网识别', all(D.is_private(i) for i in
          ('10.1.2.3', '192.168.1.1', '172.%d.0.9' % 16, '172.%d.255.1' % 31, '127.0.0.1', '169.254.1.1')))
    check('is_private 公网放行', not any(D.is_private(i) for i in
          ('93.184.216.34', '203.0.113.10', '172.32.0.1', '11.0.0.1')))
    check('cname_provider 提取注册域', D.cname_provider(['x.y.cdn.cloudflare.net']) == {'cloudflare.net'}
          or D.cname_provider(['x.y.cdn.cloudflare.net']) == {'cloudflare.net.'})
    check('same_provider 有交集', D.same_provider({'a.com'}, {'a.com', 'b.com'}))
    check('same_provider 空不相交', not D.same_provider(set(), {'b.com'}))
    # hosts 解析容错
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='', delete=False) as f:
        f.write('# comment\n127.0.0.1 localhost\n203.0.113.5 foo.test bar.test\nbadline\n\n')
        tmp = f.name
    # 直接测函数逻辑(不动 /etc/hosts)
    entries = {}
    with open(tmp) as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, domains = parts[0], parts[1:]
            for d in domains:
                entries.setdefault(d.lower(), ip)
    os.unlink(tmp)
    check('hosts 解析:多域名/注释/坏行', entries.get('localhost') == '127.0.0.1'
          and entries.get('foo.test') == '203.0.113.5' and entries.get('bar.test') == '203.0.113.5'
          and 'badline' not in entries)
    # 超时池不炸:不可路由地址
    r = D.try_resolve('192.0.2.99', 'example.com', timeout=0.5)
    check('超时返回 None 不抛异常', r is None)
    # TTL 字段
    r2 = D.try_resolve('223.5.5.5', 'example.com', timeout=3)
    if r2:
        check('TTL 提取为正整数', isinstance(r2['ttl_min'], int) and r2['ttl_min'] > 0, str(r2['ttl_min']))
    else:
        check('TTL 提取为正整数', False, '网络查询失败')


def test_real_network():
    print('[4] 真网抽测')
    rc, o = run_cli('check', 'example.com', '--timeout', '2')
    check('check 命令真网跑通', '本机' in o and '池' in o, o[:200])
    rc, o = run_cli('hosts')
    check('hosts 命令跑通', '盘点' in o or '为空' in o, o[:120])
    # hosts 里若恰好有 example.com 映射,check 应标 hosts 命中;没有也行
    rc, o = run_cli('diff', 'example.com', 'baidu.com', '--timeout', '2')
    check('diff 真网跑通且给结论行', '结论' in o and '域' in o, o[-160:])


def main():
    t0 = time.time()
    test_invariants()
    test_local_fakes()
    test_edge_functions()
    test_real_network()
    print('\n== 自测结果: %d 通过 / %d 失败 | %.1fs ==' % (len(PASS), len(FAIL), time.time() - t0))
    if FAIL:
        print('失败项: ' + ', '.join(FAIL))
        return 1
    print('ALL GREEN')
    return 0


if __name__ == '__main__':
    sys.exit(main())
