#!/usr/bin/env python3
"""dnsdiff 双仓发布:Gitee(push先→PATCH公开→读回) + GitHub(建仓→ssh443 push→topics→读回)。"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = '/Users/len/CodeBuddy/dx/dnsdiff'
GITEE_USER, GH_USER = 'tomlen', 'tomlen045'
GITEE_TOK = open('/tmp/dnsdiff_gitee_token.txt').read().split('\n')[1].strip()


def sh(args, env=None, timeout=120):
    e = dict(os.environ)
    e['GIT_TERMINAL_PROMPT'] = '0'
    if env:
        e.update(env)
    p = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, env=e, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def http(method, url, token=None, data=None, is_json=False):
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header('Authorization', 'token ' + token)
    body = None
    if data is not None:
        body = json.dumps(data).encode() if is_json else urllib.parse.urlencode(data).encode()
        if not is_json:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        else:
            req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, data=body, timeout=20) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


results = []

# ---------- 0. git 仓库准备 ----------
if not os.path.isdir(ROOT + '/.git'):
    print('init:', sh(['git', 'init', '-b', 'main'])[0])
for f in ('dnsdiff.py', 'selftest.py', 'README.md', 'README_EN.md', 'LICENSE', '.gitignore'):
    if os.path.exists(ROOT + '/' + f):
        sh(['git', 'add', f])
sh(['git', 'add', 'shots'])
_rc, st_out = sh(['git', 'status', '--porcelain'])
if st_out.strip():
    sh(['git', 'config', 'user.email', 'tomlen045@users.noreply.github.com'])
    sh(['git', 'config', 'user.name', 'tomlen'])
    rc, o = sh(['git', 'commit', '-m', 'dnsdiff v1.0.0: DNS 三方对账镜(本机/公共池/多数派), 29/29 自测全绿'])
    print('commit:', rc, o[-120:])
else:
    print('commit: 无变更')
_rc, tracked = sh(['git', 'ls-files'])
print('tracked files:', len(tracked.splitlines()))
if len(tracked.splitlines()) == 0:
    print('WARNING: nothing tracked, re-adding')
    print(sh(['git', 'add', '-A', '--force', '.']))

# ---------- 0.5 敏感扫描(仓内 tracked 文件) ----------
bad = []
for line in tracked.splitlines():
    try:
        txt = open(os.path.join(ROOT, line), encoding='utf-8', errors='replace').read()
    except OSError:
        continue
    for pat in ('172.16.', '172.18.', '10.92.', 'gitee.com/', 'ghp_', 'ghp_', 'access_token='):
        if pat in txt:
            bad.append((line, pat))
print('sensitive scan:', 'CLEAN' if not bad else bad)
if bad:
    sys.exit('SENSITIVE HIT, ABORT')

# ---------- 1. Gitee 建仓 ----------
code, body = http('POST', 'https://gitee.com/api/v5/user/repos',
                  data={'access_token': GITEE_TOK, 'name': 'dnsdiff',
                        'description': 'DNS 三方对账镜: 本机视角/公共DNS/多数派, 差集即问题。零依赖单文件 CLI',
                        'private': 'true', 'has_issues': 'true', 'auto_init': 'false'})
print('gitee create:', code)
if code not in (201, 400, 422):  # 400/422=已存在
    print(body[:300])
    sys.exit('gitee create failed')

# ---------- 2. push Gitee ----------
rc, o = sh(['git', 'remote', 'remove', 'gitee'])
rc, o = sh(['git', 'remote', 'add', 'gitee',
            'https://%s:%s@gitee.com/%s/dnsdiff.git' % (GITEE_USER, GITEE_TOK, GITEE_USER)])
rc, o = sh(['git', 'push', '-u', 'gitee', 'main'], timeout=180)
print('gitee push:', rc, o[-160:])
if rc != 0:
    sys.exit('gitee push failed')

# ---------- 3. PATCH 置公开 + GET 复核 ----------
for attempt in range(3):
    code, body = http('PATCH', 'https://gitee.com/api/v5/repos/%s/dnsdiff' % GITEE_USER,
                      data={'access_token': GITEE_TOK, 'name': 'dnsdiff', 'private': 'false'})
    print('gitee patch public try%d:' % (attempt + 1), code)
    if code == 200:
        break
import time as _t
_t.sleep(2)
code, body = http('GET', 'https://gitee.com/api/v5/repos/%s/dnsdiff?access_token=%s' % (GITEE_USER, GITEE_TOK))
priv = json.loads(body).get('private') if code == 200 else None
print('gitee private field:', priv, '(False=公开)')
results.append(('gitee public', priv is False))

# ---------- 4. GitHub 建仓 ----------
gh_tok = subprocess.run(['security', 'find-generic-password', '-s', 'GH_TOKEN', '-a', 'tomlen045', '-w'],
                        capture_output=True, text=True).stdout.strip()
code, body = http('POST', 'https://api.github.com/user/repos', token=gh_tok, is_json=True,
                  data={'name': 'dnsdiff', 'private': False,
                        'description': 'DNS three-way reconciler: local view vs public resolvers vs majority. Zero-dep single-file CLI. DNS 三方对账镜'})
print('github create:', code)
if code not in (201, 422):
    print(body[:300])
    if code != 422:
        sys.exit('github create failed')

# ---------- 5. push GitHub (ssh 443 绕 ghproxy) ----------
rc, o = sh(['git', 'remote', 'remove', 'github'])
rc, o = sh(['git', 'remote', 'add', 'github', 'git@ssh.github.com:%s/dnsdiff.git' % GH_USER])
ssh_env = {'GIT_SSH_COMMAND': 'ssh -p 443 -i ~/.ssh/id_ed25519_github -o StrictHostKeyChecking=accept-new'}
rc, o = sh(['git', 'push', '-u', 'github', 'main'], env=ssh_env, timeout=180)
print('github push:', rc, o[-160:])
results.append(('github push', rc == 0))

# ---------- 6. topics ----------
code, body = http('PUT', 'https://api.github.com/repos/%s/dnsdiff/topics' % GH_USER, token=gh_tok, is_json=True,
                  data={'names': ['dns', 'network-diagnostics', 'cli', 'security', 'sre', 'devsecops', 'zero-dependency']})
print('github topics:', code)
results.append(('topics', code == 204))

# ---------- 7. 匿名读回验证 ----------
code, _b = http('GET', 'https://gitee.com/api/v5/repos/%s/dnsdiff' % GITEE_USER)
print('gitee anon API:', code)
code2, _b2 = http('GET', 'https://gitee.com/%s/dnsdiff/raw/main/README.md' % GITEE_USER)
print('gitee raw README:', code2)
results.append(('gitee readback', code == 200 and code2 == 200))
code3, _b3 = http('GET', 'https://api.github.com/repos/%s/dnsdiff' % GH_USER)
print('github anon API:', code3)
code4, _b4 = http('GET', 'https://gcore.jsdelivr.net/gh/%s/dnsdiff@main/README.md' % GH_USER)
print('github raw via jsdelivr:', code4)
results.append(('github readback', code3 == 200 and code4 == 200))

print('\n== PUBLISH SUMMARY ==')
ok = True
for name, good in results:
    print(('  ✅' if good else '  ❌'), name)
    ok = ok and good
print('ALL OK' if ok else 'HAS FAILURES')
