#!/usr/bin/env python3
"""复核 GitHub topics 与双仓最终状态。"""
import json
import urllib.request

with urllib.request.urlopen('https://api.github.com/repos/tomlen045/dnsdiff', timeout=15) as r:
    j = json.loads(r.read())
print('github topics:', j.get('topics'))
print('github default_branch:', j.get('default_branch'), '| private:', j.get('private'))
