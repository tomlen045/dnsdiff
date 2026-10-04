# dnsdiff

[简体中文](README.md) | [English](README_EN.md)

> **DNS 三方对账镜** — 你的域名在「本机视角 / 公共 DNS / 多数派」是三张不一样的图，差集就是问题。
> 打不开一个网站时，99% 的排查都卡在「到底是哪一层出了错」——dnsdiff 把三层答案摆到一张桌子上。

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.8%2B-informational)]() [![deps](https://img.shields.io/badge/dependencies-zero-success)]()

## 它解决什么问题

这些场景你一定遇到过：

- 网站打不开，同事那边却好好的——是 hosts 残留？运营商污染？还是 CDN 抽风？
- 改了域名解析，等了半天「还没生效」——到底是没生效，还是只有你自己的电脑没生效？
- 杀毒软件/代理/公司安全网关偷偷劫持了解析，你毫无感知
- /etc/hosts 里躺着一堆历史遗留条目，某天换了个网络环境全变成「打不开」

`ping` 只告诉你通不通，`nslookup` 只给你一个视角的答案。**单视角永远查不出「本机 vs 全网」的差异**——这正是这类故障的病根。

dnsdiff 的对账逻辑：

| 视角 | 来源 | 语义 |
|---|---|---|
| **本机视角** | 系统 resolver（resolv.conf 自动探测，可覆盖） | 「你的电脑**实际**拿到什么答案」 |
| **公共池** | 阿里 223.5.5.5 / 腾讯 119.29.29.29 / Google 8.8.8.8 | 「全网**应该**是什么答案」 |
| **多数派** | 公共池中出现次数过半的答案 | 「可信基线」——单家公共 DNS 也会错 |

每次对账给出五类裁决：

| 裁决 | 含义 | 常见原因 |
|---|---|---|
| **一致** | 本机 = 多数派 | 健康 |
| **差集** | 本机与多数派完全不相交 | hosts 残留 / 本机劫持 / 污染 / 解析切换未生效 |
| **同源边缘差异** | 同一 CDN 但边缘节点不同 | 地域解析（GSLB），非劫持 |
| **本机无应答** | 本机 resolver 不响应 | 本机 DNS 出口故障 |
| **全部失败** | 三层都没答案 | 域名写错 / 无网络 / 防火墙拦 UDP 53 |

## 快速开始

零依赖，Python 3.8+ 标准库（纯 socket 手搓 DNS 报文），单文件，拷走就能跑。

```bash
# 三方对账(主命令): 本机 vs 公共池,一屏看清谁在撒谎
python3 dnsdiff.py diff example.com twitter.com

# 单域快查: 标出命中源(hosts / 本机 / 池)和 TTL
python3 dnsdiff.py check www.apple.com

# 盘点 /etc/hosts: 标私网映射,换网环境「打不开」的头号元凶
python3 dnsdiff.py hosts
```

解析迁移 / 切换场景（先存基线，再对账）：

```bash
# 切换前存基线
python3 dnsdiff.py diff api.example.com --snapshot base.json

# 切换后对账: 只标「新增差集」,已恢复的域单独列出
python3 dnsdiff.py diff api.example.com --baseline base.json
```

退出码即结论，可直接接 cron / CI：

| 退出码 | 含义 |
|---|---|
| 0 | 三方一致 |
| 1 | 有差集（本机视角与全网不符） |
| 2 | 全部查询失败（域名/网络问题） |

## 输出长什么样

真实案例（本机 resolver = 路由器 192.168.x.1）：

```text
== dnsdiff 三方对账 ==
[差集] twitter.com
  本机      : 157.240.7.20          ← Facebook 网段,典型的 DNS 污染
  池 223.5.5.5      : 174.132.167.252
  池 119.29.29.29   : 174.132.167.252
  多数派    : 174.132.167.252
  ※ 本机与公共池答案完全不相交:hosts 残留 / 本机劫持 / 污染 / 切换未生效
[同源边缘差异] www.apple.com
  本机      : 14.215.172.33,... ←CNAME www-apple-com.v.aaplimg.com → www.apple.com.w.cdngslb.com
  多数派    : 163.177.116.1
  ※ 同一 CDN(链路后缀相同)但边缘节点不同:多为地域解析差异,非劫持
[一致] github.com
  本机      : 20.205.243.166
  多数派    : 20.205.243.166
== 结论: 3 域 | 差集 1 | 一致 1 | 全部失败 0 ==
```

一眼读懂：github 是好的，apple 是 CDN 地域调度（别瞎排查），twitter 是污染（本机拿到的是 Facebook 的 IP）。

## 设计不变量

1. **零依赖**——Python 3.8+ 标准库，DNS 报文手搓（构造/解析/压缩指针还原），不装任何包
2. **只读**——绝不改系统任何配置，hosts / resolv.conf 只读不写
3. **多数派裁决**——不信单一家公共 DNS（它自己也会错/被污染），三个里取「出现次数过半」的答案
4. **TTL 诚实提示**——本机 TTL < 60s 时明确标注「动态解析，结论易翻转」，不给你假装稳定的结论
5. **CDN 去噪**——本机与池答案不相交但 CNAME 链同源时，判「同源边缘差异」而不是误报劫持
6. **退出码语义化**——对账结论就是 shell 的退出码，cron/CI 直接用
7. **TTY 感知**——管道/重定向时自动剥颜色码，报告可以放心 grep

## 搭配哨兵套件

dnsdiff 是哨兵套件的 DNS 视角，与已有工具互不重叠：

- [cronguard](https://github.com/tomlen045/cronguard) 盯定时任务
- [capguard](https://github.com/tomlen045/capguard) 盯磁盘水位
- [cfgdrift](https://github.com/tomlen045/cfgdrift) 盯配置漂移
- [bakcheck](https://github.com/tomlen045/bakcheck) 盯备份死活
- [tokshelf](https://github.com/tomlen045/tokshelf) 盯凭据寿命
- [porteye](https://github.com/tomlen045/porteye) 盯端口暴露面
- [dnsdiff](https://github.com/tomlen045/dnsdiff) 盯域名解析对账

## 边界（一句大实话）

dnsdiff 只做 **A 记录对账**，不做 DNSSEC 验证、不做 DoH/DoT（公共池走明文 UDP 53——在劫持 UDP 53 的网络里，公共池也可能被污染，此时多数派本身就不可信，工具会用「三层全不相交」的形态暴露出来）。授权查询、DNS 隧道检测不在范围内。

## License

MIT
