# dnsdiff

[简体中文](README.md) | [English](README_EN.md)

> **DNS three-way reconciler** — your domain resolves to *different* answers on your machine, on public resolvers, and by majority vote. The delta is the problem.
> When a site won't open, 99% of troubleshooting dies at "which layer is lying?" — dnsdiff puts all three answers on one table.

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.8%2B-informational)]() [![deps](https://img.shields.io/badge/dependencies-zero-success)]()

## The problem it solves

- A site won't open for you but works for your coworkers — stale hosts entry? ISP pollution? CDN glitch?
- You changed a DNS record, waited forever — is it "not propagated", or is it *only your machine* that doesn't see it?
- Antivirus / proxy / corporate gateways hijack resolution silently
- Years of leftover `/etc/hosts` entries that all break the day you switch networks

`ping` only tells you up/down. `nslookup` shows you exactly one view. **A single view can never reveal the "my machine vs the world" delta** — and that's where these failures live.

dnsdiff's reconciliation model:

| View | Source | Meaning |
|---|---|---|
| **Local** | system resolver (auto-detected, overridable) | what your machine *actually* gets |
| **Public pool** | AliDNS 223.5.5.5 / DNSPod 119.29.29.29 / Google 8.8.8.8 | what the world *should* answer |
| **Majority** | answers returned by >half of the pool | trusted baseline — any single public resolver can lie too |

Five verdicts per domain:

| Verdict | Meaning | Typical cause |
|---|---|---|
| **CLEAN (一致)** | local = majority | healthy |
| **DIFF (差集)** | local and majority fully disjoint | stale hosts / local hijack / pollution / unfinished migration |
| **EDGE (同源边缘差异)** | same CDN, different edge | Geo GSLB scheduling — not hijack |
| **LOCAL_FAIL** | local resolver silent | local DNS egress broken |
| **ALL_FAIL** | all three views empty | typo / no network / UDP 53 blocked |

## Quick start

Zero dependencies — Python 3.8+ stdlib only (DNS wire format built and parsed by hand over raw sockets). Single file, copy and run.

```bash
# Three-way diff (main command)
python3 dnsdiff.py diff example.com twitter.com

# Single-domain lookup with hit-source and TTL
python3 dnsdiff.py check www.apple.com

# Audit /etc/hosts, flag private-network mappings
python3 dnsdiff.py hosts
```

Migration / cutover workflow:

```bash
# Before cutover: snapshot the baseline
python3 dnsdiff.py diff api.example.com --snapshot base.json

# After cutover: only NEW deltas are flagged; recovered domains listed separately
python3 dnsdiff.py diff api.example.com --baseline base.json
```

Exit codes are the verdict: `0` consistent, `1` delta found, `2` all queries failed. Wire it into cron/CI directly.

## Design invariants

1. **Zero dependencies** — DNS wire format (query building, parsing, name compression pointers) hand-rolled on stdlib
2. **Read-only** — never modifies any system config
3. **Majority verdict** — no single public resolver is trusted; answers returned by >half of the pool win
4. **Honest TTL** — local TTL < 60s is flagged "dynamic resolution, verdict may flip"
5. **CDN de-noising** — disjoint IPs but same CNAME provider ⇒ "same-CDN edge difference", not a hijack false alarm
6. **Semantic exit codes** — the verdict *is* the exit code
7. **TTY-aware** — color codes stripped when piped, safe to grep

## The sentinel suite

dnsdiff is the DNS view of a larger zero-dependency sentinel suite:

- [cronguard](https://github.com/tomlen045/cronguard) — cron/launchd/systemd timer audit
- [capguard](https://github.com/tomlen045/capguard) — disk headroom forecaster
- [cfgdrift](https://github.com/tomlen045/cfgdrift) — config drift fingerprints
- [bakcheck](https://github.com/tomlen045/bakcheck) — backup actually-restorable check
- [tokshelf](https://github.com/tomlen045/tokshelf) — credential expiry shelf
- [porteye](https://github.com/tomlen045/porteye) — port exposure, inside vs outside view
- [dnsdiff](https://github.com/tomlen045/dnsdiff) — DNS three-way reconciliation

## Honest limitations

dnsdiff reconciles **A records only**. No DNSSEC validation, no DoH/DoT (the public pool speaks plaintext UDP 53 — in a network that hijacks UDP 53 the pool itself can be poisoned; the tool surfaces that as a "all three views disjoint" shape instead of hiding it). Authoritative queries and DNS tunneling detection are out of scope.

## License

MIT
