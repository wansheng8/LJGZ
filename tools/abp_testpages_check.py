#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ABP 官方测试订阅语法检查。

每次 CI 更新前拉取 abptestpages.org 的最新测试订阅, 用当前引擎逐条解析:
  - 有规则被丢弃 / 出现未知修饰符 -> 退出码 1 (阻断发布, 提示补语法)
  - 网络不可达 -> 回退到 tests/data 离线快照并告警, 不阻断
  - 与离线快照对比新增/移除的规则, 便于观察官网用例变化
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.request
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import merge_filters as mf  # noqa: E402

DEFAULT_URL = "https://www.abptestpages.org/en/abp-testcase-subscription.txt"
DEFAULT_SNAPSHOT = os.path.join(ROOT, "tests", "data",
                                "abp-testcase-subscription.txt")


def fetch(url: str, timeout: int, attempts: int = 2) -> bytes:
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "LJGZ-abp-check/1.0",
                "Cache-Control": "no-cache",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as exc:  # noqa: BLE001 - 网络异常统一重试
            last = exc
            if i + 1 < attempts:
                time.sleep(2)
    raise RuntimeError(str(last))


def load_rules(data: bytes):
    """按列表语法取规则行; 注释/列表头/# 装饰行不计。"""
    rows, comments = [], []
    for raw in data.decode("utf-8-sig").splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("!") or s.startswith("["):
            comments.append(s)
            continue
        if s.startswith("#") and not any(
                s.startswith(x) for x in mf.COSMETIC_SEPS):
            comments.append(s)
            continue
        rows.append(s)
    return rows, comments


def audit(rows):
    kinds = Counter()
    drops, dns_ok = [], []
    unknown = Counter()
    for line in rows:
        r = mf.parse_line(line)
        kinds[r.kind] += 1
        if r.dropped:
            drops.append(line)
        if r.kind == mf.K_EXCEPTION and r.dns_relevant:
            dns_ok.append(line)
        if r.modifiers:
            for part in mf._split_mods_raw(r.modifiers):
                key = part.strip().split("=", 1)[0].strip().lstrip("~").lower()
                if key and key not in mf._OFFICIAL_MODS:
                    unknown[key] += 1
    return kinds, drops, unknown, dns_ok


def sample(lines, n=8):
    for line in lines[:n]:
        print("  - " + line[:160])
    if len(lines) > n:
        print("  ... 其余 %d 条省略" % (len(lines) - n))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--strict-fetch", action="store_true",
                    help="网络失败也视为错误 (默认回退快照并告警)")
    args = ap.parse_args()

    source = "live"
    try:
        data = fetch(args.url, args.timeout)
    except Exception as exc:  # noqa: BLE001
        if args.strict_fetch or not os.path.exists(args.snapshot):
            print("::error title=ABP 订阅获取失败::%s" % exc)
            return 2
        print("::warning title=ABP 订阅获取失败::%s, 回退离线快照" % exc)
        with open(args.snapshot, "rb") as fh:
            data = fh.read()
        source = "snapshot"

    rows, comments = load_rules(data)
    if not rows:
        print("::error title=ABP 订阅为空::未解析到任何规则")
        return 1
    if not any(c.startswith("[Adblock") for c in comments):
        print("::warning title=ABP 订阅格式异常::缺少 [Adblock Plus 2.0] 列表头")

    kinds, drops, unknown, dns_ok = audit(rows)
    print("ABP 测试订阅 (%s): %d 条 | cosmetic %d / network %d / exception %d"
          % (source, len(rows), kinds[mf.K_COSMETIC], kinds[mf.K_NETWORK],
             kinds[mf.K_EXCEPTION]))
    print("丢弃 %d | 未知修饰符 %d | DNS 白名单候选 %d"
          % (len(drops), sum(unknown.values()), len(dns_ok)))

    snapshot_rows = set()
    if os.path.exists(args.snapshot) and source == "live":
        with open(args.snapshot, "rb") as fh:
            snap, _ = load_rules(fh.read())
        snapshot_rows = set(snap)
        cur = set(rows)
        print("相对快照: 新增 %d / 移除 %d"
              % (len(cur - snapshot_rows), len(snapshot_rows - cur)))

    failed = False
    if drops:
        failed = True
        print("::error title=ABP 语法回归::%d 条规则被丢弃" % len(drops))
        sample(drops)
    if unknown:
        failed = True
        print("::error title=ABP 未知修饰符::%s"
              % ", ".join("%s×%d" % (k, v) for k, v in unknown.most_common(10)))
        bad = [line for line in rows
               if any(p.strip().split("=", 1)[0].strip().lstrip("~").lower()
                      in unknown for p in mf._split_mods_raw(
                          mf.parse_line(line).modifiers or ""))]
        sample(bad)

    if failed:
        return 1
    print("ABP CHECK OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
