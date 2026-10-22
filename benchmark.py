#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线覆盖率跑分: 用固定样本对照 all.txt, 输出确定性的评分 JSON。

这不是第三方实跑分数, 而是"该拦的是否还在拦、不该拦的是否被误伤"的回归体检。
每次更新后由 CI 执行; 失败只告警, 不阻断发布。
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXPECT = os.path.join(HERE, "benchmarks", "expectations.json")


def load_rules(path):
    """返回 (纯域名拦截, 带修饰符的域名规则, 例外域名)。"""
    pure, mod, exc = set(), set(), set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("!", "[Adblock", "#")):
                continue
            if line.startswith("@@"):
                m = re.match(r"^@@\|\|([a-z0-9.-]+)\^(\$.*)?$", line, re.I)
                if m:
                    mods = m.group(2) or ""
                    # 只有无条件例外才整域放行; $script,domain=x 这类只放行特定场景
                    if not mods or "$document" in mods or "$all" in mods:
                        exc.add(m.group(1).lower())
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^$", line, re.I)
            if m:
                pure.add(m.group(1).lower())
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^\$", line, re.I)
            if m:
                mod.add(m.group(1).lower())
    return pure, mod, exc


def is_blocked(domain, pure, exc):
    """||d^ 会连带拦截子域: 自身或任一上级域命中即视为已拦; 例外同理。"""
    domain = domain.lower()
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in exc:
            return False
        if suffix in pure:
            return True
    return False


def _rate(hit, total):
    return round(hit * 100.0 / total, 1) if total else 0.0


def evaluate(all_path, expect_path=DEFAULT_EXPECT):
    pure, mod, exc = load_rules(all_path)
    with open(expect_path, encoding="utf-8") as f:
        exp = json.load(f)

    must_block = [d.lower() for d in exp.get("must_block", [])]
    must_not = [d.lower() for d in exp.get("must_not_block", [])]
    blocked = [d for d in must_block if is_blocked(d, pure, exc)]
    false_pos = [d for d in must_not if is_blocked(d, pure, exc)]

    proxy_total = proxy_hit = 0
    snapshot = exp.get("proxy_snapshot")
    if snapshot:
        snap = os.path.join(HERE, snapshot)
        if os.path.exists(snap):
            with open(snap, encoding="utf-8") as f:
                cases = [d.lower() for _, d in json.load(f)]
            exclude = {d.lower() for d in exp.get("proxy_exclude", [])}
            targets = [d for d in cases if d not in exclude]
            proxy_total = len(targets)
            proxy_hit = sum(1 for d in targets if d in pure or d in mod)

    block_rate = _rate(len(blocked), len(must_block))
    safe_rate = _rate(len(must_not) - len(false_pos), len(must_not))
    proxy_rate = _rate(proxy_hit, proxy_total)
    score = round(block_rate * 0.5 + safe_rate * 0.3 + proxy_rate * 0.2, 1)

    return {
        "score": score,
        "coverage": {"rate": block_rate, "hit": len(blocked), "total": len(must_block),
                     "missing": [d for d in must_block if d not in blocked]},
        "safety": {"rate": safe_rate, "false_positives": false_pos,
                   "total": len(must_not)},
        "proxy_missed": {"rate": proxy_rate, "hit": proxy_hit, "total": proxy_total},
        "rules": {"pure_domains": len(pure), "modifier_domains": len(mod),
                  "exceptions": len(exc)},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="benchmark", description="离线覆盖率跑分")
    ap.add_argument("--all", default=os.path.join(HERE, "output", "all.txt"))
    ap.add_argument("--expectations", default=DEFAULT_EXPECT)
    ap.add_argument("--out", default=None, help="结果 JSON 路径 (默认只打印)")
    args = ap.parse_args(argv)

    result = evaluate(args.all, args.expectations)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
