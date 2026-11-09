#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线覆盖率跑分: 用固定样本对照 all.txt, 输出确定性的评分 JSON。

这不是第三方实跑分数, 而是"该拦的是否还在拦、不该拦的是否被误伤"的回归体检。
每次更新后由 CI 执行; 失败只告警, 不阻断发布。

评分公式:
  score = must_block_hit × 0.4 + must_not_ok × 0.25 + proxy_hit × 0.1 + selector_hit × 0.25
"""
import argparse
import json
import os
import re
import sys

from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXPECT = os.path.join(HERE, "benchmarks", "expectations.json")


# ---------------------------------------------------------------------------
# 域名/修饰符/例外提取
# ---------------------------------------------------------------------------

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
                    # 只有"无条件例外"才整域放行。$document / $all / $important
                    # 都是整域语义; 一旦混进 domain= / 内容类型等收窄修饰符, 就
                    # 只放行特定场景, 不能算作该域已放行。
                    mods = {t.strip().lower()
                            for t in (m.group(2) or "").lstrip("$").split(",")
                            if t.strip()}
                    if not mods or mods <= {"document", "doc", "all", "important"}:
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


# ---------------------------------------------------------------------------
# DOM 选择器匹配 (最小实现, 与 tests/test_adblock_tester.py 保持一致)
# ---------------------------------------------------------------------------

class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _parse_css_sel(selector):
    """分解成 (tag, classes, attr_exprs)。只覆盖 .class / #id / [attr=/!=~=^=$=*=/]
    / 标签 等最常见的 ABP 选择器语法, 忽略 :has() :not() 等进程式扩展 ——
    benchmark 只验证基础命中, 进程式已由 test_adblock_tester 单独覆盖。"""
    m = re.match(r"^([\w-]+)?((?:[.#][\w-]+)*)((?:\[[^\]]+\])*)$", selector)
    if not m:
        return None
    return (m.group(1),
            re.findall(r"\.([\w-]+)", m.group(2) or ""),
            re.findall(r"\[([^\]]+)\]", m.group(3) or ""))


def _match_attr_expr(attrs, expr):
    """[attr] / [attr=v] / [attr*=v] / [attr^=v] / [attr$=v] 的最小实现。"""
    for op in ("*=", "^=", "$=", "~=", "|=", "="):
        if op in expr:
            k, v = [x.strip().strip('"').strip("'") for x in expr.split(op, 1)]
            break
    else:
        # 只有 key —— 存在性判断
        return expr in attrs
    val = attrs.get(k)
    if val is None:
        return False
    if op == "=":
        return val == v
    if op == "*=":
        return v in val
    if op == "^=":
        return val.startswith(v)
    if op == "$=":
        return val.endswith(v)
    if op == "~=":
        return v in val.split()
    if op == "|=":
        return val == v or val.startswith(v + "-")
    return False


def _sel_matches(tag, attrs, parsed):
    stag, classes, attrs_exprs = parsed
    if stag and tag != stag:
        return False
    for c in classes:
        if c.startswith("#"):
            if attrs.get("id") != c[1:]:
                return False
        else:
            if c not in (attrs.get("class") or "").split():
                return False
    for e in attrs_exprs:
        if not _match_attr_expr(attrs, e):
            return False
    return True


def parse_snapshot(path):
    """加载 HTML 快照返回 [(tag, attr_dict), ...]。"""
    with open(path, encoding="utf-8", errors="replace") as f:
        html = f.read()
    col = _TagCollector()
    col.feed(html)
    return col.tags


def selector_hit_count(snapshot_tags, selector):
    parsed = _parse_css_sel(selector)
    if parsed is None:
        return -1  # 选择器语法不可解析
    n = 0
    for tag, d in snapshot_tags:
        if _sel_matches(tag, d, parsed):
            n += 1
    return n


# ---------------------------------------------------------------------------
# 主评估
# ---------------------------------------------------------------------------

def _rate(hit, total):
    return round(hit * 100.0 / total, 1) if total else 0.0


def evaluate(all_path, expect_path=DEFAULT_EXPECT, snapshot=None):
    pure, mod, exc = load_rules(all_path)
    with open(expect_path, encoding="utf-8") as f:
        exp = json.load(f)

    must_block = [d.lower() for d in exp.get("must_block", [])]
    must_not = [d.lower() for d in exp.get("must_not_block", [])]
    blocked = [d for d in must_block if is_blocked(d, pure, exc)]
    false_pos = [d for d in must_not if is_blocked(d, pure, exc)]

    proxy_total = proxy_hit = 0
    snapshot_json = exp.get("proxy_snapshot")
    if snapshot_json:
        snap = os.path.join(HERE, snapshot_json)
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

    # --- 元素隐藏选择器断言 (P3 新增) ---
    selector_hits = selector_total = 0
    selector_results = []
    snap_tags = None
    selector_rules = exp.get("must_block_selectors", [])
    snap_path = snapshot or exp.get("snapshot")
    if selector_rules and snap_path:
        full = os.path.join(HERE, snap_path) if not os.path.isabs(snap_path) else snap_path
        if os.path.exists(full):
            snap_tags = parse_snapshot(full)
            for item in selector_rules:
                sel = item["selector"]
                expected_min = item.get("expect_min", 1)
                got = selector_hit_count(snap_tags, sel)
                selector_total += 1
                if got >= expected_min:
                    selector_hits += 1
                    selector_results.append({"selector": sel,
                                             "got": got,
                                             "expect_min": expected_min,
                                             "ok": True})
                else:
                    selector_results.append({"selector": sel,
                                             "got": got,
                                             "expect_min": expected_min,
                                             "ok": False})
    selector_rate = _rate(selector_hits, selector_total)

    # 加权总分: 域名拦截 0.4 + 域名安全 0.25 + proxy 0.1 + 选择器命中 0.25
    score = round(block_rate * 0.4 + safe_rate * 0.25
                  + proxy_rate * 0.1 + selector_rate * 0.25, 1)

    return {
        "score": score,
        "coverage": {
            "rate": block_rate,
            "hit": len(blocked),
            "total": len(must_block),
            "missing": [d for d in must_block if d not in blocked],
        },
        "safety": {
            "rate": safe_rate,
            "false_positives": false_pos,
            "total": len(must_not),
        },
        "proxy_missed": {
            "rate": proxy_rate,
            "hit": proxy_hit,
            "total": proxy_total,
        },
        "selectors": {
            "rate": selector_rate,
            "hit": selector_hits,
            "total": selector_total,
            "miss": [r for r in selector_results if not r["ok"]],
            "all": selector_results,
        },
        "rules": {
            "pure_domains": len(pure),
            "modifier_domains": len(mod),
            "exceptions": len(exc),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="benchmark", description="离线覆盖率跑分")
    ap.add_argument("--all", default=os.path.join(HERE, "output", "all.txt"))
    ap.add_argument("--expectations", default=DEFAULT_EXPECT)
    ap.add_argument("--snapshot", default=None,
                    help="HTML 快照路径 (默认从 expectations.snapshot 取)")
    ap.add_argument("--out", default=None, help="结果 JSON 路径 (默认只打印)")
    args = ap.parse_args(argv)

    result = evaluate(args.all, args.expectations, snapshot=args.snapshot)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
