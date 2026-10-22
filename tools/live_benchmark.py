#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真实浏览器跑分 (Playwright/Chromium, 非阻断)。

在真实 Chromium 中加载 adblock-tester 页面快照, 用 all.txt 的域名/路径规则
拦截请求, 再统计仍可见的广告元素。输出 JSON + 截图, 由独立 workflow 每周跑。
不依赖第三方站点在线, 因此不会因为反爬导致每日更新变红。
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def load_blocklist(path):
    """返回 (纯域名集合, [(域名, 路径前缀)], 无条件例外域名集合)。"""
    pure, paths, exc = set(), [], set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("!", "[Adblock", "#")):
                continue
            if line.startswith("@@"):
                m = re.match(r"^@@\|\|([a-z0-9.-]+)\^(\$.*)?$", line, re.I)
                if m and (not m.group(2) or "$document" in m.group(2)):
                    exc.add(m.group(1).lower())
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^$", line, re.I)
            if m:
                pure.add(m.group(1).lower())
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)(/[^$^]*)\^?(\$.*)?$", line, re.I)
            if m:
                paths.append((m.group(1).lower(), m.group(2)))
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^?\$", line, re.I)
            if m and not any(x in line.lower() for x in ("$removeparam", "$cookie", "$csp")):
                pure.add(m.group(1).lower())
    return pure, paths, exc


def is_blocked(url, pure, paths, exc):
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if not host:
        return False
    parts = host.split(".")
    for i in range(len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix in exc:
            return False
        if suffix in pure:
            return True
    path = u.path or "/"
    return any(host == h or host.endswith("." + h) for h, p in paths
               if path.startswith(p))


def adblock_tester_selectors(config_path):
    """从 config.extra_rules 取 adblock-tester.com 的元素隐藏选择器。"""
    with open(config_path, encoding="utf-8") as f:
        rules = json.load(f).get("extra_rules", [])
    return [r.split("##", 1)[1] for r in rules
            if r.startswith("adblock-tester.com##") and "##" in r]


def run(html_path, all_path, config_path, out_path, shot_path=None, channel=None):
    from playwright.sync_api import sync_playwright

    pure, paths, exc = load_blocklist(all_path)
    selectors = adblock_tester_selectors(config_path)
    stats = {"total_requests": 0, "blocked_requests": 0}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=channel)
        page = browser.new_page()

        def route(r):
            stats["total_requests"] += 1
            if is_blocked(r.request.url, pure, paths, exc):
                stats["blocked_requests"] += 1
                r.abort()
            else:
                r.continue_()

        page.route("**/*", route)
        page.goto(Path(html_path).resolve().as_uri(), wait_until="load", timeout=60000)
        page.wait_for_timeout(1500)

        visible = page.evaluate(
            """(sels) => {
                const out = {};
                for (const s of sels) {
                    try {
                        out[s] = [...document.querySelectorAll(s)]
                            .filter(el => el.offsetParent !== null).length;
                    } catch (e) { out[s] = -1; }
                }
                return out;
            }""", selectors)
        if shot_path:
            page.screenshot(path=shot_path, full_page=True)
        browser.close()

    leaked = sum(v for v in visible.values() if v > 0)
    result = {
        "score": max(0, 100 - leaked * 10),
        "visible_ad_elements": leaked,
        "selectors": visible,
        "requests": stats,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(prog="live_benchmark")
    ap.add_argument("--html", default=os.path.join(REPO, "tests", "data", "adblock-tester.html"))
    ap.add_argument("--all", default=os.path.join(REPO, "output", "all.txt"))
    ap.add_argument("--config", default=os.path.join(REPO, "config.json"))
    ap.add_argument("--out", default=os.path.join(REPO, "output", "live-benchmark.json"))
    ap.add_argument("--screenshot", default=None)
    ap.add_argument("--channel", default=None, help="浏览器通道, 如 msedge (本地调试用)")
    args = ap.parse_args(argv)
    result = run(args.html, args.all, args.config, args.out, args.screenshot, args.channel)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
