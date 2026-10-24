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

# Adblock 修饰符 -> Playwright resource_type
TYPE_MAP = {
    "script": {"script"},
    "image": {"image"},
    "stylesheet": {"stylesheet"},
    "css": {"stylesheet"},
    "object": {"other"},
    "object-subrequest": {"other"},
    "xmlhttprequest": {"xhr", "fetch"},
    "subdocument": {"document"},
    "document": {"document"},
    "popup": {"document"},
    "media": {"media"},
    "font": {"font"},
    "websocket": {"websocket"},
    "ping": {"other"},
    "other": {"other"},
}

# 这些修饰符本身不产生拦截效果, 整条规则跳过
NO_BLOCK = ("$removeparam", "$cookie", "$csp", "$header", "$redirect", "$rewrite",
            "$webrtc", "$genericblock", "$generichide", "$elemhide", "$specifichide")


def parse_modifiers(mods):
    """把 $ 后面的修饰符解析成 (类型集合|None, 仅第三方|None, 限定页面域名|None)。

    类型为 None 表示不限类型; 限定域名用 (包含集合, 排除集合) 表示。
    """
    types, third, dom_in, dom_out = set(), None, set(), set()
    for tok in (mods or "").lstrip("$").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if tok in ("third-party", "3p"):
            third = True
        elif tok in ("first-party", "1p", "~third-party"):
            third = False
        elif tok.startswith("domain="):
            for d in tok[len("domain="):].split("|"):
                d = d.strip().lower()
                if not d:
                    continue
                if d.startswith("~"):
                    dom_out.add(d[1:])
                else:
                    dom_in.add(d)
        elif tok.startswith("~"):
            continue  # 否定类型暂不支持, 按"不限类型"处理
        elif tok in TYPE_MAP:
            types |= TYPE_MAP[tok]
    domains = None
    if dom_in or dom_out:
        domains = (frozenset(dom_in), frozenset(dom_out))
    return (frozenset(types) if types else None), third, domains


def load_blocklist(path):
    """返回 (纯域名, [(域名, 路径前缀)], [受限规则], 例外域名)。

    受限规则为 (域名, 类型集合, 仅第三方, 路径前缀, 限定页面域名)。
    """
    pure, paths, scoped, exc = set(), [], [], set()
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
            if any(x in line.lower() for x in NO_BLOCK):
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^(\$.*)$", line, re.I)
            if m and "." in m.group(1):
                types, third, domains = parse_modifiers(m.group(2))
                scoped.append((m.group(1).lower(), types, third, "/", domains))
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)\^$", line, re.I)
            if m and "." in m.group(1):
                pure.add(m.group(1).lower())
                continue
            m = re.match(r"^\|\|([a-z0-9.-]+)(/[^$^]*)\^?(\$.*)?$", line, re.I)
            if m and "." in m.group(1):
                host, prefix = m.group(1).lower(), m.group(2)
                types, third, domains = parse_modifiers(m.group(3) or "")
                if types or third is not None or domains:
                    scoped.append((host, types, third, prefix, domains))
                else:
                    paths.append((host, prefix))
    return pure, paths, scoped, exc


def _site(host):
    """粗粒度站点域名: 取最后两段, 用于判断第一/第三方。"""
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _host_match(host, rule_host):
    return host == rule_host or host.endswith("." + rule_host)


def _scoped_hit(host, path, rule, resource_type, page_host):
    rule_host, types, third, prefix, domains = rule
    if not _host_match(host, rule_host) or not path.startswith(prefix):
        return False
    if types is not None and resource_type not in types:
        return False
    if third is True and page_host and _site(host) == _site(page_host):
        return False
    if third is False and page_host and _site(host) != _site(page_host):
        return False
    if domains:
        dom_in, dom_out = domains
        page = page_host or ""
        if dom_out and any(_host_match(page, d) for d in dom_out):
            return False
        if dom_in and not any(_host_match(page, d) for d in dom_in):
            return False
    return True


def is_blocked(url, pure, paths, exc, scoped=(), resource_type=None, page_url=None):
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
    if any(_host_match(host, h) and path.startswith(p) for h, p in paths):
        return True
    page_host = (urlparse(page_url).hostname or "").lower() if page_url else ""
    return any(_scoped_hit(host, path, rule, resource_type, page_host)
               for rule in scoped)


def adblock_tester_selectors(config_path):
    """从 config.extra_rules 取 adblock-tester.com 的元素隐藏选择器。"""
    with open(config_path, encoding="utf-8") as f:
        rules = json.load(f).get("extra_rules", [])
    return [r.split("##", 1)[1] for r in rules
            if r.startswith("adblock-tester.com##") and "##" in r]


COSMETIC_MARKERS = ("#@?#", "#@#", "#?#", "##")


def parse_cosmetic(rule):
    """把一条元素隐藏规则拆成 (标记, 域名列表, 选择器); 非元素隐藏返回 None。"""
    if not rule or rule.startswith(("!", "[Adblock")):
        return None
    # HTML 过滤、脚本注入、样式重写都不是 CSS 能表达的
    if any(x in rule for x in ("##^", "#%#", "#$#", "%#")):
        return None
    marker = next((m for m in COSMETIC_MARKERS if m in rule), None)
    if marker is None:
        return None
    doms_part, _, sel = rule.partition(marker)
    sel = sel.strip()
    if not sel or sel.startswith("+js("):
        return None
    doms = [d.strip().lower() for d in doms_part.split(",") if d.strip()]
    return marker, doms, sel


def load_cosmetic(all_path, config_path=None):
    """收集元素隐藏规则, 返回 (通用选择器, [(域名, 选择器)], 例外集合)。"""
    generic, scoped, exc = set(), [], set()
    lines = []
    with open(all_path, encoding="utf-8", errors="replace") as f:
        lines.extend(f)
    if config_path:
        with open(config_path, encoding="utf-8") as f:
            lines.extend(json.load(f).get("extra_rules", []))
    for line in lines:
        parsed = parse_cosmetic(line.strip())
        if not parsed:
            continue
        marker, doms, sel = parsed
        if not doms:
            generic.add(sel)
        elif marker.startswith("#@"):
            for d in doms:
                exc.add((d, sel))
        else:
            for d in doms:
                scoped.append((d, sel))
    return generic, scoped, exc


def build_css(generic, scoped, exceptions, page_host):
    """按页面域名生成实际生效的隐藏样式。"""
    host = (page_host or "").lower()
    sels = set(generic)
    for dom, sel in scoped:
        negated = dom.startswith("~")
        base = dom.lstrip("~")
        if not host or not _host_match(host, base):
            continue
        if negated:
            sels.discard(sel)
        else:
            sels.add(sel)
    for dom, sel in exceptions:
        base = dom.lstrip("~")
        if host and _host_match(host, base):
            sels.discard(sel)
    return "".join(s + "{display:none!important}\n" for s in sorted(sels))


def run(html_path, all_path, config_path, out_path, shot_path=None, channel=None, url=None):
    from playwright.sync_api import sync_playwright

    pure, paths, scoped, exc = load_blocklist(all_path)
    generic, cosmetic_scoped, cosmetic_exc = load_cosmetic(all_path, config_path)
    selectors = adblock_tester_selectors(config_path)
    stats = {"total_requests": 0, "blocked_requests": 0}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=channel)
        page = browser.new_page()

        def route(r):
            stats["total_requests"] += 1
            # 实测线上站点时放行主文档, 否则页面本身被拦会直接打不开
            if url and r.request.resource_type == "document":
                r.continue_()
                return
            if is_blocked(r.request.url, pure, paths, exc, scoped,
                          r.request.resource_type, page.url):
                stats["blocked_requests"] += 1
                r.abort()
            else:
                r.continue_()

        page.route("**/*", route)
        target = url or Path(html_path).resolve().as_uri()
        page.goto(target, wait_until="load", timeout=60000)

        # 本地快照是 adblock-tester.com 的镜像, 用该域名代入, 否则元素隐藏规则无从命中
        page_host = urlparse(target).hostname or ("adblock-tester.com" if not url else "")
        page.add_style_tag(content=build_css(generic, cosmetic_scoped,
                                             cosmetic_exc, page_host))
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
    ap.add_argument("--url", default=None, help="改为实测线上页面, 如 https://example.com/test/")
    args = ap.parse_args(argv)
    result = run(args.html, args.all, args.config, args.out, args.screenshot,
                 args.channel, args.url)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
