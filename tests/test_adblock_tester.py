# -*- coding: utf-8 -*-
"""
adblock-tester.com 专项: extra_rules 里的选择器必须真实匹配页面 DOM。

历史教训: 曾写入 `##div[id^="ads:"]` (页面里该 id 在 <input> 上, 匹配 0 个
<div>, 且隐藏开关会破坏页面交互) 和 `##div[data-ads]` (页面是 data-ads="",
选择器缺值判断, 匹配 0 个)。以及网络层用 `$~third-party` 导致同域 banner
永不拦截 —— 22 项检查里 4 项因此失败, 分数卡在 74。

本测试用一份真实抓取的 adblock-tester.com 快照做离线断言, 任何选择器匹配
数归零都会在 CI 失败, 而不是等到用户测分才发现。
"""
import json
import os
import re
import unittest
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SNAPSHOT = os.path.join(HERE, "data", "adblock-tester.html")
CONFIG = os.path.join(REPO, "config.json")


# --- 抓取快照时禁止出现的写法 (历史 bug) ---
BANNED = {
    "$~third-party": "同域请求永不满足该条件, banner 类规则会静默失效",
    "div[id^=\"ads:\"]": "该 id 在 <input> 上, 匹配 0 个元素且会隐藏开关",
    "div[id^=\"banner:\"]": "该 id 在 <input> 上, 匹配 0 个元素且会隐藏开关",
    "div[data-ads]": "页面是 data-ads=\"\", 需带值判断, 否则匹配 0 个",
}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _matches(tag, attrs, selector):
    """最小 CSS 选择器实现: 覆盖 tag / .class / [attr] / [attr=v] / *= ^= $=。"""
    m = re.match(r"^([\w-]+)?((?:[.#][\w-]+)*)((?:\[[^\]]+\])*)$", selector)
    if not m:
        raise ValueError("无法解析的选择器: %r" % selector)
    stag, rest, attr_part = m.group(1), m.group(2) or "", m.group(3) or ""
    if stag and tag != stag:
        return False
    for cls in re.findall(r"\.([\w-]+)", rest):
        if cls not in (attrs.get("class") or "").split():
            return False
    for a in re.findall(r"\[([^\]]+)\]", attr_part):
        hit = False
        for op in ("*=", "^=", "$=", "="):
            if op in a:
                k, v = [x.strip().strip('"').strip("'") for x in a.split(op, 1)]
                val = attrs.get(k)
                if op == "=":
                    hit = val == v
                elif val is None:
                    hit = False
                elif op == "*=":
                    hit = v in val
                elif op == "^=":
                    hit = val.startswith(v)
                else:
                    hit = val.endswith(v)
                break
        if not hit:
            return False
    return True


class AdblockTesterRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SNAPSHOT):
            raise unittest.SkipTest("缺少 adblock-tester 快照: %s" % SNAPSHOT)
        with open(SNAPSHOT, encoding="utf-8", errors="replace") as f:
            html = f.read()
        col = _Collector()
        col.feed(html)
        cls.tags = col.tags
        with open(CONFIG, encoding="utf-8") as f:
            cls.rules = json.load(f).get("extra_rules", [])

    def test_snapshot_has_expected_elements(self):
        """快照本身有效 —— 页面结构变了要让测试先失败, 而不是静默放过。"""
        counts = {}
        for tag, d in self.tags:
            counts[tag] = counts.get(tag, 0) + 1
        for tag, minimum in (("object", 1), ("embed", 1), ("param", 1),
                             ("img", 3), ("div", 50), ("ins", 1)):
            self.assertGreaterEqual(
                counts.get(tag, 0), minimum,
                "快照里 <%s> 数量异常, 快照可能已过期" % tag)
        banner_imgs = [d for t, d in self.tags
                       if t == "img" and "banners/" in (d.get("src") or "")]
        self.assertEqual(len(banner_imgs), 2, "应恰好有 gif + png 两个 banner img")

    def test_no_banned_patterns(self):
        for rule in self.rules:
            for banned, why in BANNED.items():
                self.assertNotIn(
                    banned, rule,
                    "规则 %r 含已证伪的写法 %r: %s" % (rule, banned, why))

    def test_banner_network_rule_is_unconditional(self):
        """banner 规则必须无条件拦截: 同域请求不满足 $~third-party。"""
        banner = [r for r in self.rules if "adblock-tester.com/banners" in r]
        self.assertTrue(banner, "缺少 banner 网络拦截规则")
        for r in banner:
            self.assertIn("$all", r,
                          "banner 规则 %r 缺 $all, 在同域场景下可能不生效" % r)

    def test_every_cosmetic_selector_matches_real_dom(self):
        """核心回归: 每条 adblock-tester 元素隐藏规则必须真实命中 >=1 个元素。"""
        checked = 0
        for rule in self.rules:
            m = re.match(r"^adblock-tester\.com##(.+)$", rule)
            if not m:
                continue
            selector = m.group(1)
            n = sum(1 for t, d in self.tags if _matches(t, d, selector))
            self.assertGreater(
                n, 0,
                "选择器 ##%s 在真实 DOM 上匹配 0 个元素 —— 规则无效" % selector)
            checked += 1
        self.assertGreaterEqual(checked, 8, "元素隐藏规则过少, 覆盖退化")

    def test_no_selector_hides_page_switches(self):
        """不能隐藏 <input id="ads:*"> —— 那是页面自己的开关控件。"""
        for rule in self.rules:
            m = re.match(r"^adblock-tester\.com##(.+)$", rule)
            if not m:
                continue
            self.assertNotRegex(
                m.group(1), r"^input",
                "规则 %r 会隐藏页面开关控件" % rule)

    def test_rules_are_unique(self):
        self.assertEqual(
            len(self.rules), len(set(self.rules)), "extra_rules 存在重复项")


if __name__ == "__main__":
    unittest.main()
