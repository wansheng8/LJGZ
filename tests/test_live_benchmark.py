# -*- coding: utf-8 -*-
"""真实浏览器跑分的规则匹配与页面选择器 (不启动 Chromium)。"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from tools import live_benchmark as lb  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


class TestRuleMatching(unittest.TestCase):
    def test_domain_rule_blocks_subdomain(self):
        self.assertTrue(lb.is_blocked("https://a.b.ads.test/x.js",
                                      {"ads.test"}, [], set()))

    def test_path_rule_only_matches_prefix(self):
        paths = [("adblock-tester.com", "/banners/")]
        self.assertTrue(lb.is_blocked("https://adblock-tester.com/banners/a.png",
                                      set(), paths, set()))
        self.assertFalse(lb.is_blocked("https://adblock-tester.com/other/a.png",
                                       set(), paths, set()))

    def test_exception_wins(self):
        self.assertFalse(lb.is_blocked("https://ads.test/x", {"ads.test"}, [], {"ads.test"}))

    def test_removeparam_is_not_treated_as_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||clean.test^$removeparam=utm\n||block.test^\n")
            pure, _, _, _ = lb.load_blocklist(p)
        self.assertNotIn("clean.test", pure)
        self.assertIn("block.test", pure)

    def test_bare_tld_rule_is_ignored(self):
        """||com/... 这类畸形规则不能把整个 .com 打死。"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||com/*/ModalEngage|$script,3p\n||com/$doc,ipaddress=1.2.3.4\n")
            pure, paths, scoped, exc = lb.load_blocklist(p)
            blocked = lb.is_blocked("https://www.example.com/_astro/a.css",
                                    pure, paths, exc, scoped, "stylesheet",
                                    "https://www.example.com/test/")
        self.assertFalse(blocked)

    def test_typed_rule_only_blocks_that_type(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||cdn.test^$script\n")
            pure, paths, scoped, exc = lb.load_blocklist(p)
            self.assertTrue(lb.is_blocked("https://cdn.test/a.js", pure, paths, exc,
                                          scoped, "script", "https://site.test/"))
            self.assertFalse(lb.is_blocked("https://cdn.test/a.css", pure, paths, exc,
                                           scoped, "stylesheet", "https://site.test/"))

    def test_third_party_rule_spares_first_party(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||site.test^$third-party\n")
            pure, paths, scoped, exc = lb.load_blocklist(p)
            self.assertTrue(lb.is_blocked("https://api.site.test/x", pure, paths, exc,
                                          scoped, "xhr", "https://other.test/"))
            self.assertFalse(lb.is_blocked("https://api.site.test/x", pure, paths, exc,
                                          scoped, "xhr", "https://www.site.test/"))

    def test_domain_scoped_rule_respects_page(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||tracker.test^$domain=a.test|~b.a.test\n")
            pure, paths, scoped, exc = lb.load_blocklist(p)
            self.assertTrue(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                          scoped, "script", "https://a.test/"))
            self.assertFalse(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                           scoped, "script", "https://b.a.test/"))
            self.assertFalse(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                           scoped, "script", "https://c.test/"))


class TestCosmetic(unittest.TestCase):
    def test_parse_skips_scriptlet_and_html_filtering(self):
        self.assertIsNone(lb.parse_cosmetic("a.test##+js(json-prune, x)"))
        self.assertIsNone(lb.parse_cosmetic("a.test#$#abort-on-property-read x"))
        self.assertIsNone(lb.parse_cosmetic("a.test##^script:has-text(ads)"))
        self.assertEqual(lb.parse_cosmetic("##.ad")[2], ".ad")

    def test_generic_cosmetic_applies_everywhere(self):
        css = lb.build_css({".ad"}, [], set(), "any.test")
        self.assertIn(".ad{display:none!important}", css)
        self.assertIn(".ad{display:none!important}",
                      lb.build_css({".ad"}, [], set(), "other.test"))

    def test_domain_cosmetic_and_exception(self):
        css = lb.build_css(set(), [("site.test", ".banner")], set(), "www.site.test")
        self.assertIn(".banner{display:none!important}", css)
        css = lb.build_css(set(), [("site.test", ".banner")], set(), "other.test")
        self.assertNotIn(".banner", css)
        css = lb.build_css(set(), [("~site.test", ".banner")], set(), "www.site.test")
        self.assertNotIn(".banner", css)
        css = lb.build_css({".banner"}, [], {("site.test", ".banner")}, "www.site.test")
        self.assertNotIn(".banner", css)

    def test_real_lists_yield_usable_css(self):
        generic, scoped, _ = lb.load_cosmetic(os.path.join(REPO, "output", "all.txt"),
                                              os.path.join(REPO, "config.json"))
        self.assertGreater(len(generic), 10000, "通用隐藏规则过少")
        css = lb.build_css(generic, scoped, set(), "adblock-tester.com")
        self.assertGreater(len(css), 100000)
        self.assertIn(".include", css)


class TestSelectors(unittest.TestCase):
    def test_config_exposes_adblock_tester_selectors(self):
        sels = lb.adblock_tester_selectors(os.path.join(REPO, "config.json"))
        self.assertGreaterEqual(len(sels), 5, "元素隐藏选择器过少, 跑分失去意义")
        for s in sels:
            self.assertNotIn("##", s)


if __name__ == "__main__":
    unittest.main()
