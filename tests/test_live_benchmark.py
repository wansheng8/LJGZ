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
            pure, _, _ = lb.load_blocklist(p)
        self.assertNotIn("clean.test", pure)
        self.assertIn("block.test", pure)


class TestSelectors(unittest.TestCase):
    def test_config_exposes_adblock_tester_selectors(self):
        sels = lb.adblock_tester_selectors(os.path.join(REPO, "config.json"))
        self.assertGreaterEqual(len(sels), 5, "元素隐藏选择器过少, 跑分失去意义")
        for s in sels:
            self.assertNotIn("##", s)


if __name__ == "__main__":
    unittest.main()
