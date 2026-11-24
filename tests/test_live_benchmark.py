# -*- coding: utf-8 -*-
"""真实浏览器跑分的规则匹配与页面选择器 (不启动 Chromium)。"""
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
            pure, _, _, _, _ = lb.load_blocklist(p)
        self.assertNotIn("clean.test", pure)
        self.assertIn("block.test", pure)

    def test_bare_tld_rule_is_ignored(self):
        """||com/... 这类畸形规则不能把整个 .com 打死。"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||com/*/ModalEngage|$script,3p\n||com/$doc,ipaddress=1.2.3.4\n")
            pure, paths, scoped, exc, _ = lb.load_blocklist(p)
            blocked = lb.is_blocked("https://www.example.com/_astro/a.css",
                                    pure, paths, exc, scoped, "stylesheet",
                                    "https://www.example.com/test/")
        self.assertFalse(blocked)

    def test_typed_rule_only_blocks_that_type(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||cdn.test^$script\n")
            pure, paths, scoped, exc, _ = lb.load_blocklist(p)
            self.assertTrue(lb.is_blocked("https://cdn.test/a.js", pure, paths, exc,
                                          scoped, "script", "https://site.test/"))
            self.assertFalse(lb.is_blocked("https://cdn.test/a.css", pure, paths, exc,
                                           scoped, "stylesheet", "https://site.test/"))

    def test_third_party_rule_spares_first_party(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||site.test^$third-party\n")
            pure, paths, scoped, exc, _ = lb.load_blocklist(p)
            self.assertTrue(
                lb.is_blocked("https://api.site.test/x", pure, paths, exc,
                              scoped, "xhr", "https://other.test/"))
            self.assertFalse(
                lb.is_blocked("https://api.site.test/x", pure, paths, exc,
                              scoped, "xhr", "https://www.site.test/"))

    def test_domain_scoped_rule_respects_page(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||tracker.test^$domain=a.test|~b.a.test\n")
            pure, paths, scoped, exc, _ = lb.load_blocklist(p)
            self.assertTrue(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                          scoped, "script", "https://a.test/"))
            self.assertFalse(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                           scoped, "script", "https://b.a.test/"))
            self.assertFalse(lb.is_blocked("https://tracker.test/p", pure, paths, exc,
                                           scoped, "script", "https://c.test/"))

    def test_parent_exception_covers_blocked_subdomain(self):
        """父域例外优先级高于子域拦截, 与 merge_filters._excepted 一致。"""
        self.assertFalse(lb.is_blocked("https://smetrics.huntington.com/x",
                                       {"smetrics.huntington.com"}, [], {"huntington.com"}))

    def test_main_document_only_allowed_for_main_frame(self):
        """在线模式只放行主框架文档, iframe 的 document 仍参与拦截判定。"""
        self.assertTrue(lb.allow_document("document", "main", "main"))
        self.assertFalse(lb.allow_document("document", "iframe", "main"))
        self.assertFalse(lb.allow_document("script", "main", "main"))
        self.assertFalse(lb.allow_document("document", None, "main"))

    def test_negated_type_is_passed_through(self):
        """$~media 的语义是除媒体外都拦, 媒体请求必须放行。"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||2mdn.net^$~media,third-party\n")
            pure, paths, scoped, exc, exc_scoped = lb.load_blocklist(p)
        self.assertFalse(lb.is_blocked("https://2mdn.net/a.mp4", pure, paths, exc,
                                       scoped, "media", "https://site.test/",
                                       exc_scoped))
        self.assertTrue(lb.is_blocked("https://2mdn.net/a.js", pure, paths, exc,
                                      scoped, "script", "https://site.test/",
                                      exc_scoped))

    def test_path_exception_unblocks_only_that_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||tracker.test^\n@@||tracker.test/allow/$script\n")
            pure, paths, scoped, exc, exc_scoped = lb.load_blocklist(p)
        self.assertFalse(lb.is_blocked("https://tracker.test/allow/a.js",
                                       pure, paths, exc, scoped, "script",
                                       "https://site.test/", exc_scoped))
        self.assertTrue(lb.is_blocked("https://tracker.test/other/a.js",
                                      pure, paths, exc, scoped, "script",
                                      "https://site.test/", exc_scoped))

    def test_domain_scoped_exception_respects_page(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||tracker.test^\n@@||tracker.test^$script,domain=site.test\n")
            pure, paths, scoped, exc, exc_scoped = lb.load_blocklist(p)
        self.assertFalse(lb.is_blocked("https://tracker.test/a.js", pure, paths,
                                       exc, scoped, "script", "https://site.test/",
                                       exc_scoped))
        self.assertTrue(lb.is_blocked("https://tracker.test/a.js", pure, paths,
                                      exc, scoped, "script", "https://other.test/",
                                      exc_scoped))

    def test_cosmetic_exception_does_not_unblock_requests(self):
        """$ghide 只关闭元素隐藏, 不能让该域的网络请求全部放行。"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("||1warie.com^\n@@||1warie.com^$ghide\n")
            pure, paths, scoped, exc, exc_scoped = lb.load_blocklist(p)
        self.assertTrue(lb.is_blocked("https://1warie.com/x.js", pure, paths, exc,
                                      scoped, "script", "https://site.test/",
                                      exc_scoped))


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

    def test_generic_cosmetic_exception_removes_selector(self):
        """无域名的 #@# 是通用例外, 不能反过来变成隐藏规则。"""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "all.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("##.ad-box\n#@#.ad-box\n")
            generic, scoped, exc = lb.load_cosmetic(p)
        self.assertIn(("", ".ad-box"), exc)
        self.assertNotIn(".ad-box", lb.build_css(generic, scoped, exc, "any.test"))

    def test_negated_domain_applies_outside_excluded_site(self):
        """~site.test##sel 的语义是除该域外都生效。"""
        css = lb.build_css(set(), [("~site.test", ".banner")], set(), "other.test")
        self.assertIn(".banner{display:none!important}", css)

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


class TestScoring(unittest.TestCase):
    def test_empty_selectors_is_error_not_full_score(self):
        r = lb.score_visible([], {})
        self.assertEqual(0, r["score"])
        self.assertTrue(r["errors"])

    def test_unparsable_selector_is_error(self):
        r = lb.score_visible(["##bad"], {"##bad": None})
        self.assertEqual(0, r["score"])
        self.assertTrue(r["errors"])

    def test_zero_match_is_diagnostic_unless_every_selector_misses(self):
        # 单条 0 命中: 元素可能被 onerror 自行移除, 不算基线失配
        part = lb.score_visible(
            ["div.ad", "div.banner"],
            {"div.ad": {"matched": 0, "visible": 0, "non_rendered": 0},
             "div.banner": {"matched": 1, "visible": 0, "non_rendered": 1}})
        self.assertEqual(100, part["score"])
        self.assertEqual(["div.ad"], part["zero_match_selectors"])
        # 全部 0 命中: 快照/规则失配, 判 0
        whole = lb.score_visible(
            ["div.ad"],
            {"div.ad": {"matched": 0, "visible": 0, "non_rendered": 0}})
        self.assertEqual(0, whole["score"])
        self.assertTrue(any("基线可能失配" in e for e in whole["errors"]))

    def test_non_rendered_selector_is_reported_not_counted_as_leak(self):
        r = lb.score_visible(["param"],
                             {"param": {"matched": 2, "visible": 0, "non_rendered": 2}})
        self.assertEqual(100, r["score"])
        self.assertEqual({"param": 2}, r["non_rendered_selectors"])

    def test_visible_ads_reduce_score(self):
        r = lb.score_visible(["div.ad"],
                             {"div.ad": {"matched": 3, "visible": 2, "non_rendered": 0}})
        self.assertEqual(80, r["score"])
        self.assertEqual(2, r["visible_ad_elements"])


if __name__ == "__main__":
    unittest.main()
