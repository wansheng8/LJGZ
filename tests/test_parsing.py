# -*- coding: utf-8 -*-
"""解析层测试: 各类规则行的词法分类 (TDD — 先于实现编写)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class TestDroppedLines(unittest.TestCase):
    """注释 / 预处理指令 / 头部行 / 空行 —— 应被丢弃并分类正确。"""

    def test_empty_and_blank(self):
        for line in ("", "   ", "\t"):
            self.assertTrue(mf.parse_line(line).dropped, repr(line))

    def test_comments(self):
        for line in ("! 这是注释", "# 这也是注释", "! Title: EasyList",
                     "! Version: 20260926", "! Last Modified: x", "# 127.0.0.1 local"):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, line)
            self.assertEqual(r.kind, mf.K_COMMENT, line)

    def test_preprocessor_directives(self):
        for line in ("!#include sub.txt", "!#if env_firefox", "!#else", "!#endif",
                     "!#platform chrome", "!#include /path/to/list.txt"):
            r = mf.parse_line(line)
            self.assertEqual(r.kind, mf.K_PREPROC, line)
            self.assertTrue(r.dropped, line)

    def test_list_header(self):
        for line in ("[Adblock Plus 2.0]", "[uBlock Origin 1.60.0]", "[AdGuard DNS]"):
            self.assertTrue(mf.parse_line(line).dropped, line)

    def test_junk_line_with_spaces_dropped(self):
        r = mf.parse_line("this is junk text with spaces")
        self.assertTrue(r.dropped)


class TestCosmetic(unittest.TestCase):
    """元素隐藏 / CSS / scriptlet / HTML 过滤类规则应整体保留为 cosmetic。"""

    def test_generic_cosmetic_starts_with_hash(self):
        for line in ("##.advert", '##div[id^="ad"]', "#@#.advert", "#?#div:has(>img.ad)"):
            r = mf.parse_line(line)
            self.assertFalse(r.dropped, line)
            self.assertEqual(r.kind, mf.K_COSMETIC, line)

    def test_cosmetic_variants(self):
        lines = [
            "example.com##.advert",
            "example.com,~mail.example.com##.sponsor",
            "example.com#@#.advert",
            "example.com#?#div:-abp-has(> div > img.advert)",
            "example.org#?#div:has(> a[target=\"_blank\"])",
            "example.com#$#body { background-color: #333!important; }",
            "example.com#$?#h3:contains(cookies) { display: none!important; }",
            "example.com#%#window.__gaq = undefined;",
            "example.com#@%#//scriptlet()",
            "example.com##+js(nobab)",
            "example.com##+js(set-constant, adBlock, false)",
            "example.com##^script:has-text(x)",
            'example.org$$script[data-src="banner"]',
            "example.org$@$script[data-src]",
            "example.org/checkout##.promo-banner",
            "[$domain=example.com]##.textad",
            "*##.selector",
        ]
        for line in lines:
            r = mf.parse_line(line)
            self.assertFalse(r.dropped, line)
            self.assertEqual(r.kind, mf.K_COSMETIC, line)


class TestDomainRules(unittest.TestCase):
    """`||domain^`、裸域名、*.domain、hosts 行、Pi-hole 正则 —— 归并为域名规则。"""

    def test_adblock_domain_anchor(self):
        r = mf.parse_line("||example.com^")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("example.com",))

    def test_domain_anchor_variants(self):
        self.assertEqual(mf.parse_line("||example.com").domains, ("example.com",))
        self.assertEqual(mf.parse_line("||EXAMPLE.com^").domains, ("example.com",))
        self.assertEqual(mf.parse_line("||sub.example.com^").domains, ("sub.example.com",))

    def test_wildcard_prefix(self):
        self.assertEqual(mf.parse_line("*.example.com").domains, ("example.com",))

    def test_bare_domain(self):
        r = mf.parse_line("example.com")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("example.com",))

    def test_fqdn_trailing_dot(self):
        self.assertEqual(mf.parse_line("example.com.").domains, ("example.com",))

    def test_hosts_lines(self):
        cases = [
            ("0.0.0.0 example.com", ("example.com",)),
            ("127.0.0.1\tads.example.com", ("ads.example.com",)),
            ("::1 ads.example.com", ("ads.example.com",)),
            ("0.0.0.0 example.com # 内联注释", ("example.com",)),
        ]
        for line, expected in cases:
            r = mf.parse_line(line)
            self.assertFalse(r.dropped, line)
            self.assertEqual(r.kind, mf.K_DOMAIN, line)
            self.assertEqual(r.domains, expected, line)

    def test_hosts_multiple_domains(self):
        r = mf.parse_line("0.0.0.0 a.com b.com")
        self.assertEqual(r.domains, ("a.com", "b.com"))

    def test_hosts_junk_tokens_skipped(self):
        r = mf.parse_line("0.0.0.0 a.com this is a hosts file comment")
        self.assertEqual(r.domains, ("a.com",))

    def test_hosts_localhost_dropped(self):
        for line in ("127.0.0.1 localhost", "::1 localhost ip6-localhost ip6-loopback",
                     "255.255.255.255 broadcasthost", "0.0.0.0 0.0.0.0",
                     "0.0.0.0 localhost.localdomain"):
            self.assertTrue(mf.parse_line(line).dropped, line)

    def test_reserved_arpa_dropped(self):
        for line in ("0.0.0.0 1.0.0.127.in-addr.arpa", "0.0.0.0 x.ip6.arpa"):
            self.assertTrue(mf.parse_line(line).dropped, line)

    def test_pihole_regex_converted(self):
        r = mf.parse_line(r"(^|\.)doubleclick\.net$")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("doubleclick.net",))

    def test_important_modifier_counts_as_domain(self):
        r = mf.parse_line("||example.com^$important")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("example.com",))


class TestNetworkRules(unittest.TestCase):
    """带内容类型修饰符的规则、正则模式、地址锚点模式 —— 保留为网络规则。"""

    def test_typed_network_rule(self):
        r = mf.parse_line("||example.com^$script")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertEqual(r.pattern, "||example.com^")
        self.assertEqual(r.modifiers, "script")
        self.assertEqual(r.domain, "example.com")
        self.assertFalse(r.dropped)

    def test_multiple_modifiers(self):
        r = mf.parse_line("||example.com^$script,image,domain=foo.com|~bar.com")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertIn("script", r.modifiers)
        self.assertIn("domain=foo.com", r.modifiers)

    def test_regex_pattern(self):
        r = mf.parse_line(r"/banner\d+/")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertEqual(r.pattern, r"/banner\d+/")
        self.assertEqual(r.modifiers, "")

    def test_regex_pattern_with_modifiers(self):
        r = mf.parse_line(r"/banner\d+/$third-party")
        self.assertEqual(r.pattern, r"/banner\d+/")
        self.assertEqual(r.modifiers, "third-party")

    def test_pipe_anchor(self):
        r = mf.parse_line("|http://ads.example.com/|")
        self.assertEqual(r.kind, mf.K_NETWORK)

    def test_substring_pattern(self):
        r = mf.parse_line("-banner-")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertFalse(r.dropped)

    def test_dnsrewrite_stays_network(self):
        r = mf.parse_line("||example.com^$dnsrewrite=NOERROR;CNAME;example.net")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertIn("dnsrewrite", r.modifiers)

    def test_badfilter_flagged(self):
        r = mf.parse_line("||ads.com^$badfilter")
        self.assertIn("badfilter", r.modifiers)
        r = mf.parse_line("*$script,badfilter")
        self.assertIn("badfilter", r.modifiers)

    def test_wildcard_suffix_is_network(self):
        # uBO: example.com* 表示"任意位置匹配", 不是域名规则
        r = mf.parse_line("example.com*")
        self.assertEqual(r.kind, mf.K_NETWORK)


class TestExceptions(unittest.TestCase):
    """@@ 例外规则: DNS 相关性判定。"""

    def test_basic_exception(self):
        r = mf.parse_line("@@||example.com^")
        self.assertEqual(r.kind, mf.K_EXCEPTION)
        self.assertTrue(r.dns_relevant)
        self.assertEqual(r.domain, "example.com")
        self.assertFalse(r.dropped)

    def test_document_exception_is_dns_relevant(self):
        self.assertTrue(mf.parse_line("@@||example.com^$document").dns_relevant)

    def test_cosmetic_exceptions_not_dns_relevant(self):
        for line in ("@@||example.com^$elemhide", "@@||example.com^$generichide",
                     "@@||example.com^$specifichide", "@@||example.com^$jsinject",
                     "@@||example.com^$stealth", "@@||example.com^$content"):
            r = mf.parse_line(line)
            self.assertEqual(r.kind, mf.K_EXCEPTION, line)
            self.assertFalse(r.dns_relevant, line)

    def test_client_exception_not_dns_relevant(self):
        r = mf.parse_line(r"@@||example.com^$client='Frank\'s laptop'")
        self.assertEqual(r.kind, mf.K_EXCEPTION)
        self.assertFalse(r.dns_relevant)


if __name__ == "__main__":
    unittest.main()
