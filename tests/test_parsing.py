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

    def test_hash_decorative_comment_dropped(self):
        """上游用 # 画的分隔注释不是元素隐藏规则 (## 后没有合法 id 选择器)。"""
        for line in ("###################################################",
                     "### Version: V1.2021.05.8588",
                     "##### Version Information #",
                     "##### Version Information ##"):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, line)
            self.assertEqual(r.kind, mf.K_COMMENT, line)

    def test_id_selector_after_hash_is_cosmetic(self):
        """真正的 ###id 规则仍须保留。"""
        for line in ("###AD_300", "###ad-area > .x", "###\\31 280_adv"):
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

    def test_scriptlet_with_regex_param_kept(self):
        """scriptlet 参数含正则字面量 /.../ 不应触发括号配对误判。"""
        lines = [
            "example.com##+js(acs, localStorage.removeItem, /^(ad|utm)/, 'gi')",
            "example.com##+js(rpnt, script, /url:.*?foo/, url: 'x')",
            "example.com##^script:has-text(/popunder|\\(\\)\\{/)",
            "example.com##div:has-text(/foo|bar/)",
        ]
        for line in lines:
            r = mf.parse_line(line)
            self.assertFalse(r.dropped, line)
            self.assertEqual(r.kind, mf.K_COSMETIC, line)

    def test_truncated_scriptlet_dropped(self):
        """上游截断的 scriptlet (参数体半截 / 引号未闭合) 客户端会整行跳过,
        留着只占体积 — parse_line 应直接丢弃。"""
        lines = [
            # 参数体被截断在字符串字面量里 ('\x 是随机哈希, 后面没有闭合引号)
            r"example.com##+js(acs, Math, localStorage['\x)",
            # rpnt 尾部残缺 (逗号和结束括号被截)
            r"example.com##+js(rpnt, script, /url:.*?'\,/, url: ''\,)",
            # HTML 过滤 + 正则片段未闭合
            r"example.com##^script:has-text(/popunder|\(\)\{try\{",
            # JS 片段参数未闭合
            r"example.com##+js(trusted-rpnt, script, (function($), '(function(){x()}));",
        ]
        for line in lines:
            r = mf.parse_line(line)
            self.assertTrue(r.dropped,
                            "截断 scriptlet 应被丢弃, 但 parse_line 返回 kind=%s: %s"
                            % (r.kind, line))
            self.assertEqual(r.kind, mf.K_INVALID)


class TestMaliciousPayloadFilter(unittest.TestCase):
    """上游源偶尔混进 PHP 后门片段 / base64 大块等 payload 规则。

    语法上合法, 客户端拿到也会尝试匹配 — 但正常站点绝不可能发这种 URL。
    parse_line 在不含锚点/正则的纯子串网络规则上应直接丢弃。
    """

    def test_php_microtime_token_substring_dropped(self):
        """spam 注册器生成的 md5(microtime()) URL 片段 (AdGuard 上游曾混入)。"""
        for line in (
            "%3C?php%20echo%20substr(md5(microtime()))$popup",
            "%3C?php%20echo%20substr(md5(microtime()),0,rand(10,30));?%3E&$doc",
        ):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, line)
            self.assertEqual(r.kind, mf.K_INVALID)

    def test_plain_php_tag_dropped(self):
        """明文 <?php 出现在 URL 片段里 — 正常站点绝不发送这种请求。"""
        r = mf.parse_line("example.com/?cmd=<?php eval($_GET[x]); ?>$script")
        self.assertTrue(r.dropped)
        self.assertEqual(r.kind, mf.K_INVALID)

    def test_base64_decode_backdoor_dropped(self):
        """base64_decode(大块 payload) — RFI / webshell 特征。"""
        payload = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5" * 5
        r = mf.parse_line(f"checkout.example.com/?k=base64_decode('{payload}')$script")
        self.assertTrue(r.dropped)

    def test_anchor_domain_and_regex_not_filtered(self):
        """锚点域 / 正则规则不做 payload 过滤 — 它们的 pattern 由语法形态约束,
        不可能被植入恶意片段, 误杀风险高。"""
        for line in ("||example.com^",
                     "/^https?:\\/\\/(?:www\\.)?ad\\./"):
            r = mf.parse_line(line)
            self.assertFalse(r.dropped, line)
            self.assertNotEqual(r.kind, mf.K_INVALID, line)

    def test_extra_rules_not_filtered(self):
        """本地 extra_rules 里所有规则不得被 payload 过滤误杀 — FORBIDDEN /
        EXPECTED_SAFE / adblock-tester 相关规则都走 parse_line。"""
        import json
        cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                "..", "config.json"))
        cfg = json.load(open(cfg_path, encoding="utf-8"))
        for rule in cfg.get("extra_rules", []):
            r = mf.parse_line(rule)
            self.assertFalse(r.dropped,
                             f"P2 payload 过滤误杀 extra_rules 里的 {rule!r}")


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
        """hosts 式与单行裸 .arpa 都属反向解析保留区, 一律丢弃。"""
        for line in ("0.0.0.0 1.0.0.127.in-addr.arpa", "0.0.0.0 x.ip6.arpa",
                     "1.0.0.127.in-addr.arpa", "X.IP6.ARPA",
                     "1.0.0.127.in-addr.arpa."):
            self.assertTrue(mf.parse_line(line).dropped, line)

    def test_pihole_regex_converted(self):
        """Pi-hole 两种子域正则顺序 + 精确匹配形状都归并为域名。"""
        for line in (r"(^|\.)doubleclick\.net$", r"(\.|^)doubleclick\.net$",
                     r"^doubleclick\.net$"):
            r = mf.parse_line(line)
            self.assertEqual(r.kind, mf.K_DOMAIN, line)
            self.assertEqual(r.domains, ("doubleclick.net",), line)

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

    def test_document_exception_not_dns_relevant(self):
        """$document 是浏览器内容类型, 不能升级为整域 DNS 放行。"""
        r = mf.parse_line("@@||example.com^$document")
        self.assertFalse(r.dns_relevant)
        self.assertTrue(mf.parse_line("@@||example.com^$important").dns_relevant)

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
