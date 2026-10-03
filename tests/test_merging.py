# -*- coding: utf-8 -*-
"""合并层测试: 语义去重 / 例外保护 / badfilter / 输出分类 (TDD — 先于实现编写)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def merge(*lines):
    """辅助: 把若干行解析后喂给 Merger, 返回 finalize 结果。"""
    m = mf.Merger()
    for ln in lines:
        m.add_rule(mf.parse_line(ln))
    return m.finalize()


class TestSemanticDedup(unittest.TestCase):
    def test_equivalent_forms_collapse_to_one(self):
        """||d^ ≡ d ≡ 0.0.0.0 d ≡ *.d — 同一域名只输出一条。"""
        res = merge(
            "||example.com^",
            "example.com",
            "0.0.0.0 example.com",
            "*.example.com",
        )
        self.assertEqual(res.adguard_blocks, ["||example.com^"])
        self.assertEqual(res.domains, ["example.com"])
        self.assertEqual(res.hosts, ["0.0.0.0 example.com"])
        self.assertEqual(res.all_blocks, ["||example.com^"])

    def test_exact_network_dedup(self):
        res = merge("||ads.com^$script", "||ads.com^$script")
        self.assertEqual(len(res.all_network), 1)

    def test_cosmetic_dedup(self):
        res = merge("example.com##.ad", "example.com##.ad")
        self.assertEqual(len(res.all_cosmetic), 1)

    def test_important_beats_plain(self):
        """同一域名普通拦截 + $important 拦截 → 保留 important 形式。"""
        res = merge("||example.com^", "||example.com^$important")
        self.assertEqual(res.adguard_blocks, ["||example.com^$important"])

    def test_case_insensitive_domain_merge(self):
        res = merge("||EXAMPLE.com^", "example.com")
        self.assertEqual(res.domains, ["example.com"])

    def test_hosts_multi_domain_line_expands(self):
        res = merge("0.0.0.0 a.com b.com")
        self.assertEqual(sorted(res.domains), ["a.com", "b.com"])


class TestExceptionProtection(unittest.TestCase):
    def test_dns_relevant_exception_removes_domain_block(self):
        """@@ 例外 → 该域名不进 hosts/domains/adguard 拦截输出, 但进白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$document")
        self.assertEqual(res.domains, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.adguard_blocks, [])
        self.assertIn("@@||ads.com^$document", res.whitelist)
        self.assertIn("@@||ads.com^$document", res.all_exceptions)

    def test_bare_dns_exception_dropped_but_domain_blocked(self):
        """无修饰符的整域 @@ 例外会被丢弃 (它会在浏览器端架空同域拦截),
        因此对应域名继续出现在拦截输出里 — 这是与旧行为的有意变更。
        见 test_bare_exception_arbitration 及 stats.dropped_bare_exceptions。"""
        res = merge("||ads.com^", "@@||ads.com^")
        self.assertIn("||ads.com^", res.all_blocks)
        self.assertEqual(res.dropped_bare_exceptions, 1)
        self.assertEqual(res.all_exceptions, [])

    def test_modified_dns_exception_still_removes_domain(self):
        """带修饰符的例外 (如 $document / $domain=x) 语义明确, 仍按旧逻辑
        把该域从拦截输出剔除并进白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$document")
        self.assertEqual(res.domains, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.adguard_blocks, [])
        self.assertIn("@@||ads.com^$document", res.whitelist)

    def test_important_block_beats_normal_exception(self):
        """$important 拦截压过普通例外 (上游设计保留): 带 $document 修饰符的
        例外仍会被 important 拦截盖住, 域名留在拦截输出。"""
        res = merge("||ads.com^$important", "@@||ads.com^$document")
        self.assertIn("||ads.com^$important", res.adguard_blocks)
        self.assertEqual(res.domains, ["ads.com"])

    def test_cosmetic_only_exception_does_not_unblock_dns(self):
        res = merge("||ads.com^", "@@||ads.com^$elemhide")
        self.assertEqual(res.domains, ["ads.com"])
        self.assertEqual(res.whitelist, [])   # 仅浏览器侧例外不进 DNS 白名单


class TestBadfilter(unittest.TestCase):
    def test_badfilter_kills_identical_rule(self):
        res = merge("||ads.com^$script", "||ads.com^$script,badfilter")
        self.assertEqual(res.all_network, [])

    def test_badfilter_does_not_kill_others(self):
        res = merge("||ads.com^$script", "||other.com^$script,badfilter")
        self.assertEqual(res.all_network, ["||ads.com^$script"])

    def test_badfilter_on_domain_rule(self):
        res = merge("||ads.com^", "||ads.com^$badfilter")
        self.assertEqual(res.all_blocks, [])
        self.assertEqual(res.domains, [])

    def test_modifier_order_irrelevant_for_badfilter(self):
        res = merge("||ads.com^$script", "||ads.com^$badfilter,script")
        self.assertEqual(res.all_network, [])


class TestOutputsSplit(unittest.TestCase):
    def test_dns_syntax_rules_go_to_adguard(self):
        res = merge("||example.com^$dnsrewrite=NOERROR;CNAME;example.net")
        self.assertIn("||example.com^$dnsrewrite=NOERROR;CNAME;example.net",
                      res.adguard_dns)

    def test_browser_only_rule_not_in_dns_outputs(self):
        res = merge("||ads.com^$script")
        self.assertEqual(res.adguard_dns, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.domains, [])

    def test_sorted_domain_output(self):
        res = merge("||b.com^", "||a.com^", "||c.com^")
        self.assertEqual(res.domains, ["a.com", "b.com", "c.com"])
        self.assertEqual(res.adguard_blocks,
                         ["||a.com^", "||b.com^", "||c.com^"])


class TestSubdomainCollapse(unittest.TestCase):
    def test_subdomain_collapsed_when_parent_blocked(self):
        res = merge("||example.com^", "||sub.example.com^")
        self.assertIn("||example.com^", res.adguard_blocks)
        self.assertNotIn("||sub.example.com^", res.adguard_blocks)
        # hosts/domains 为精确匹配语义, 保留子域
        self.assertEqual(sorted(res.domains), ["example.com", "sub.example.com"])

    def test_no_collapse_without_parent(self):
        res = merge("||sub.other.com^")
        self.assertEqual(res.adguard_blocks, ["||sub.other.com^"])

    def test_collapse_disabled_option(self):
        m = mf.Merger(collapse_subdomains=False)
        m.add_rule(mf.parse_line("||example.com^"))
        m.add_rule(mf.parse_line("||sub.example.com^"))
        res = m.finalize()
        self.assertIn("||sub.example.com^", res.adguard_blocks)


class TestStats(unittest.TestCase):
    def test_stats_counts(self):
        res = merge(
            "||example.com^",       # 域名
            "example.com",          # 重复域名
            "||ads.com^$script",    # 网络
            "##.ad",                # cosmetic
            "! comment",            # 丢弃
            "junk line here",       # 丢弃 (无有效域名)
        )
        st = res.stats
        self.assertEqual(st["domains_unique"], 1)
        self.assertEqual(st["network_unique"], 1)
        self.assertEqual(st["cosmetic_unique"], 1)
        self.assertEqual(st["dropped"], 2)


if __name__ == "__main__":
    unittest.main()
