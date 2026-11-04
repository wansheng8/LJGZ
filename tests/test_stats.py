# -*- coding: utf-8 -*-
"""stats 口径回归测试: 四类计数之和必须等于 all.txt 的实际规则行数。"""
import os
import json
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def merge(*lines):
    m = mf.Merger()
    m.add_lines(list(lines))
    return m.finalize()


class TestStatsSemantics(unittest.TestCase):
    def test_domains_unique_matches_all_txt_domain_rules(self):
        """domains_unique 计 all.txt 中的域名规则行 (折叠后), 不再按 DNS
        精确域集合计 —— 后者另含已折叠的子域。"""
        res = merge("||example.com^", "||sub.example.com^")
        self.assertEqual(res.stats["domains_unique"], 1)
        self.assertEqual(res.all_blocks, ["||example.com^"])
        # hosts/domains 精确匹配语义, 子域仍单独成条
        self.assertEqual(sorted(res.domains), ["example.com", "sub.example.com"])

    def test_domains_unique_keeps_exception_domain(self):
        """浏览器层不剔例外: all.txt 仍含该拦截行, 故仍计入 domains_unique;
        只有 DNS 域集合 (domains.txt) 会剔除它。"""
        res = merge("||a.com^", "||b.com^", "@@||b.com^$important")
        self.assertEqual(res.stats["domains_unique"], 2)
        self.assertEqual(res.domains, ["a.com"])

    def test_domains_lines_matches_domains_txt(self):
        """domains_lines 必须等于 domains.txt 行数, 且徽章取的是它 ——
        用户拿徽章数字去数文件行数得对得上。"""
        res = merge("||a.com^", "||sub.a.com^")
        self.assertEqual(res.stats["domains_lines"], len(res.domains))
        self.assertEqual(res.stats["domains_lines"], 2)   # 折叠前: a + sub.a
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="t", now="x")
            with open(paths["domains"], encoding="utf-8") as f:
                body = [l for l in f.read().splitlines()
                        if l and not l.startswith("#")]
            with open(paths["badge-domains"], encoding="utf-8") as f:
                badge = json.load(f)
        self.assertEqual(len(body), res.stats["domains_lines"])
        self.assertEqual(badge["message"], "2")            # 不足一万显原数

    def test_stats_sum_equals_all_txt_header(self):
        """四类计数之和 == all.txt 头部 `! Rules` 所报的实际行数。"""
        res = merge("||a.com^", "||sub.a.com^", "||ads.com^$script",
                    "example.com##.ad", "@@||ok.com^$important", "! comment")
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="t", now="x")
            with open(paths["all"], encoding="utf-8") as f:
                lines = f.read().splitlines()
        rule_lines = [l for l in lines[1:] if l and not l.startswith("!")]
        st = res.stats
        self.assertEqual(
            st["domains_unique"] + st["network_unique"] +
            st["cosmetic_unique"] + st["exceptions_unique"],
            len(rule_lines))

    def test_dropped_counts_preproc_and_header(self):
        """注释/preproc/header 行都应计入 dropped (运行报告完整性)。"""
        res = merge("! comment", "!#include x.txt", "[Adblock Plus 2.0]",
                    "", "||a.com^")
        self.assertEqual(res.stats["dropped"], 4)


if __name__ == "__main__":
    unittest.main()
