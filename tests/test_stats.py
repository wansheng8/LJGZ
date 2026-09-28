# -*- coding: utf-8 -*-
"""stats 语义修正回归测试: domains_unique 应与 DNS 输出一致, dropped 计全。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def merge(*lines):
    m = mf.Merger()
    m.add_lines(list(lines))
    return m.finalize()


class TestStatsSemantics(unittest.TestCase):
    def test_domains_unique_matches_dns_output(self):
        """被 @@ 例外解锁的域名不应计入 domains_unique。"""
        res = merge("||a.com^", "||b.com^", "@@||b.com^$document")
        self.assertEqual(res.stats["domains_unique"], 1)
        self.assertEqual(res.domains, ["a.com"])

    def test_dropped_counts_preproc_and_header(self):
        """注释/preproc/header 行都应计入 dropped (运行报告完整性)。"""
        res = merge("! comment", "!#include x.txt", "[Adblock Plus 2.0]",
                    "", "||a.com^")
        self.assertEqual(res.stats["dropped"], 4)

    def test_browser_cap_not_counted_as_domains_unique(self):
        """浏览器截断只影响 all_blocks, 不影响 domains_unique (DNS 输出为准)。"""
        lines = [f"||d{i}.example.com^" for i in range(10)]
        res = merge(*lines)
        self.assertEqual(res.stats["domains_unique"], 10)
        self.assertEqual(len(res.all_blocks), 10)


if __name__ == "__main__":
    unittest.main()
