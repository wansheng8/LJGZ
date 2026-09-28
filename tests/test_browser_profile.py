# -*- coding: utf-8 -*-
"""浏览器订阅优化测试: all.txt 应以「带类型网络规则 + cosmetic」为主体,
纯域名型 ||d^ 控制在合理比例内 (TDD — 先于实现编写)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def merge_rules(*lines):
    m = mf.Merger()
    for ln in lines:
        m.add_rule(mf.parse_line(ln))
    return m.finalize()


class TestBrowserOutputProfile(unittest.TestCase):
    """浏览器版输出: 有效规则为主体, 纯域名规则限量。"""

    def test_pure_domain_capped_when_typical_sources(self):
        """典型上游混合时, 浏览器版纯域名条目 ≤ 15万 (超过即截到阈值)。"""
        rules = []
        # 模拟 DNS 大列表 (10 万条纯域名)
        for i in range(100000):
            rules.append(f"||dns{i}.example.com^")
        # 模拟真实浏览器列表: typed + third-party 各 2 万
        for i in range(20000):
            rules.append(f"||typed{i}.example.com^$script")
            rules.append(f"site{i}.example.com##.ad-banner")
            rules.append(f"||net{i}.example.com^$third-party,domain=foo.com")
        res = merge_rules(*rules)
        # 浏览器输出: all_blocks 应被截到 ≤ 150000
        self.assertLessEqual(len(res.all_blocks), 150000)
        # 而网络规则 (typed 2万 + third-party 2万) / cosmetic 不受限
        self.assertEqual(len(res.all_network), 40000)
        self.assertEqual(len(res.all_cosmetic), 20000)

    def test_cap_not_applied_when_under_limit(self):
        """正常规模 (纯域名 < 阈值) 不截断。"""
        rules = [f"||d{i}.com^" for i in range(100)] + ["a.com##.x"]
        res = merge_rules(*rules)
        self.assertEqual(len(res.all_blocks), 100)

    def test_importance_preserved_when_capping(self):
        """截断时 $important 域名必须保留。"""
        rules = [f"||dns{i}.example.com^" for i in range(160000)]
        rules.append("||critical.example.com^$important")
        res = merge_rules(*rules)
        self.assertIn("||critical.example.com^$important", res.all_blocks)
        self.assertLessEqual(len(res.all_blocks), 150000)

    def test_whitelisted_domains_excluded_from_all(self):
        """被 @@ DNS 例外解锁的域名不应出现在浏览器拦截输出。"""
        res = merge_rules("||ads.com^", "@@||ads.com^$document")
        self.assertNotIn("||ads.com^", res.all_blocks)

    def test_ranking_important_first_within_cap(self):
        """截断时按「重要性」排序而非纯字典序: important > 普通。"""
        rules = [f"||dns{i:06d}.example.com^" for i in range(149999)]
        rules.append("||aaa0.example.com^$important")
        res = merge_rules(*rules)
        self.assertIn("||aaa0.example.com^$important", res.all_blocks)


if __name__ == "__main__":
    unittest.main()
