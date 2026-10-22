# -*- coding: utf-8 -*-
"""浏览器订阅完整性测试: 全格式 all.txt 必须包含全部规则 (含所有 ||d^),
不能因体积阈值静默截断域名。"""
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
    """浏览器版输出: 有效规则为主体, 纯域名规则全量保留。"""

    def test_all_pure_domains_kept(self):
        """典型上游混合时, 浏览器版纯域名条目不得被截断。"""
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
        # 全部 10 万纯域名 + 2 万 typed + 2 万 third-party 均须保留
        self.assertEqual(len(res.all_blocks), 100000)
        self.assertEqual(len(res.all_network), 40000)
        self.assertEqual(len(res.all_cosmetic), 20000)

    def test_cap_not_applied_when_under_limit(self):
        """正常规模 (纯域名 < 阈值) 不截断。"""
        rules = [f"||d{i}.com^" for i in range(100)] + ["a.com##.x"]
        res = merge_rules(*rules)
        self.assertEqual(len(res.all_blocks), 100)

    def test_importance_preserved(self):
        """超大规模下 $important 域名仍必须保留。"""
        rules = [f"||dns{i}.example.com^" for i in range(160000)]
        rules.append("||critical.example.com^$important")
        res = merge_rules(*rules)
        self.assertIn("||critical.example.com^$important", res.all_blocks)
        self.assertEqual(len(res.all_blocks), 160001)

    def test_whitelisted_domains_excluded_from_all(self):
        """被 @@ DNS 例外解锁的域名不应出现在浏览器拦截输出。"""
        res = merge_rules("||ads.com^", "@@||ads.com^$document")
        self.assertNotIn("||ads.com^", res.all_blocks)

    def test_no_silent_domain_loss(self):
        """大规模纯域名不得因字典序截断而丢尾部域名。"""
        rules = [f"||dns{i:06d}.example.com^" for i in range(149999)]
        rules.append("||zzz-last.example.com^")
        res = merge_rules(*rules)
        self.assertIn("||zzz-last.example.com^", res.all_blocks)
        self.assertEqual(len(res.all_blocks), 150000)


if __name__ == "__main__":
    unittest.main()
