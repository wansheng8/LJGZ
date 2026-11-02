# -*- coding: utf-8 -*-
"""解析器边界回归测试 (自审发现): 裸 IP / 空修饰符尾随 $。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class TestBareIp(unittest.TestCase):
    """hosts 文件里的裸 IP 行 (无域名) 是常见脏数据, 不能进网络规则输出。"""

    def test_bare_ipv4_dropped(self):
        for line in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4"):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, f"{line} 应丢弃, 实际 kind={r.kind}")
            self.assertEqual(r.kind, mf.K_INVALID, line)

    def test_bare_ipv6_dropped(self):
        for line in ("::1", "fe80::1", "::"):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, f"{line} 应丢弃, 实际 kind={r.kind}")

    def test_hosts_ip_with_domain_still_works(self):
        r = mf.parse_line("0.0.0.0 ads.example.com")
        self.assertFalse(r.dropped)
        self.assertEqual(r.domains, ("ads.example.com",))

    def test_ip_pattern_with_path_is_network(self):
        """URL 模式里带路径的 IP (如 ||1.2.3.4^$script) 仍是合法网络规则。"""
        r = mf.parse_line("||185.86.149.47^$script")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertFalse(r.dropped)


class TestTrailingDollar(unittest.TestCase):
    """`||domain^$` 尾随空 $ — 语法上等于无修饰符, 应按域名规则归并。"""

    def test_trailing_dollar_domain(self):
        r = mf.parse_line("||ads.com^$")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("ads.com",))

    def test_trailing_dollar_exception(self):
        r = mf.parse_line("@@||good.com^$")
        self.assertEqual(r.kind, mf.K_EXCEPTION)
        self.assertTrue(r.dns_relevant)      # 无实际修饰符 → DNS 相关

    def test_trailing_dollar_not_double_counted(self):
        m = mf.Merger()
        m.add_lines(["||ads.com^$", "||ads.com^"])
        res = m.finalize()
        self.assertEqual(len(res.all_blocks), 1)
        self.assertEqual(len(res.domains), 1)


class TestStrictDomain(unittest.TestCase):
    """域名校验必须是严格版 (≥2 标签 + 字母开头 TLD)。

    此前 scriptlet 校验器复用了同名 _DOMAIN_RE 并重新赋值, 把严格版覆盖成
    宽松版 (放行通配/下划线/纯数字 TLD/裸 IP), 导致 199 条畸形条目混进
    hosts 与纯域名产物。
    """

    def test_loose_forms_rejected(self):
        for bad in ("1.2.3.4", "142.91.159", "23.109.82", "1080.x.90",
                    "analytics-*.aasaam.com", "content_tracking.js",
                    "outlook.live.com._6tqjfb_hmyqup_npe6dhc",
                    "rgmechanicsgames.com*vpn.exe"):
            self.assertFalse(mf._is_domain(bad), bad)

    def test_hosts_line_with_malformed_domain_dropped(self):
        for line in ("0.0.0.0 analytics-*.aasaam.com",
                     "0.0.0.0 content_tracking.js",
                     "0.0.0.0 rgmechanicsgames.com*vpn.exe",
                     "0.0.0.0 23.109.82",
                     "0.0.0.0 1.2.3.4"):
            r = mf.parse_line(line)
            self.assertTrue(r.dropped, f"{line} 应丢弃, 实际 kind={r.kind}")

    def test_ip_anchor_is_network_rule(self):
        """||1.2.3.4^ 无处可归并为域名, 只能按网络规则留在 all.txt。"""
        r = mf.parse_line("||1.2.3.4^")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertFalse(r.dropped)


if __name__ == "__main__":
    unittest.main()
