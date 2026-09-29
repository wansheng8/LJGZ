# -*- coding: utf-8 -*-
"""含空格修饰符值的规则不得被误丢弃 (语法大全 §5: $csp / $dnsrewrite / $header 官方示例)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402

CASES = [
    "||example.com^$csp=script-src 'none'",
    "||example.com^$permissions=autoplay=()",
    "||example.com^$dnsrewrite=NOERROR;MX;32 example.mail",
    "||example.com^$dnsrewrite=NOERROR;SRV;10 60 8080 example.com",
    "||example.com^$dnsrewrite=NOERROR;TXT;hello world",
    "||example.com^$header=set-cookie:/foo\\, bar$/",
    "@@||example.com^$csp",
    "||example.com^$replace=/a b/c d/",
    "||example.com^$removeparam=utm source",   # 值含空格 (非典型但合法解析目标)
]


class TestWhitespaceModifierValues(unittest.TestCase):
    def test_not_dropped(self):
        for rule in CASES:
            r = mf.parse_line(rule)
            self.assertFalse(r.dropped, rule)
            self.assertIn(r.kind, (mf.K_NETWORK, mf.K_EXCEPTION, mf.K_DOMAIN), rule)

    def test_still_network_kind(self):
        r = mf.parse_line("||example.com^$csp=script-src 'none'")
        self.assertEqual(r.kind, mf.K_NETWORK)
        self.assertEqual(r.domain, "example.com")

    def test_hosts_line_still_works(self):
        r = mf.parse_line("0.0.0.0 ads.example.com")
        self.assertEqual(r.kind, mf.K_DOMAIN)
        self.assertEqual(r.domains, ("ads.example.com",))

    def test_junk_text_line_still_dropped(self):
        self.assertTrue(mf.parse_line("this is junk text").dropped)
        self.assertTrue(mf.parse_line("Copyright 2026 by someone").dropped)


if __name__ == "__main__":
    unittest.main()
