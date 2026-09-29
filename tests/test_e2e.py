# -*- coding: utf-8 -*-
"""端到端集成测试: run() 主流程 (注入假下载, 不真实联网)。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class _FakeTransport:
    def __init__(self, mapping):
        self.mapping = mapping   # url -> text
        self.calls = []

    def __call__(self, url, timeout=30):
        self.calls.append(url)
        if url not in self.mapping:
            raise mf.HTTPStatusError(404)
        return self.mapping[url]


EASYLIST = """! Title: EasyList (测试样本)
[Adblock Plus 2.0]
||doubleclick.net^
||ads.example.com^$script
example.com##.advert
@@||good.example.com^$document
"""

HOSTS_LIST = """# hosts 测试样本
0.0.0.0 ads.example.com
0.0.0.0 tracker.io
127.0.0.1 localhost
"""

BARE_DOMAINS = "doubleclick.net\npihole.net\n"


class TestRunEndToEnd(unittest.TestCase):
    def _run(self, transport, **kw):
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                import json
                json.dump({"sources": [
                    {"name": "easylist", "url": "https://x/easylist.txt"},
                    {"name": "hosts", "url": "https://x/hosts.txt"},
                    {"name": "bare", "url": "https://x/domains.txt"},
                ], "title": "E2E"}, f)
            outdir = os.path.join(td, "out")
            report = mf.run(cfg, outdir=outdir, transport=transport, **kw)
            files = {}
            for key, p in report["paths"].items():
                with open(p, encoding="utf-8") as fh:
                    files[key] = fh.read()
        return report, files

    def test_merged_outputs_from_three_sources(self):
        t = _FakeTransport({
            "https://x/easylist.txt": EASYLIST,
            "https://x/hosts.txt": HOSTS_LIST,
            "https://x/domains.txt": BARE_DOMAINS,
        })
        report, files = self._run(t)

        # 三源都拉取了
        self.assertEqual(len(t.calls), 3)
        # 域名合并: doubleclick.net (easylist≡bare 重复), tracker.io, pihole.net
        # 例外剔除: good.example.com 不进 DNS 输出
        self.assertIn("0.0.0.0 tracker.io", files["hosts"])
        self.assertIn("0.0.0.0 pihole.net", files["hosts"])
        self.assertNotIn("good.example.com", files["hosts"])
        self.assertNotIn("localhost", files["hosts"])
        # all 输出含 browsers 语法
        self.assertIn("example.com##.advert", files["all"])
        self.assertIn("||ads.example.com^$script", files["all"])
        self.assertIn("@@||good.example.com^$document", files["all"])
        # adguard 输出: 纯 ||d^ + 白名单, dnsrewrite 网络规则
        self.assertIn("||doubleclick.net^", files["adguard"])
        self.assertIn("@@||good.example.com^$document", files["adguard"])
        self.assertNotIn("||ads.example.com^$script", files["adguard"])
        # 网络规则 ||ads.example.com^$script 不能进 hosts/domains
        self.assertNotIn("||ads.example.com^$script", files["hosts"])
        # 报告含每源统计
        self.assertEqual(report["sources_ok"], 3)
        self.assertEqual(report["sources_failed"], 0)

    def test_failed_source_does_not_crash_run(self):
        t = _FakeTransport({
            "https://x/easylist.txt": EASYLIST,
            # hosts.txt 和 domains.txt → 404
        })
        report, files = self._run(t)
        self.assertEqual(report["sources_ok"], 1)
        self.assertEqual(report["sources_failed"], 2)
        self.assertIn("||doubleclick.net^", files["all"])

    def test_domains_duplicates_removed_across_sources(self):
        t = _FakeTransport({
            "https://x/easylist.txt": "||doubleclick.net^\n||doubleclick.net^\n",
            "https://x/hosts.txt": "0.0.0.0 doubleclick.net\n",
            "https://x/domains.txt": "doubleclick.net\n",
        })
        report, files = self._run(t)
        self.assertEqual(files["domains"].count("doubleclick.net"), 1)
        self.assertEqual(files["hosts"].count("0.0.0.0 doubleclick.net"), 1)



class TestStatsJsonIncludesSources(unittest.TestCase):
    def test_stats_json_has_sources(self):
        import json as _json
        t = _FakeTransport({
            "https://x/easylist.txt": EASYLIST,
            # hosts.txt 404 → failed
        })
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                _json_write = _json  # noqa
                f.write(_json.dumps({"sources": [
                    {"name": "easylist", "url": "https://x/easylist.txt"},
                    {"name": "hosts", "url": "https://x/hosts.txt"},
                ]}))
            outdir = os.path.join(td, "out")
            report = mf.run(cfg, outdir=outdir, transport=t)
            with open(os.path.join(outdir, "stats.json"), encoding="utf-8") as f:
                stats = _json.load(f)
        self.assertEqual(stats["sources_ok"], 1)
        self.assertEqual(stats["sources_failed"], 1)
        self.assertEqual(stats["sources_total"], 2)


if __name__ == "__main__":
    unittest.main()
