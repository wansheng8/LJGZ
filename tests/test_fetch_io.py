# -*- coding: utf-8 -*-
"""下载层与输出层测试: fetch 重试 / 输出文件 / 北京时间头部 (TDD — 先于实现编写)。"""
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class _FakeTransport:
    """可编排响应/异常的假下载器。"""
    def __init__(self, responses):
        self.responses = list(responses)   # 每项: str 文本 或 Exception
        self.calls = []

    def __call__(self, url, timeout=30):
        self.calls.append(url)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestFetch(unittest.TestCase):
    def test_fetch_returns_text(self):
        t = _FakeTransport(["line1\nline2\n"])
        text = mf.fetch_text("https://example.com/list.txt", transport=t)
        self.assertEqual(text, "line1\nline2\n")

    def test_fetch_retries_on_transient_error(self):
        t = _FakeTransport([OSError("boom"), OSError("boom"), "ok\n"])
        text = mf.fetch_text("https://example.com/l.txt", transport=t,
                             retries=3, retry_delay=0)
        self.assertEqual(text, "ok\n")
        self.assertEqual(len(t.calls), 3)

    def test_fetch_gives_up_after_max_retries(self):
        t = _FakeTransport([OSError("down")] * 5)
        with self.assertRaises(mf.FetchError):
            mf.fetch_text("https://example.com/l.txt", transport=t,
                          retries=3, retry_delay=0)

    def test_fetch_does_not_retry_http_404(self):
        t = _FakeTransport([mf.HTTPStatusError(404)])
        with self.assertRaises(mf.FetchError):
            mf.fetch_text("https://example.com/l.txt", transport=t,
                          retries=3, retry_delay=0)
        self.assertEqual(len(t.calls), 1)


class TestSourceParsing(unittest.TestCase):
    def test_load_sources_from_json_config(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write('{"sources": ['
                        '{"name": "easylist", "url": "https://x/easylist.txt"},'
                        '{"name": "hosts", "url": "https://x/hosts.txt", "enabled": false}'
                        ']}')
            srcs = mf.load_sources(cfg)
        self.assertEqual(len(srcs), 1)
        self.assertEqual(srcs[0]["name"], "easylist")

    def test_load_sources_dedups_urls(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write('{"sources": ['
                        '{"name": "a", "url": "https://x/l.txt"},'
                        '{"name": "b", "url": "https://x/l.txt"}'
                        ']}')
            srcs = mf.load_sources(cfg)
        self.assertEqual(len(srcs), 1)


class TestWriteOutputs(unittest.TestCase):
    def _merged(self):
        res = mf.MergeResult()
        res.all_blocks = ["||a.com^"]
        res.all_network = ["||ads.com^$script"]
        res.all_cosmetic = ["example.com##.ad"]
        res.all_exceptions = ["@@||ok.com^"]
        res.adguard_dns = ["||a.com^", "@@||ok.com^"]
        res.hosts = ["0.0.0.0 a.com"]
        res.domains = ["a.com"]
        res.whitelist = ["@@||ok.com^"]
        res.stats = {"domains_unique": 1, "network_unique": 1, "cosmetic_unique": 1,
                     "exceptions_unique": 1, "whitelist_unique": 1,
                     "badfilter_targets": 0, "dropped": 0}
        return res

    def test_writes_all_output_files(self):
        res = self._merged()
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="-test", now="2026-09-27 08:00")
            for p in paths.values():
                self.assertTrue(os.path.exists(p), p)
            with open(paths["all"], encoding="utf-8") as f:
                head = f.read()
            self.assertIn("! Title: -test · 全格式", head)
            self.assertIn("2026-09-27 08:00", head)      # 北京时间
            self.assertIn("||a.com^", head)
            self.assertIn("||ads.com^$script", head)
            self.assertIn("example.com##.ad", head)
            self.assertIn("@@||ok.com^", head)
            with open(paths["hosts"], encoding="utf-8") as f:
                h = f.read()
            self.assertIn("0.0.0.0 a.com", h)
            with open(paths["domains"], encoding="utf-8") as f:
                self.assertEqual(f.read().strip().splitlines()[-1], "a.com")

    def test_hosts_file_is_valid_hosts_syntax(self):
        res = self._merged()
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="t", now="x")
            with open(paths["hosts"], encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self.assertRegex(line, r"^0\.0\.0\.0 \S+$")

    def test_stats_json_written(self):
        res = self._merged()
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="t", now="x")
            self.assertIn("stats", paths)
            with open(paths["stats"], encoding="utf-8") as f:
                import json
                st = json.load(f)
            self.assertEqual(st["domains_unique"], 1)


if __name__ == "__main__":
    unittest.main()
