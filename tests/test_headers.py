# -*- coding: utf-8 -*-
"""输出头与 CDN 分卷测试 (修复: ABP 头缺失 / all.txt 超 jsDelivr 20MB 上限)。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402

ABP_HEADER = "[Adblock Plus 2.0]"


def _sample_result():
    res = mf.MergeResult()
    res.all_blocks = ["||a{}.com^".format(i) for i in range(200)]
    res.all_network = ["||ads.com^$script"]
    res.all_cosmetic = ["example.com##.ad"]
    res.all_exceptions = ["@@||ok.com^"]
    res.adguard_dns = ["||a0.com^", "@@||ok.com^"]
    res.hosts = ["0.0.0.0 a0.com"]
    res.domains = ["a0.com"]
    res.whitelist = ["@@||ok.com^"]
    res.stats = {"domains_unique": 200, "network_unique": 1, "cosmetic_unique": 1,
                 "exceptions_unique": 1, "whitelist_unique": 1,
                 "badfilter_targets": 0, "dropped": 0}
    return res


class TestAbpHeader(unittest.TestCase):
    def test_all_txt_starts_with_abp_header(self):
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(_sample_result(), td, title="t", now="x")
            with open(paths["all"], encoding="utf-8") as f:
                self.assertEqual(f.readline().rstrip(), ABP_HEADER)

    def test_adguard_txt_starts_with_abp_header(self):
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(_sample_result(), td, title="t", now="x")
            with open(paths["adguard"], encoding="utf-8") as f:
                self.assertEqual(f.readline().rstrip(), ABP_HEADER)

    def test_abp_header_is_exactly_first_line(self):
        """头必须在第 1 行 (ABP 只认首行, 前面不能有空行/BOM)。"""
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(_sample_result(), td, title="t", now="x")
            with open(paths["all"], "rb") as f:
                first = f.read(len(ABP_HEADER))
            self.assertEqual(first.decode(), ABP_HEADER)


class TestCdnParts(unittest.TestCase):
    def test_chunk_by_bytes(self):
        chunks = mf._chunk_by_bytes(["aaaa"] * 10, max_bytes=12)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(sum(len(l) + 1 for l in c), 12)

    def test_chunk_preserves_all_lines_in_order(self):
        lines = ["line-{:03}".format(i) for i in range(50)]
        chunks = mf._chunk_by_bytes(lines, max_bytes=100)
        flat = [l for c in chunks for l in c]
        self.assertEqual(flat, lines)

    def test_write_outputs_splits_all_for_cdn(self):
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(_sample_result(), td, title="t", now="x",
                                     max_part_bytes=500)
            parts = sorted(k for k in paths if k.startswith("all-part"))
            self.assertGreaterEqual(len(parts), 2, "小阈值下应产生多个分卷")
            bodies = []
            for k in parts:
                with open(paths[k], encoding="utf-8") as f:
                    content = f.read()
                self.assertTrue(content.startswith(ABP_HEADER + "\n"), k)
                body = content.splitlines()[1:]
                # 去掉分卷自己的 ! 头部行
                body = [l for l in body
                        if not l.startswith("!") and l != ""]
                bodies.append(body)
            # 并集 == all.txt 正文 (去掉 ABP 头与 ! 注释后; 顺序无关比对)
            with open(paths["all"], encoding="utf-8") as f:
                all_body = [l for l in f.read().splitlines()[1:]
                            if not l.startswith("!") and l != ""]
            flat = [l for b in bodies for l in b]
            self.assertEqual(sorted(flat), sorted(all_body))
            self.assertEqual(len(flat), len(all_body))

    def test_parts_size_cap(self):
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(_sample_result(), td, title="t", now="x",
                                     max_part_bytes=400)
            for k, p in paths.items():
                if k.startswith("all-part"):
                    self.assertLess(os.path.getsize(p), 400 + 600,
                                    f"{k} 超出阈值 (含头部容差)")


if __name__ == "__main__":
    unittest.main()
