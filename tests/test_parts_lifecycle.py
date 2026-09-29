# -*- coding: utf-8 -*-
"""分卷生命周期测试: 规则数减少时旧分卷必须被清理, 不能残留。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def _result(n_domains):
    res = mf.MergeResult()
    res.all_blocks = [f"||d{i:07d}.example.com^" for i in range(n_domains)]
    res.all_network, res.all_cosmetic, res.all_exceptions = [], [], []
    res.adguard_dns, res.hosts, res.domains = [], [], []
    res.whitelist = []
    res.stats = {"domains_unique": n_domains, "network_unique": 0,
                 "cosmetic_unique": 0, "exceptions_unique": 0,
                 "whitelist_unique": 0, "badfilter_targets": 0, "dropped": 0}
    return res


class TestPartLifecycle(unittest.TestCase):
    def test_stale_parts_removed(self):
        """3 卷 → 1 卷时, 旧 part-02/03 必须从输出目录删除。"""
        with tempfile.TemporaryDirectory() as td:
            # 第一轮: 小阈值 → 多卷
            mf.write_outputs(_result(100), td, title="t", now="x",
                             max_part_bytes=2000)
            n_before = len([f for f in os.listdir(td) if f.startswith("all-part")])
            self.assertGreaterEqual(n_before, 2)

            # 第二轮: 阈值放大 → 单卷 (all.txt 本身不切, 无 part 产出)
            mf.write_outputs(_result(100), td, title="t", now="x",
                             max_part_bytes=10_000_000)
            parts_after = [f for f in os.listdir(td) if f.startswith("all-part")]
            self.assertEqual(parts_after, [], f"旧分卷残留: {parts_after}")

    def test_parts_rewritten_each_run(self):
        """每轮重新写分卷 (旧内容不能与新 all.txt 混用)。"""
        with tempfile.TemporaryDirectory() as td:
            mf.write_outputs(_result(300), td, title="t", now="x",
                             max_part_bytes=2000)   # 300 条 ≈ 7.5KB → 4 卷
            p1 = os.path.join(td, "all-part-01.txt")
            self.assertTrue(os.path.exists(p1))
            with open(p1, encoding="utf-8") as f:
                first = f.read()
            # 第二轮同样小阈值 → 分卷仍在, 但内容应携带新标题
            mf.write_outputs(_result(300), td, title="t2", now="y",
                             max_part_bytes=2000)
            self.assertTrue(os.path.exists(p1))
            with open(p1, encoding="utf-8") as f:
                second = f.read()
            self.assertNotEqual(first, second, "分卷未随新数据重写")
            self.assertIn("! Title: t2", second)


if __name__ == "__main__":
    unittest.main()
