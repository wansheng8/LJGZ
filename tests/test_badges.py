# -*- coding: utf-8 -*-
"""shields.io endpoint 徽章数据文件生成测试 (TDD — 先于实现编写)。"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402

STATS = {
    "domains_unique": 449997,
    "network_unique": 25770,
    "cosmetic_unique": 31524,
    "exceptions_unique": 2898,
    "whitelist_unique": 124,
    "badfilter_targets": 5,
    "dropped": 9657,
}


class TestBadgeFiles(unittest.TestCase):
    def _write(self, td):
        mf.write_badge_files(td, STATS, "2026-09-27 02:41:00 +0800")
        out = {}
        for name in ("badge-domains.json", "badge-rules.json", "badge-updated.json"):
            with open(os.path.join(td, name), encoding="utf-8") as f:
                out[name] = json.load(f)
        return out

    def test_endpoint_schema(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._write(td)
        for name, badge in b.items():
            self.assertEqual(badge["schemaVersion"], 1, name)
            self.assertIn("label", badge)
            self.assertIn("message", badge)
            self.assertRegex(badge["color"], r"^[0-9A-Fa-f]{6}$", name)
            self.assertLessEqual(badge.get("cacheSeconds", 0), 3600, name)

    def test_domains_badge_content(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._write(td)
        self.assertEqual(b["badge-domains.json"]["label"], "拦截域名")
        self.assertEqual(b["badge-domains.json"]["message"], "45.0万")

    def test_rules_badge_counts_all_types(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._write(td)
        # 449997+25770+31524+2898 = 510189 → 51.0万
        self.assertEqual(b["badge-rules.json"]["label"], "规则总数")
        self.assertEqual(b["badge-rules.json"]["message"], "51.0万")

    def test_small_counts_not_in_wan(self):
        with tempfile.TemporaryDirectory() as td:
            mf.write_badge_files(td, {**STATS, "domains_unique": 123},
                                 "2026-09-27 02:41:00 +0800")
            with open(os.path.join(td, "badge-domains.json"), encoding="utf-8") as f:
                badge = json.load(f)
        self.assertEqual(badge["message"], "123")

    def test_updated_badge_strips_timezone(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._write(td)
        self.assertEqual(b["badge-updated.json"]["label"], "北京时间更新")
        self.assertIn("2026-09-27 02:41", b["badge-updated.json"]["message"])
        self.assertNotIn("+0800", b["badge-updated.json"]["message"])

    def test_write_outputs_includes_badges(self):
        res = mf.MergeResult()
        res.stats = STATS
        with tempfile.TemporaryDirectory() as td:
            paths = mf.write_outputs(res, td, title="t", now="2026-09-27 02:41:00 +0800")
            self.assertIn("badge-domains", paths)
            self.assertTrue(os.path.exists(paths["badge-domains"]))


if __name__ == "__main__":
    unittest.main()
