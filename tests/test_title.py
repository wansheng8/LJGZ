# -*- coding: utf-8 -*-
"""标题重复 bug 的回归测试 (run 传入 title 不应出现两次)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class TestTitleFormatting(unittest.TestCase):
    def test_no_duplicate_title(self):
        lines = mf._header_lines("MyList", "2026-09-27 00:00", 1, "全格式")
        title = next(l for l in lines if l.startswith("! Title:"))
        self.assertEqual(title, "! Title: MyList · 全格式")

    def test_default_title_when_empty(self):
        lines = mf._header_lines("", "t", 1, "hosts")
        title = next(l for l in lines if l.startswith("! Title"))
        self.assertEqual(title, "! Title: AdFilter Merge Base · hosts")


if __name__ == "__main__":
    unittest.main()
