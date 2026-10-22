# -*- coding: utf-8 -*-
"""Issue 初筛: 表单域名解析 + 对照 all.txt 的结论。"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from tools import triage_issue as ti  # noqa: E402


class TestExtractDomain(unittest.TestCase):
    def test_form_field(self):
        body = "### 域名\n\nhttps://ads.example.com/banner.js\n\n### 页面 URL\n\nhttps://a.com"
        self.assertEqual("ads.example.com", ti.extract_domain(body))

    def test_title_fallback(self):
        self.assertEqual("ads.example.com", ti.extract_domain("", "[漏拦] ads.example.com"))

    def test_ignores_invalid(self):
        self.assertEqual("", ti.extract_domain("### 域名\n\n不是域名", ""))


class TestAnalyze(unittest.TestCase):
    def _all(self, lines):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self.addCleanup(os.remove, path)
        return path

    def test_blocked_by_parent(self):
        path = self._all(["||example.com^"])
        self.assertEqual("blocked", ti.analyze("ads.example.com", path)["verdict"])

    def test_partial_modifier_rule(self):
        path = self._all(["||example.com^$script"])
        self.assertEqual("partial", ti.analyze("example.com", path)["verdict"])

    def test_none(self):
        path = self._all(["||other.com^"])
        self.assertEqual("none", ti.analyze("example.com", path)["verdict"])

    def test_unconditional_exception(self):
        path = self._all(["||example.com^", "@@||example.com^"])
        self.assertEqual("excepted", ti.analyze("example.com", path)["verdict"])


class TestComment(unittest.TestCase):
    def test_comment_contains_verdict_and_marker(self):
        text = ti.build_comment("false-positive", "example.com",
                                {"verdict": "blocked", "matched": "example.com",
                                 "message": "命中域名级拦截：`||example.com^`"})
        self.assertIn("`example.com`", text)
        self.assertIn("<!-- triage: false-positive:example.com:blocked -->", text)


if __name__ == "__main__":
    unittest.main()
