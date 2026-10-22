# -*- coding: utf-8 -*-
"""自研 scriptlet 规则: 加载、语法校验、合并进输出。

订阅只能调用客户端内置 scriptlet, 无法下发任意 JS —— 本测试锁定这条边界,
并确保语法错误的规则在合并前就报错, 而不是让整份订阅被扩展拒绝加载。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


class TestScriptletLoader(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_comments_ignored_and_rule_kept(self):
        path = self._write("! 注释\n\n# 也是注释\nyoutube.com##+js(json-prune, a b)\n")
        self.assertEqual(
            ["youtube.com##+js(json-prune, a b)"],
            mf.load_scriptlet_rules(path))

    def test_rejects_non_scriptlet_line(self):
        path = self._write("||example.com^\n")
        with self.assertRaises(ValueError):
            mf.load_scriptlet_rules(path)

    def test_rejects_unbalanced_parens(self):
        path = self._write("youtube.com##+js(json-prune, a b\n")
        with self.assertRaises(ValueError):
            mf.load_scriptlet_rules(path)

    def test_rejects_invalid_domain(self):
        path = self._write("not a domain##+js(noop)\n")
        with self.assertRaises(ValueError):
            mf.load_scriptlet_rules(path)

    def test_missing_file_is_empty(self):
        self.assertEqual([], mf.load_scriptlet_rules("no-such-file.txt"))

    def test_real_config_file_is_valid(self):
        rules = mf.load_scriptlet_file(os.path.join(REPO, "config.json"))
        self.assertGreaterEqual(len(rules), 1, "自研 scriptlet 文件为空")
        for ln in rules:
            self.assertEqual(ln.count("("), ln.count(")"), ln)
            self.assertRegex(ln, r"^[a-z0-9.-]+##\+js\([a-z0-9-]+", )


class TestScriptletMerge(unittest.TestCase):
    def test_rule_flows_into_all_output(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(os.path.join(td, "scriptlets.txt"), "w", encoding="utf-8") as f:
                f.write("youtube.com##+js(json-prune, playerAds)\n")
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump({"sources": [{"name": "s", "url": "https://x/l.txt"}],
                           "scriptlet_file": "scriptlets.txt"}, f)

            class T:
                def __call__(self, url, timeout=30):
                    return "||base.com^\n"

            report = mf.run(cfg, outdir=os.path.join(td, "out"), transport=T())
            with open(report["paths"]["all"], encoding="utf-8") as f:
                content = f.read()
            self.assertIn("youtube.com##+js(json-prune, playerAds)", content)
            self.assertGreaterEqual(report["stats"]["scriptlet_rules"], 1)


if __name__ == "__main__":
    unittest.main()
