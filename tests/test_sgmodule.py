# -*- coding: utf-8 -*-
"""Shadowrocket 模块 (.sgmodule) 生成契约。

模块语法 (Surge 兼容): 顶部 `#!name` / `#!desc` 元信息, 之后段落头
`[Rule]`, 规则行为 `DOMAIN-SUFFIX,域名,REJECT|DIRECT`。Surge 系引擎
首个命中生效, 所以白名单 DIRECT 必须整体排在 REJECT 之前。
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import merge_filters as mf  # noqa: E402


def _res(blocks, whitelist):
    res = mf.MergeResult()
    res.adguard_blocks = list(blocks)
    res.whitelist = list(whitelist)
    res.stats = {}
    return res


class ShadowrocketModuleTest(unittest.TestCase):
    def _write(self, res, **kw):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return mf.write_shadowrocket_module(
            res, self.tmp.name, "测试模块", "2026-01-01 00:00:00", **kw)

    def test_header_and_rule_section(self):
        paths = self._write(_res(["||ads.example.com^", "||tracker.example.net^$important"],
                                 ["@@||safe.example.com^"]))
        with open(paths["shadowrocket"], encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertTrue(lines[0].startswith("#!name="), lines[0])
        self.assertTrue(any(ln.startswith("#!desc=") for ln in lines))
        self.assertIn("[Rule]", lines)
        self.assertLess(lines.index("[Rule]"), len(lines) - 1)

    def test_exception_precedes_reject(self):
        """父域 REJECT 与子域 DIRECT 共存时, DIRECT 必须先出现。"""
        paths = self._write(_res(["||example.com^"],
                                 ["@@||safe.example.com^$important"]))
        with open(paths["shadowrocket"], encoding="utf-8") as f:
            body = [ln for ln in f.read().splitlines() if ln.startswith("DOMAIN-SUFFIX,")]
        self.assertEqual(body[0], "DOMAIN-SUFFIX,safe.example.com,DIRECT")
        self.assertEqual(body[1], "DOMAIN-SUFFIX,example.com,REJECT")

    def test_rules_are_surge_syntax(self):
        paths = self._write(_res(
            ["||a.example.com^", "||b.example.com^$important",
             "/regex/", "||1.2.3.4^"],   # 后两条无法翻译, 必须被跳过
            ["@@||c.example.com^"]))
        with open(paths["shadowrocket"], encoding="utf-8") as f:
            body = [ln for ln in f.read().splitlines() if ln.startswith("DOMAIN-SUFFIX,")]
        self.assertEqual(body, [
            "DOMAIN-SUFFIX,c.example.com,DIRECT",
            "DOMAIN-SUFFIX,a.example.com,REJECT",
            "DOMAIN-SUFFIX,b.example.com,REJECT",
        ])

    def test_nested_rejects_deduplicated(self):
        """DOMAIN-SUFFIX 已连带子域, 父子同被拦截时只保留父域。"""
        paths = self._write(_res(["||example.com^", "||a.example.com^"], []))
        with open(paths["shadowrocket"], encoding="utf-8") as f:
            body = [ln for ln in f.read().splitlines() if ln.startswith("DOMAIN-SUFFIX,")]
        self.assertEqual(body, ["DOMAIN-SUFFIX,example.com,REJECT"])

    def test_no_abp_syntax_leaks(self):
        paths = self._write(_res(["||ads.example.com^"], []))
        with open(paths["shadowrocket"], encoding="utf-8") as f:
            text = f.read()
        for bad in ("##", "@@", "||", "^$"):
            self.assertNotIn(bad, text.replace("#!desc=", ""),
                             "模块里残留 ABP 语法: %r" % bad)

    def test_splits_when_over_size_limit(self):
        res = _res(["||d%05d.example.com^" % i for i in range(500)], [])
        paths = self._write(res, max_part_bytes=2000)
        self.assertNotIn("shadowrocket", paths)
        self.assertGreater(res.stats["shadowrocket_parts"], 1)
        first = paths["shadowrocket-part-01"]
        with open(first, encoding="utf-8") as f:
            self.assertIn("(1/", f.readline())
        for p in paths.values():
            self.assertLess(os.path.getsize(p), 2000)


if __name__ == "__main__":
    unittest.main()
