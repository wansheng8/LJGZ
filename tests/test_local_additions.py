# -*- coding: utf-8 -*-
"""本地补充规则 (local-additions) 测试: 在 config 里声明的额外规则, 直接进 all.txt。

用途: 上游列表未覆盖的缺口 (如 adblock-tester.com 的 ymatuhin.ru 检测域),
不用等上游更新, 自主可控地补齐。
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class TestLocalAdditions(unittest.TestCase):
    def test_config_extra_rules_loaded(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write(json.dumps({"sources": [], "extra_rules": [
                    "||ymatuhin.ru^",
                    "adblock-tester.com###ads:custom",
                    "adblock-tester.com###banners"]}))
            extras = mf.load_extra_rules(cfg)
        self.assertIn("||ymatuhin.ru^", extras)
        self.assertEqual(len(extras), 3)

    def test_extras_flow_into_merge(self):
        extras = ["||ymatuhin.ru^", "adblock-tester.com###ads-custom"]
        m = mf.Merger()
        m.add_lines(extras, source="local-additions")
        res = m.finalize()
        self.assertIn("||ymatuhin.ru^", res.all_blocks)
        self.assertIn("adblock-tester.com###ads-custom", res.all_cosmetic)

    def test_extras_marked_in_stats(self):
        extras = ["||ymatuhin.ru^"]
        m = mf.Merger()
        m.add_lines(extras, source="local-additions")
        res = m.finalize()
        self.assertEqual(res.stats.get("local_additions"), 1)

    def test_run_applies_extras_from_config(self):
        """run() 应把 config 的 extra_rules 合入 (端到端)。"""
        import json
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "config.json")
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump({"sources": [
                    {"name": "s", "url": "https://x/l.txt"}],
                    "extra_rules": ["||ymatuhin.ru^"]}, f)
            outdir = os.path.join(td, "out")

            class T:
                def __call__(self, url, timeout=30):
                    return "||base.com^\n"

            report = mf.run(cfg, outdir=outdir, transport=T())
            with open(report["paths"]["all"], encoding="utf-8") as f:
                content = f.read()
            self.assertIn("||ymatuhin.ru^", content)
            self.assertIn("||base.com^", content)


if __name__ == "__main__":
    unittest.main()
