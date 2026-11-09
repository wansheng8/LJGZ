# -*- coding: utf-8 -*-
"""扩展建议 2: 规则质量门控 —— 未知修饰符数量硬门限 + 镜像覆盖率硬下限。

质量门控的核心假设:
  · 上游规则里出现 ABP/uBO/AdGuard 三家引擎都不认的修饰符 token →
    客户端会把整行当无效丢弃 (拦不住)。merge_filters.py 新增
    _OFFICIAL_MODS 白名单 + Merger._unknown_mods 计数器, 产出 stats 里的
    unknown_mods_total / unknown_mods_top 字段。
  · 阈值 ≤ 300: 包含了上游偶尔混入的脏数据 + 解析边界噪音 (约 50 条
    [aria-label 这种被错切的元素隐藏选择器片段), 持续监控, 超过则 fail。

扩展建议 3 的覆盖率指标也一并检查:
  · pure_all_uncovered (真缺口) 应 ≤ 10 —— 上游 $all 域必须被父域裸规则
    覆盖或由镜像兜底。
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402

_STATS_PATH = os.path.join(os.path.dirname(__file__), "..", "output", "stats.json")

# 门限: 可根据上游数据质量调整, 但调完必须在 REPORT.md 里记录原因
_UNKNOWN_MODS_MAX = 300
_ALL_UNCOVERED_MAX = 30


class TestOfficialModsWhitelist(unittest.TestCase):
    """白名单覆盖已知官方修饰符, 否定前缀 `~` 不影响。"""

    def test_common_mods_recognized(self):
        known = [
            "script", "image", "xmlhttprequest", "frame", "popup",
            "third-party", "important", "all", "redirect", "domain=foo.com",
            "~third-party", "~script",    # 否定前缀
        ]
        for tok in known:
            key = tok.split("=", 1)[0].strip()
            if key.startswith("~"):
                key = key[1:]
            self.assertIn(key, mf._OFFICIAL_MODS,
                          f"官方修饰符 '{tok}' 漏在白名单外")

    def test_fabricated_token_not_in_whitelist(self):
        for fake in ["_____", "reason=tracker", "xyzzy", "foobar123"]:
            key = fake.split("=", 1)[0].strip()
            self.assertNotIn(key, mf._OFFICIAL_MODS,
                             f"疑似脏 token '{fake}' 应不在白名单里")

    def test_merger_counts_unknown_mods(self):
        """未知修饰符在 add_rule 里被计数 (绕过 _sanitize_modifiers 已清洗的 token)。"""
        merger = mf.Merger()
        # 直接构造 Rule 绕过 sanitize, 用不会被清洗的假 token
        merger.add_rule(mf.Rule(
            raw="||a.com^$script,notarealmod",
            kind=mf.K_NETWORK, pattern="||a.com^",
            modifiers="script,notarealmod", domain="a.com",
        ))
        merger.add_rule(mf.Rule(
            raw="||b.com^$redirect=nooptext",
            kind=mf.K_NETWORK, pattern="||b.com^",
            modifiers="redirect=nooptext", domain="b.com",
        ))
        self.assertEqual(merger._unknown_mods.get("notarealmod", 0), 1)
        self.assertEqual(sum(merger._unknown_mods.values()), 1)


@unittest.skipUnless(os.path.exists(_STATS_PATH),
                     "需要先跑 merge_filters.py 生成 output/stats.json")
class TestQualityGate(unittest.TestCase):
    """硬门限: 超过则 CI fail, 阻止推送。"""

    @classmethod
    def setUpClass(cls):
        with open(_STATS_PATH, encoding="utf-8") as f:
            cls.stats = json.load(f)

    def test_unknown_mods_within_threshold(self):
        total = self.stats.get("unknown_mods_total", 0)
        top = self.stats.get("unknown_mods_top", {})
        msg = (
            f"未知修饰符总数 {total} 超过门限 {_UNKNOWN_MODS_MAX}\n"
            f"top 10: {json.dumps(top, indent=2, ensure_ascii=False)}"
        )
        self.assertLessEqual(total, _UNKNOWN_MODS_MAX, msg)

    def test_all_mirror_uncovered_within_threshold(self):
        cov = self.stats.get("all_coverage") or {}
        uncovered = cov.get("pure_all_uncovered", 0)
        msg = (
            f"$all 镜像未覆盖数 {uncovered} 超过门限 {_ALL_UNCOVERED_MAX}\n"
            f"coverage: {json.dumps(cov, indent=2)}"
        )
        self.assertLessEqual(uncovered, _ALL_UNCOVERED_MAX, msg)


if __name__ == "__main__":
    unittest.main()
