# -*- coding: utf-8 -*-
"""离线覆盖率跑分: 评分逻辑 + 真实样本回归。"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import benchmark  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXPECT = os.path.join(REPO, "benchmarks", "expectations.json")


class TestScoring(unittest.TestCase):
    def _evaluate(self, rules, expect):
        with tempfile.TemporaryDirectory() as td:
            all_path = os.path.join(td, "all.txt")
            with open(all_path, "w", encoding="utf-8") as f:
                f.write(rules)
            exp_path = os.path.join(td, "exp.json")
            with open(exp_path, "w", encoding="utf-8") as f:
                json.dump(expect, f)
            return benchmark.evaluate(all_path, exp_path)

    def test_parent_domain_blocks_subdomain(self):
        res = self._evaluate("||example.com^\n",
                             {"must_block": ["ads.example.com"], "must_not_block": []})
        self.assertEqual(1, res["coverage"]["hit"])

    def test_exception_protects_parent_and_children(self):
        res = self._evaluate("||example.com^\n@@||example.com^\n",
                             {"must_block": [], "must_not_block": ["a.example.com"]})
        self.assertEqual([], res["safety"]["false_positives"])

    def test_safety_and_coverage_are_weighted(self):
        res = self._evaluate("||ad.test^\n",
                             {"must_block": ["ad.test", "missing.test"],
                              "must_not_block": ["safe.test"]})
        self.assertEqual(50.0, res["coverage"]["rate"])
        self.assertEqual(100.0, res["safety"]["rate"])
        self.assertEqual(55.0, res["score"])  # 50*0.5 + 100*0.3 + 无样本*0.2

    def test_missing_domains_reported(self):
        res = self._evaluate("||ad.test^\n", {"must_block": ["ad.test", "gone.test"]})
        self.assertEqual(["gone.test"], res["coverage"]["missing"])


class TestRealOutput(unittest.TestCase):
    def test_expectations_are_valid(self):
        with open(EXPECT, encoding="utf-8") as f:
            exp = json.load(f)
        self.assertGreaterEqual(len(exp["must_block"]), 20)
        self.assertGreaterEqual(len(exp["must_not_block"]), 20)
        overlap = set(exp["must_block"]) & set(exp["must_not_block"])
        self.assertEqual(set(), overlap, "同一域名不能既要求拦又要求放行")

    def test_proxy_exclusions_match_safety_tests(self):
        from tests.test_safe_tracking_domains import FORBIDDEN
        with open(EXPECT, encoding="utf-8") as f:
            exp = json.load(f)
        self.assertEqual(set(FORBIDDEN), set(exp["proxy_exclude"]),
                         "跑分排除项必须与安全测试的禁拦清单一致")

    def test_current_output_scores_high(self):
        all_path = os.path.join(REPO, "output", "all.txt")
        if not os.path.exists(all_path):
            self.skipTest("缺少 output/all.txt")
        res = benchmark.evaluate(all_path, EXPECT)
        self.assertEqual([], res["coverage"]["missing"], "应拦样本出现漏拦")
        self.assertEqual([], res["safety"]["false_positives"], "关键站点被整域误伤")
        self.assertGreaterEqual(res["score"], 95.0)


if __name__ == "__main__":
    unittest.main()
