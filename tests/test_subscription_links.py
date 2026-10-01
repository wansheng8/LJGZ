# -*- coding: utf-8 -*-
"""
订阅链路健康检查。

背景: jsDelivr 有 20MB 单文件上限, 分卷卡在 18MB 边缘, 实测对 18MB 的
all-part-01.txt 反复返回 48 字节的 "Failed to fetch ... from GitHub."。
README 与订阅中心一度把它标成"国内推荐/首选", 导致用户订阅了一个必然
返回错误文本的地址 —— 浏览器扩展拿到的是错误字符串, 规则数 0, 分数
永远停在 74。本测试锁死两条规则:

1. GitHub Pages 必须是全站首选, jsDelivr 只能是备选。
2. 文档里的测试数量必须与实际套件一致 (防止文档腐烂)。
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
README = os.path.join(REPO, "README.md")
INDEX = os.path.join(REPO, "docs", "index.html")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class SubscriptionLinksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = _read(README)
        cls.index = _read(INDEX)

    def test_pages_is_listed_first_in_readme(self):
        """README 表格表头: 首选列必须是 GitHub Pages。"""
        header = next((l for l in self.readme.splitlines()
                       if l.startswith("| 场景")), "")
        self.assertIn("首选", header, "README 订阅表头缺少「首选」列: %r" % header)
        self.assertLess(header.index("Pages"), header.index("jsDelivr"),
                        "README 必须把 GitHub Pages 排在 jsDelivr 之前")

    def test_no_page_recommends_jsdelivr(self):
        """任何位置都不得再把 jsDelivr 称作推荐/首选。"""
        for name, text in (("README.md", self.readme),
                           ("docs/index.html", self.index)):
            for bad in ("CDN 推荐", "推荐 (国内 CDN)", "国内网络推荐订阅"):
                self.assertNotIn(
                    bad, text, "%s 仍把 jsDelivr 标为推荐: %r" % (name, bad))

    def test_jsdelivr_failure_is_documented(self):
        """既然 jsDelivr 不可靠, 文档必须明确告知用户症状与对策。"""
        for name, text in (("README.md", self.readme),
                           ("docs/index.html", self.index)):
            self.assertIn("jsDelivr", text, "%s 未提及 jsDelivr" % name)
            self.assertTrue(
                "Failed to fetch" in text or "分卷" in text,
                "%s 未说明 jsDelivr 失败症状" % name)

    def test_docs_test_count_matches_reality(self):
        """文档里的测试数必须等于实际用例数。"""
        actual = 0
        for f in os.listdir(os.path.join(REPO, "tests")):
            if f.startswith("test_") and f.endswith(".py"):
                src = _read(os.path.join(REPO, "tests", f))
                actual += len(re.findall(r"^\s+def test_", src, re.M))
        for name, text in (("README.md", self.readme),
                           ("docs/index.html", self.index)):
            for claim in re.findall(r"(\d+)\s*项(?:测试|, 无网络)", text):
                self.assertEqual(
                    int(claim), actual,
                    "%s 声称 %s 项测试, 实际 %d 项" % (name, claim, actual))

    def test_every_output_has_a_pages_url(self):
        """每个产物都必须有 Pages 直出地址 —— 唯一可靠的首选链路。"""
        names = re.findall(r"\| (?:🧩|🏠|🕳|📃|✅) \*\*[^*]+\*\*", self.readme)
        self.assertGreaterEqual(len(names), 5, "README 订阅表行数异常")
        for fname in ("all.txt", "adguard.txt", "hosts.txt",
                      "domains.txt", "whitelist.txt"):
            self.assertIn(
                "https://wansheng8.github.io/LJGZ/" + fname, self.readme,
                "README 缺少 %s 的 Pages 地址" % fname)


if __name__ == "__main__":
    unittest.main()
