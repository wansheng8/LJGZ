# -*- coding: utf-8 -*-
"""
裸整域例外仲裁回归。

历史教训: 上游易易里 314 条无修饰符的 `@@||d^` (整域无条件放行)。它们会
全局架空对应域的所有拦截规则 — uBO 加载 all.txt 时例外优先匹配, 这些域
就从"拦截列表"漏出去, 用户表现为"订阅了却没拦住"。实测 23 个上游域
(awin1 / crwdcntrl / costco data.* / dotomi ...) 和我方 2 个域
(app.adjust.com / metrics.icloud.com) 的拦截全部被打穿。

仲裁策略: 丢弃无修饰符的整域例外 (它们语义最模糊 — 上游本意多为放行
"合法点击链接"等特定用途), 保留带修饰符 / 带路径 / 子域形式的例外
(语义明确, 不产生全量架空)。

测试锁定:
1. Merger.finalize 后 `dropped_bare_exceptions` > 0
2. 被丢弃的域, 其拦截规则仍出现在 all_blocks
3. 带修饰符的例外 (`@@||d^$popup` / `@@||d^$domain=x`) 不被丢弃
4. all_exceptions 里没有无修饰符的整域例外
"""
import re
import unittest

from merge_filters import Merger, parse_line, K_EXCEPTION


class BareExceptionArbitrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        m = Merger()
        m.add_lines([
            "||awin1.com^",           # 上游拦截
            "@@||awin1.com^",         # 裸整域无条件例外 → 应丢弃
            "@@||awin1.com^|",        # 尾部|同样是裸例外 → 应丢弃
            "||app.adjust.com^",  # 我方域的拦截
            "@@||app.adjust.com^",    # 裸例外 → 应丢弃
            "||data.orders.costco.com^",
            "@@||data.orders.costco.com^",
            "@@||cdn.onetrust.com^$domain=example.com",  # 带修饰符 → 保留
            "||example.com^$script",
            "||example.com^",  # 域型规则, 让 example.com 有拦截基线
            "@@||example.com/path.js",           # 带路径 → 保留
            "||ok.com^",
        ])
        cls.res = m.finalize()

    def test_bare_exceptions_dropped(self):
        self.assertGreater(
            self.res.dropped_bare_exceptions, 0,
            "未丢弃任何裸整域例外 — 仲裁逻辑可能失效")
        self.assertEqual(
            self.res.dropped_bare_exceptions, 4,
            "应丢弃 4 条裸例外 (awin1 x2, adjust, costco), 实际 %d"
            % self.res.dropped_bare_exceptions)

    def test_block_rules_survive_dropped_exceptions(self):
        """被丢弃裸例外的域, 拦截规则必须留在 all_blocks。"""
        for rule in ("||awin1.com^", "||app.adjust.com^",
                     "||data.orders.costco.com^"):
            self.assertIn(rule, self.res.all_blocks,
                          "%s 被裸例外错误剔除" % rule)

    def test_modified_exceptions_preserved(self):
        """带修饰符/带路径的例外语义明确, 必须原样保留。"""
        self.assertIn(
            "@@||cdn.onetrust.com^$domain=example.com", self.res.all_exceptions)
        self.assertIn("@@||example.com/path.js", self.res.all_exceptions)

    def test_no_bare_whole_domain_exception_in_output(self):
        """输出里不允许再有无修饰符的整域例外 (会架空同域拦截)。"""
        bad = []
        for line in self.res.all_exceptions:
            m = re.fullmatch(r"@@\|\|[a-z0-9.-]+\^\|?", line, re.I)
            if m:
                bad.append(line)
        self.assertEqual([], bad, "输出仍含裸整域例外: %s" % bad)

    def test_dns_whitelist_excludes_dropped(self):
        """DNS 白名单也不应保留被丢弃的裸例外。"""
        self.assertNotIn("@@||awin1.com^", self.res.whitelist)
        self.assertNotIn("@@||app.adjust.com^", self.res.whitelist)


if __name__ == "__main__":
    unittest.main()
