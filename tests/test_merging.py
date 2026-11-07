# -*- coding: utf-8 -*-
"""合并层测试: 语义去重 / 例外保护 / badfilter / 输出分类 (TDD — 先于实现编写)。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


def merge(*lines):
    """辅助: 把若干行解析后喂给 Merger, 返回 finalize 结果。"""
    m = mf.Merger()
    for ln in lines:
        m.add_rule(mf.parse_line(ln))
    return m.finalize()


class TestSemanticDedup(unittest.TestCase):
    def test_equivalent_forms_collapse_to_one(self):
        """||d^ ≡ d ≡ 0.0.0.0 d ≡ *.d — 同一域名只输出一条。"""
        res = merge(
            "||example.com^",
            "example.com",
            "0.0.0.0 example.com",
            "*.example.com",
        )
        self.assertEqual(res.adguard_blocks, ["||example.com^"])
        self.assertEqual(res.domains, ["example.com"])
        self.assertEqual(res.hosts, ["0.0.0.0 example.com"])
        self.assertEqual(res.all_blocks, ["||example.com^"])

    def test_exact_network_dedup(self):
        res = merge("||ads.com^$script", "||ads.com^$script")
        self.assertEqual(len(res.all_network), 1)

    def test_cosmetic_dedup(self):
        res = merge("example.com##.ad", "example.com##.ad")
        self.assertEqual(len(res.all_cosmetic), 1)

    def test_important_beats_plain(self):
        """同一域名普通拦截 + $important 拦截 → 保留 important 形式。"""
        res = merge("||example.com^", "||example.com^$important")
        self.assertEqual(res.adguard_blocks, ["||example.com^$important"])

    def test_case_insensitive_domain_merge(self):
        res = merge("||EXAMPLE.com^", "example.com")
        self.assertEqual(res.domains, ["example.com"])

    def test_hosts_multi_domain_line_expands(self):
        res = merge("0.0.0.0 a.com b.com")
        self.assertEqual(sorted(res.domains), ["a.com", "b.com"])


class TestExceptionProtection(unittest.TestCase):
    def test_dns_relevant_exception_removes_domain_block(self):
        """@@ 例外 → 该域名不进 hosts/domains/adguard 拦截输出, 但进白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$important")
        self.assertEqual(res.domains, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.adguard_blocks, [])
        self.assertIn("@@||ads.com^$important", res.whitelist)
        self.assertIn("@@||ads.com^$important", res.all_exceptions)

    def test_bare_dns_exception_dropped_but_domain_blocked(self):
        """无修饰符的整域 @@ 例外会被丢弃 (它会在浏览器端架空同域拦截),
        因此对应域名继续出现在拦截输出里 — 这是与旧行为的有意变更。
        见 test_bare_exception_arbitration 及 stats.dropped_bare_exceptions。"""
        res = merge("||ads.com^", "@@||ads.com^")
        self.assertIn("||ads.com^", res.all_blocks)
        self.assertEqual(res.dropped_bare_exceptions, 1)
        self.assertEqual(res.all_exceptions, [])

    def test_modified_dns_exception_still_removes_domain(self):
        """带 $important 的例外是 DNS 侧唯一认可的放行形式, 仍把该域从
        DNS 拦截输出剔除并进白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$important")
        self.assertEqual(res.domains, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.adguard_blocks, [])
        self.assertIn("@@||ads.com^$important", res.whitelist)

    def test_whitelist_only_important_exceptions(self):
        """白名单只收 DNS 可兑现的 $important 例外; $document 属浏览器层,
        不进白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$document",
                    "@@||ok.com^$important")
        self.assertNotIn("@@||ads.com^", res.whitelist)
        self.assertNotIn("@@||ads.com^$document", res.whitelist)
        self.assertEqual(res.whitelist, ["@@||ok.com^$important"])
        self.assertIn("ads.com", res.domains)

    def test_dns_exception_inherits_to_subdomains(self):
        """DNS 例外沿子域继承: 父域被例外放行时, 子域拦截一并从 hosts /
        domains / adguard 剔除。`||d^` 的拦截含子域语义, 例外必须对称 ——
        否则 hosts 格式没有 @@ 机制, 白名单会被上游仍在拦的子域打败。"""
        res = merge("||ads.com^", "||sub.ads.com^", "@@||ads.com^$important")
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.domains, [])
        self.assertEqual(res.adguard_blocks, [])
        self.assertEqual(res.whitelist, ["@@||ads.com^$important"])

    def test_exception_does_not_leak_to_siblings(self):
        """例外不横向扩散: 放行 ads.com 不影响兄弟域 other.com。"""
        res = merge("||ads.com^", "||sub.ads.com^", "||other.com^",
                    "@@||ads.com^$important")
        self.assertEqual(res.domains, ["other.com"])

    def test_whitelist_anchor_is_double_pipe(self):
        """白名单必须写 `@@||d^`: 单竖线 `@@|d^` 锚定 URL 开头, 客户端匹配
        的是 `https://d/...`, 该条会成为死规则 (自家跑分脚本也只认 `@@||d^`)。"""
        res = merge("||ads.com^", "@@||ads.com^$important")
        self.assertEqual(res.whitelist, ["@@||ads.com^$important"])
        self.assertNotIn("@@|ads.com^", res.whitelist)

    def test_browser_layer_ignores_dns_exception(self):
        """两套裁决: $document 只影响浏览器层 —— all.txt 原样输出 @@ 交给
        客户端仲裁, DNS 产物照常拦截, 也不产生白名单。"""
        res = merge("||ads.com^", "@@||ads.com^$document")
        self.assertIn("||ads.com^", res.all_blocks)
        self.assertIn("@@||ads.com^$document", res.all_exceptions)
        self.assertIn("||ads.com^", res.adguard_blocks)
        self.assertEqual(res.domains, ["ads.com"])
        self.assertEqual(res.whitelist, [])

    def test_whitelist_takes_only_dns_relevant_exceptions(self):
        """白名单只由 DNS 层裁决产生: 浏览器专属例外 ($elemhide / $document)
        不进白名单, 也不剔 DNS 域。"""
        res = merge("||ads.com^", "@@||ads.com^$elemhide",
                    "@@||ok.com^$document")
        self.assertIn("@@||ads.com^$elemhide", res.all_exceptions)
        self.assertEqual(res.whitelist, [])
        self.assertIn("ads.com", res.domains)

    def test_important_block_survives_document_exception(self):
        """$document 不参与 DNS 裁决: 该域即使有 $document 例外, 其
        $important 拦截仍照常输出到 DNS 产物。"""
        res = merge("||ads.com^$important", "@@||ads.com^$document")
        self.assertIn("||ads.com^$important", res.adguard_blocks)
        self.assertEqual(res.domains, ["ads.com"])

    def test_cosmetic_only_exception_does_not_unblock_dns(self):
        res = merge("||ads.com^", "@@||ads.com^$elemhide")
        self.assertEqual(res.domains, ["ads.com"])
        self.assertEqual(res.whitelist, [])   # 仅浏览器侧例外不进 DNS 白名单


class TestBadfilter(unittest.TestCase):
    def test_badfilter_kills_identical_rule(self):
        res = merge("||ads.com^$script", "||ads.com^$script,badfilter")
        self.assertEqual(res.all_network, [])

    def test_badfilter_does_not_kill_others(self):
        res = merge("||ads.com^$script", "||other.com^$script,badfilter")
        self.assertEqual(res.all_network, ["||ads.com^$script"])

    def test_badfilter_on_domain_rule(self):
        res = merge("||ads.com^", "||ads.com^$badfilter")
        self.assertEqual(res.all_blocks, [])
        self.assertEqual(res.domains, [])

    def test_modifier_order_irrelevant_for_badfilter(self):
        res = merge("||ads.com^$script", "||ads.com^$badfilter,script")
        self.assertEqual(res.all_network, [])


class TestOutputsSplit(unittest.TestCase):
    def test_dns_syntax_rules_go_to_adguard(self):
        res = merge("||example.com^$dnsrewrite=NOERROR;CNAME;example.net")
        self.assertIn("||example.com^$dnsrewrite=NOERROR;CNAME;example.net",
                      res.adguard_dns)

    def test_browser_only_rule_not_in_dns_outputs(self):
        res = merge("||ads.com^$script")
        self.assertEqual(res.adguard_dns, [])
        self.assertEqual(res.hosts, [])
        self.assertEqual(res.domains, [])

    def test_path_pattern_not_in_dns_output(self):
        """带路径/查询串的规则在 DNS 层永不命中, 即使修饰符合法也不进 adguard.txt。"""
        res = merge("||ads.com/path/a.php$important",
                    "||ads.com^$important",
                    "||track.example.com/x?y=1$important",
                    "stun:1755001826:443$important")
        self.assertEqual(res.adguard_dns, ["||ads.com^$important"])
        # 浏览器输出仍原样保留
        self.assertIn("||ads.com/path/a.php$important", res.all_network)

    def test_regex_and_wildcard_are_dns_patterns(self):
        """正则与 * 主机名通配仍是合法 DNS pattern, 不能被新校验误伤。"""
        res = merge("/^ad[0-9]+\\.com$/$dnstype=A",
                    "||*serror*.wo.com.cn^$dnstype=A|CNAME")
        self.assertEqual(len(res.adguard_dns), 2)

    def test_sorted_domain_output(self):
        res = merge("||b.com^", "||a.com^", "||c.com^")
        self.assertEqual(res.domains, ["a.com", "b.com", "c.com"])
        self.assertEqual(res.adguard_blocks,
                         ["||a.com^", "||b.com^", "||c.com^"])


class TestSubdomainCollapse(unittest.TestCase):
    def test_subdomain_collapsed_when_parent_blocked(self):
        res = merge("||example.com^", "||sub.example.com^")
        self.assertIn("||example.com^", res.adguard_blocks)
        self.assertNotIn("||sub.example.com^", res.adguard_blocks)
        # hosts/domains 为精确匹配语义, 保留子域
        self.assertEqual(sorted(res.domains), ["example.com", "sub.example.com"])

    def test_no_collapse_without_parent(self):
        res = merge("||sub.other.com^")
        self.assertEqual(res.adguard_blocks, ["||sub.other.com^"])

    def test_collapse_disabled_option(self):
        m = mf.Merger(collapse_subdomains=False)
        m.add_rule(mf.parse_line("||example.com^"))
        m.add_rule(mf.parse_line("||sub.example.com^"))
        res = m.finalize()
        self.assertIn("||sub.example.com^", res.adguard_blocks)


class TestBrowserSubdomainCollapse(unittest.TestCase):
    """浏览器 all.txt 也做子域折叠 (2026-10 优化)。

    动机: 折叠原先只作用于 adguard 输出, 浏览器 all_blocks 仍保留 ~9.5k 条
    "父域已覆盖"的冗余子域规则, 订阅体积虚高。折叠语义不变 (||d^ 本就拦
    子域), 拦截能力 0 损失 (不变量: 折叠前后 domains/hosts 精确域集合相同)。
    子域的 $important 不向父域提升: 提升会把整域升级成 important 拦截, 连带
    压过上游针对兄弟子域的例外。数字 label (IP 段) 保守不折叠。
    """

    def test_all_blocks_collapse_subdomains(self):
        res = merge("||example.com^", "||sub.example.com^")
        self.assertEqual(res.all_blocks, ["||example.com^"])
        self.assertEqual(res.adguard_blocks, ["||example.com^"])
        # hosts/domains 精确匹配语义, 子域保留
        self.assertEqual(sorted(res.domains), ["example.com", "sub.example.com"])
        self.assertEqual(sorted(res.hosts),
                         ["0.0.0.0 example.com", "0.0.0.0 sub.example.com"])

    def test_important_child_kept_when_parent_is_plain(self):
        """父域只是裸 ||d^ 时, 子域的 $important 必须保留 (不提升、也不丢)。

        丢掉子域那条 = 失去 $important, 上游任何 `@@` 例外都能重新盖住;
        保留它则拦截强度不变, 只是多一行。
        """
        res = merge("||example.com^", "||sub.example.com^$important")
        self.assertEqual(sorted(res.all_blocks),
                         ["||example.com^", "||sub.example.com^$important"])
        self.assertEqual(sorted(res.adguard_blocks),
                         ["||example.com^", "||sub.example.com^$important"])

    def test_important_child_folded_into_important_parent(self):
        """父域同样是 $important 时强度等价, 子域才可折叠 (且不提升语义)。"""
        res = merge("||example.com^$important", "||sub.example.com^$important")
        self.assertEqual(res.all_blocks, ["||example.com^$important"])

    def test_chained_important_kept_when_chain_is_plain(self):
        """链式: a.b.c.com$important 的祖先链没有 important → 保留。"""
        res = merge("||c.com^", "||b.c.com^", "||a.b.c.com^$important")
        self.assertEqual(res.all_blocks, ["||a.b.c.com^$important", "||c.com^"])

    def test_numeric_label_not_collapsed(self):
        """数字 label 子域 (0.ackzany.com) 保守保留, 不折叠。"""
        res = merge("||ackzany.com^", "||0.ackzany.com^")
        self.assertIn("||0.ackzany.com^", res.all_blocks)
        self.assertIn("||0.ackzany.com^", res.adguard_blocks)

    def test_collapse_preserves_dns_set_invariant(self):
        """不变量: 折叠前后 domains/hosts 精确域集合完全相同 (0 拦截损失)。"""
        lines = ["||big.com^"] + [f"||sub{i}.big.com^" for i in range(5)]
        m1 = mf.Merger()
        m1.add_lines(lines)
        r1 = m1.finalize()
        m2 = mf.Merger(collapse_subdomains=False)
        m2.add_lines(lines)
        r2 = m2.finalize()
        self.assertEqual(sorted(r1.domains), sorted(r2.domains))
        self.assertEqual(sorted(r1.hosts), sorted(r2.hosts))


class TestTypeRuleSubsumption(unittest.TestCase):
    """同域纯 type 网络规则消解 (2026-10 优化)。

    高效拦截红线: 某域已被"全请求类型"拦截 (all_blocks 里有 ||d^ / ||d^$important)
    时, 同域"纯请求类型"窄规则 (||d^$script 等) 是严格子集 — 删掉不改变任何
    拦截结果, 只省体积。凡带独立语义的窄规则 (redirect/rewrite/=值/~否定/$all/
    $important/denyallow) 一律保留, 数字 label (IP 段) 跳过, 被 all_blocks 截断
    掉的域 (裸规则已不在 all.txt) 的窄规则也保留 (避免漏拦)。
    消解只作用于浏览器 all_network; adguard_dns 独立读 _net, 保留全量。
    """

    def test_bare_domain_covers_sametype_rule(self):
        res = merge("||ads.com^", "||ads.com^$script")
        self.assertEqual(res.all_network, [])

    def test_multiple_types_all_subsumed(self):
        res = merge("||ads.com^", "||ads.com^$image",
                    "||ads.com^$script", "||ads.com^$object")
        self.assertEqual(res.all_network, [])

    def test_important_parent_covers_type_rule(self):
        res = merge("||ads.com^$important", "||ads.com^$script")
        self.assertEqual(res.all_network, [])

    def test_no_bare_domain_keeps_type_rule(self):
        res = merge("||ads.com^$script")
        self.assertEqual(res.all_network, ["||ads.com^$script"])

    def test_functional_modifier_preserved(self):
        """redirect / =值 / ~否定 有独立语义, 保留。"""
        res = merge("||ads.com^",
                    "||ads.com^$script,redirect=blank.html",
                    "||ads.com^$domain=site.org",
                    "||ads.com^$~third-party")
        for keep in ("||ads.com^$script,redirect=blank.html",
                     "||ads.com^$domain=site.org",
                     "||ads.com^$~third-party"):
            self.assertIn(keep, res.all_network, "%s 应保留" % keep)
        self.assertEqual(len(res.all_network), 3)

    def test_important_narrow_rule_preserved(self):
        """$important 窄规则有优先级语义, 保留 (删了会被上游例外反杀)。"""
        res = merge("||ads.com^", "||ads.com^$script,important")
        self.assertEqual(res.all_network, ["||ads.com^$script,important"])

    def test_all_modifier_preserved(self):
        """$all 平台修饰符 (含 adguard) 不匹配裸 ||d^ 语义, 保留。"""
        res = merge("||ads.com^", "||ads.com^$all")
        self.assertEqual(res.all_network, ["||ads.com^$all"])

    def test_all_modifier_mirrored_as_plain_domain_rule(self):
        """$all 只有 AdGuard 认; uBO/ABP 会丢整行 → 补裸 ||d^ 镜像。

        镜像不用 $important: 强度与 $all 相同 (全请求类型), 但站点 `@@`
        仍可放行, 不抬高优先级。
        """
        res = merge("||ads.com^$all")
        self.assertEqual(res.all_blocks, ["||ads.com^"])       # 跨引擎可用的镜像
        self.assertEqual(res.all_network, ["||ads.com^$all"])  # AdGuard 原规则
        self.assertEqual(res.domains, ["ads.com"])
        self.assertEqual(res.stats["all_compat_mirrors"], 1)

    def test_all_mirror_skipped_when_domain_already_blocked(self):
        """该域已有全类型拦截时不补镜像, 避免上千条冗余。"""
        res = merge("||ads.com^", "||ads.com^$all")
        self.assertEqual(res.all_blocks, ["||ads.com^"])
        self.assertEqual(res.stats["all_compat_mirrors"], 0)

    def test_all_mirror_skipped_when_ancestor_blocks(self):
        """父域已拦 → 子域的 $all 由父域覆盖, 不补镜像。"""
        res = merge("||ads.com^", "||x.ads.com^$all")
        self.assertEqual(res.all_blocks, ["||ads.com^"])
        self.assertEqual(res.stats["all_compat_mirrors"], 0)

    def test_path_all_rule_mirrored_without_important(self):
        """路径形态 $all 按原式去 $all 补镜像 (不扩到整域, 不抬优先级)。"""
        res = merge("||example.com/ad.js$all")
        self.assertEqual(sorted(res.all_network),
                         ["||example.com/ad.js", "||example.com/ad.js$all"])
        self.assertNotIn("$important", "".join(res.all_network))
        self.assertEqual(res.stats["all_compat_mirrors"], 1)

    def test_numeric_label_skipped(self):
        """数字 label 窄规则保守保留, 不消解。"""
        res = merge("||ackzany.com^", "||0.ackzany.com^$script")
        self.assertEqual(res.all_network, ["||0.ackzany.com^$script"])

    def test_disabled_option(self):
        m = mf.Merger(subsume_type_rules=False)
        m.add_lines(["||ads.com^", "||ads.com^$script"])
        res = m.finalize()
        self.assertEqual(res.all_network, ["||ads.com^$script"])

    def test_stats_records_subsumed_count(self):
        m = mf.Merger()
        m.add_lines(["||ads.com^", "||ads.com^$script", "||ads.com^$image"])
        res = m.finalize()
        self.assertEqual(res.stats["subsumed_type_rules"], 2)

    def test_adguard_dns_keeps_full_network(self):
        """消解只瘦身浏览器 all_network; adguard_dns 的 DNS 网络规则独立全量。"""
        m = mf.Merger()
        m.add_lines(["||ads.com^", "||ads.com^$dnsrewrite=NOERROR"])
        res = m.finalize()
        # dnsrewrite 规则不属于 _SUBSUME_OK_MODS, 保留在 all_network
        self.assertIn("||ads.com^$dnsrewrite=NOERROR", res.all_network)
        # 且也进 adguard_dns (AGH 可兑现)
        self.assertIn("||ads.com^$dnsrewrite=NOERROR", res.adguard_dns)


class TestStats(unittest.TestCase):
    def test_stats_counts(self):
        res = merge(
            "||example.com^",       # 域名
            "example.com",          # 重复域名
            "||ads.com^$script",    # 网络
            "##.ad",                # cosmetic
            "! comment",            # 丢弃
            "junk line here",       # 丢弃 (无有效域名)
        )
        st = res.stats
        self.assertEqual(st["domains_unique"], 1)
        self.assertEqual(st["network_unique"], 1)
        self.assertEqual(st["cosmetic_unique"], 1)
        self.assertEqual(st["dropped"], 2)


if __name__ == "__main__":
    unittest.main()
