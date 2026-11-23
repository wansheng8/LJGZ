# -*- coding: utf-8 -*-
"""ABP 官方测试页 (abptestpages.org) 语法回归测试。

覆盖官网 test pages 的规则形态: 基础拦截 / 元素隐藏 / 扩展选择器 /
remove 与 inline-css / 各类资源类型与约束 / 例外与 DNS 安全 / CSP /
rewrite / sitekey / snippets。目标: 合并引擎不得丢弃或误判这些合法规则。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import merge_filters as mf  # noqa: E402


class AbpCase(unittest.TestCase):
    def assert_kept(self, line, kind):
        r = mf.parse_line(line)
        self.assertFalse(r.dropped, "不应丢弃: %s" % line)
        self.assertEqual(kind, r.kind, "分类错误: %s" % line)
        return r

    def assert_mods_known(self, line):
        r = mf.parse_line(line)
        self.assertTrue(r.modifiers, "修饰符未解析: %s" % line)
        for part in mf._split_mods_raw(r.modifiers):
            key = part.strip().split("=", 1)[0].strip().lstrip("~").lower()
            if key:
                self.assertIn(key, mf._OFFICIAL_MODS,
                              "未知修饰符 %s: %s" % (key, line))
        return r


class TestBlocking(AbpCase):
    def test_path_rules(self):
        """filters/blocking: 完整路径 / 部分路径 / 通配 / 动态 / 深子域。"""
        for line in (
            "||abptestpages.org/testfiles/blocking/full-path.png",
            "/testfiles/blocking/partial-path/",
            "/testfiles/blocking/wildcard/*/wildcard.png",
            "/testfiles/blocking/dynamic.png",
            "||subdomain.abptestpages.org/testfiles/blocking/subdomain.png",
            # service-worker/worker-itself 与 worker-subresource
            "abptestpages.org/testfiles/service-worker/blocked-service-worker.js",
            "abptestpages.org/testfiles/service-worker/worker-subresource.png",
        ):
            self.assert_kept(line, mf.K_NETWORK)


class TestElementHiding(AbpCase):
    def test_basic_and_exceptions(self):
        """filters/element-hiding 与 exceptions/element-hiding。"""
        for line in (
            "abptestpages.org##.testcase-eh",
            "abptestpages.org##div[id^=\"ad\"]",
            "abptestpages.org#@#.testcase-eh",
            "abptestpages.*##div[style*=\"width: 203px;\"]",
            "abptestpages.*###eh-id",
            "abptestpages.*#?#div:-abp-has(> div:-abp-properties(width: 231px))",
        ):
            self.assert_kept(line, mf.K_COSMETIC)

    def test_extended_selectors(self):
        """filters/element-hiding-emulation: ABP 扩展选择器。"""
        for line in (
            "abptestpages.org#?#div:-abp-properties(width: 213px)",
            "abptestpages.org#?#div:-abp-has(>div>span.ehe-abp-has)",
            "abptestpages.org#?#div:has(>div>span.ehe-has)",
            "abptestpages.org#?#span:-abp-contains(ehe-contains-target)",
            "abptestpages.org#?#span:xpath(//*[@id=\"basic-xpath-usage-fail\"])",
            "abptestpages.org#?#span:has-text(ehe-has-text)",
            "abptestpages.org#?#div > div:-abp-contains(/ehe-containsregex\\d/)",
            "abptestpages.org#?#.ehe-wildcard:-abp-properties(cursor:*)",
        ):
            self.assert_kept(line, mf.K_COSMETIC)

    def test_extended_exceptions(self):
        """element-hiding-emulation-inversion / inline-css-inversion。"""
        for line in (
            "abptestpages.org#@#.testcase-eh",
            "abptestpages.org#@?#div:-abp-has(> span.ehe-has)",
            "abptestpages.org#@$#.testcase-inline-css {background-color: #fff;}",
        ):
            self.assert_kept(line, mf.K_COSMETIC)

    def test_remove_and_inline_css_blocks(self):
        """filters/remove 与 filters/inline-css: ## 后接 CSS 声明块。"""
        for line in (
            "abptestpages.org###remove-id {remove: true;}",
            "abptestpages.org##div[id='{{remove-id}}'] {remove: true;}",
            "abptestpages.org##.testcase-area > .remove-descendant {remove: true;}",
            "abptestpages.org##div[style*=\"width: 45px;\"] {remove: true;}",
            "abptestpages.org###inline-css-id {background-color: #0dc74b;}",
            "abptestpages.org##div[id='{{inline-css-id}}'] "
            "{background-color: #0dc74b;}",
        ):
            self.assert_kept(line, mf.K_COSMETIC)


class TestFilterOptions(AbpCase):
    def test_resource_types(self):
        """filters/{image,script,stylesheet,subdocument,websocket,xhr,ping,popup}。"""
        for opt in ("image", "script", "stylesheet", "subdocument", "websocket",
                    "xmlhttprequest", "ping", "popup", "font", "media",
                    "object", "other", "document", "inline-script"):
            line = "||abptestpages.org/testfiles/%s$%s" % (opt, opt)
            self.assert_kept(line, mf.K_NETWORK)
            self.assert_mods_known(line)

    def test_legacy_aliases(self):
        """ABP 旧资源类型 object-subrequest 与 uBO inline-font。"""
        for line in (
            "||abptestpages.org/old$object-subrequest",
            "||abptestpages.org/font.woff2$inline-font",
        ):
            self.assert_kept(line, mf.K_NETWORK)
            self.assert_mods_known(line)

    def test_constraints(self):
        """filters/{domain,third-party,match-case,other}。"""
        for line in (
            "||abptestpages.org/testfiles/tp$third-party",
            "||abptestpages.org/testfiles/case$match-case",
            "||abptestpages.org/testfiles/domain$domain=abptestpages.org|example.com",
            "||abptestpages.org/testfiles/other$other",
            "||abptestpages.org/testfiles/popup$popup",
        ):
            self.assert_kept(line, mf.K_NETWORK)
            self.assert_mods_known(line)

    def test_header_csp_rewrite_values(self):
        """filters/{header,csp,rewrite}: 值内含 = / 空格 / 逗号时不得切坏。"""
        cases = {
            "||abptestpages.org/testfiles/header_exception/"
            "$header=content-type=image/png":
                "header=content-type=image/png",
            "||abptestpages.org/en/exceptions/csp^"
            "$csp=script-src https://abptestpages.org/lib/utils.js":
                "csp=script-src https://abptestpages.org/lib/utils.js",
            "||abptestpages.org/testfiles/rewrite/*.js"
            "$rewrite=abp-resource:blank-js,domain=abptestpages.org":
                "rewrite=abp-resource:blank-js,domain=abptestpages.org",
        }
        for line, mods in cases.items():
            r = self.assert_kept(line, mf.K_NETWORK)
            self.assertEqual(mods, r.modifiers, line)
            self.assert_mods_known(line)


class TestExceptions(AbpCase):
    def test_abp_exceptions_kept(self):
        lines = [
            "@@||abptestpages.org/en/exceptions/document$document",
            "@@abptestpages.org/en/exceptions/elemhide$elemhide",
            "@@||abptestpages.org/en/exceptions/generichide$generichide",
            "@@||abptestpages.org/en/exceptions/genericblock$genericblock",
            "@@||abptestpages.org/en/exceptions/csp^$csp",
            "@@abptestpages.org/testfiles/header_exception/$header=content-type",
            "@@$document,sitekey=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGtTstne7e8MbmDHDiMFkGbcuBg",
            # exceptions/iframe: 子文档例外只放行该文档
            "@@||abptestpages.org/testfiles/iframe_exception/empty.html^$document",
        ]
        # exceptions/{image,script,stylesheet,subdocument,websocket,xhr,ping,popup}
        for opt in ("image", "script", "stylesheet", "subdocument", "websocket",
                    "xmlhttprequest", "ping", "popup", "font", "media",
                    "object", "other"):
            lines.append("@@||abptestpages.org/testfiles/%s$%s" % (opt, opt))
        for line in lines:
            self.assert_kept(line, mf.K_EXCEPTION)

    def test_sitekey_is_known_option(self):
        r = self.assert_mods_known(
            "@@$document,sitekey=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGtTstne7e8MbmDHDiMFkGbcuBg")
        self.assertEqual(mf.K_EXCEPTION, r.kind)

    def test_http_only_exceptions_not_dns_whitelist(self):
        """$document/$elemhide/$generichide/$genericblock/$csp/sitekey/header
        只放行页面或资源, 不能升级为整域 DNS 放行。"""
        for line in (
            "@@||abptestpages.org/en/exceptions/document$document",
            "@@||abptestpages.org/en/exceptions/elemhide$elemhide",
            "@@||abptestpages.org/en/exceptions/generichide$generichide",
            "@@||abptestpages.org/en/exceptions/genericblock$genericblock",
            "@@||abptestpages.org/en/exceptions/csp^$csp",
            "@@abptestpages.org/testfiles/header_exception/$header=content-type",
            "@@$document,sitekey=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGtTstne7e8MbmDHDiMFkGbcuBg",
        ):
            self.assertFalse(mf.parse_line(line).dns_relevant, line)

    def test_dns_exceptions_still_relevant(self):
        for line in ("@@||example.com^",
                     "@@||example.com^$important"):
            self.assertTrue(mf.parse_line(line).dns_relevant, line)


class TestSnippets(AbpCase):
    def test_abp_snippets_kept(self):
        """snippets/*: ABP 用 #$# 承载 snippet, 参数含引号/正则/逗号。"""
        for line in (
            "abptestpages.org#$#skip-video #skip-video-test-video "
            ".//div[@class=\"ad\"]",
            "abptestpages.org#$#timer-override 1 '' '' both timerStackFn",
            "abptestpages.org#$#replace-fetch-response /\\d+\\s+years?\\s+old/ "
            "'stoic' /[CcKk]ardamon/",
            "abptestpages.org#$#hide-if-contains-similar-text "
            "Sponsored-hicst-basic '#hicst-basic-id' '#hicst-basic-id' 1 4",
            "abptestpages.org##+js(abort-on-property-read, alert)",
        ):
            self.assert_kept(line, mf.K_COSMETIC)


class TestOfficialSubscription(AbpCase):
    """tests/data/abp-testcase-subscription.txt 是官网订阅的离线快照。"""

    def test_snapshot_parses_completely(self):
        path = os.path.join(os.path.dirname(__file__), "data",
                            "abp-testcase-subscription.txt")
        rows = []
        with open(path, encoding="utf-8-sig") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("!") or s.startswith("["):
                    continue
                if s.startswith("#") and not any(
                        s.startswith(x) for x in mf.COSMETIC_SEPS):
                    continue
                rows.append(s)
        self.assertGreaterEqual(len(rows), 300, "快照疑似被截断")
        drops, unknown, dns_leak = [], {}, []
        for line in rows:
            r = mf.parse_line(line)
            if r.dropped:
                drops.append(line)
            if r.kind == mf.K_EXCEPTION and r.dns_relevant:
                dns_leak.append(line)
            if r.modifiers:
                for part in mf._split_mods_raw(r.modifiers):
                    key = part.strip().split("=", 1)[0].strip().lstrip("~").lower()
                    if key and key not in mf._OFFICIAL_MODS:
                        unknown[key] = unknown.get(key, 0) + 1
        self.assertEqual([], drops, "官方订阅中有规则被丢弃")
        self.assertEqual({}, unknown, "官方订阅中有未知修饰符")
        self.assertEqual([], dns_leak, "官方订阅例外不应升级为 DNS 白名单")


if __name__ == "__main__":
    unittest.main()
