# -*- coding: utf-8 -*-
"""
纯追踪域拦截的安全边界。

mobileproxy.space 的 487 项检测里 43 项漏网。这 43 个并非都能加:
有些是通用服务主域 (impact.com 联盟平台 / mailchimp.com 邮件服务 /
f.vimeocdn.com Vimeo 核心 CDN), 加 ||domain^ 会打死大量正常网站。
本测试把"可加"与"不可加"两侧都锁死, 防止为了刷分而误伤。

背景数据见 tests/data/mobileproxy-missed.json。
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONFIG = os.path.join(REPO, "config.json")
MISSED = os.path.join(HERE, "data", "mobileproxy-missed.json")

# 绝不能无条件拦截的域名: 通用服务 / 平台主域, 拦截会破坏正常站点。
# 值为原因说明 (会出现在测试失败信息里)。
FORBIDDEN = {
    "app.link": "通用短链服务主域, 正常分享链接会全部失效",
    "bnc.lt": "短链服务主域",
    "settings-win.data.microsoft.com": "Windows 设置同步端点, 可能影响系统功能",
    "cdn.onetrust.com": "OneTrust 主 CDN, 承载 CMP UI 脚本, 会让同意弹窗报错",
    "cdn.cookielaw.org": "Cookiebot 主 CDN, 同上",
    "impact.com": "联盟营销平台主域, 会打死真实联盟链接",
    "api.impact.com": "impact.com 子域, 随主域一并观望",
    "sdk.split.io": "Split.io SDK 被大量正常应用加载",
    "dev.visualwebsiteoptimizer.com": "VWO 主域, 大型 A/B 平台",
    "mailchimp.com": "Mailchimp 主域, 邮件系统与登录页在用",
    "app.convertkit.com": "ConvertKit 主应用域, 在线创作者站点在用",
    "f.vimeocdn.com": "Vimeo 核心 CDN, 拦了看不到所有 Vimeo 视频",
}

# 应当出现在 extra_rules 里的纯追踪域。
EXPECTED_SAFE = {
    "mixpanel.com", "fullstory.com", "app.adjust.com", "tags.tiqcdn.com",
    "trackjs.com", "cpu.js.org", "st-widget.s3.amazonaws.com",
    "metrics.icloud.com", "cookies-data.onetrust.io", "cdn.privacy-mgmt.com",
    "wrapper-api.sp-prod.net", "consent.trustarc.com",
    "consent-pref.trustarc.com", "api.usercentrics.eu",
    "aggregator.service.usercentrics.eu", "app.usercentrics.eu",
    "mobile.launchdarkly.com", "streaming.split.io", "app.launchdarkly.com",
    "stream.launchdarkly.com", "edge.api.flagsmith.com", "cdn.configcat.com",
    "api.flagsmith.com", "cdn-eu.configcat.com", "assets.mailerlite.com",
    "click.mailerlite.com", "clicks.aweber.com", "pixel.aweber.com",
    "email.mailgun.net", "mandrillapp.com", "fresnel.vimeocdn.com",
}


def _domains_in(rules):
    """从 ||domain^ 形式规则里取出被拦截的域名集合。"""
    out = set()
    for r in rules:
        m = re.match(r"^\|\|([^\^$/]+(?:\.[^\^$/]+)*)\^", r)
        if m:
            out.add(m.group(1).lower())
    return out


class SafeTrackingDomainsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CONFIG, encoding="utf-8") as f:
            cls.rules = json.load(f).get("extra_rules", [])
        cls.blocked = _domains_in(cls.rules)

    def test_no_forbidden_domain_is_blocked(self):
        """核心安全断言: 通用服务主域绝不能被无条件拦截。"""
        hits = sorted(self.blocked & set(FORBIDDEN))
        self.assertEqual(
            [], hits,
            "extra_rules 拦截了会造成误伤的域名: " + "; ".join(
                "%s (%s)" % (d, FORBIDDEN[d]) for d in hits))

    def test_every_expected_safe_domain_is_present(self):
        missing = sorted(EXPECTED_SAFE - self.blocked)
        self.assertEqual(
            [], missing,
            "mobileproxy 检测中已确认可安全拦截但缺失的域名: %s" % missing)

    def test_forbidden_domains_are_documented(self):
        """每个高风险域名都必须写明不拦的原因, 便于日后复核。"""
        for d, why in FORBIDDEN.items():
            self.assertTrue(why and len(why) > 5,
                            "域名 %s 缺少不拦截原因说明" % d)

    def test_tracking_rules_are_unconditional(self):
        """追踪域必须用 $all —— 依赖默认修饰符会在某些实现里不生效。"""
        for r in self.rules:
            m = re.match(r"^\|\|([^\^]+)\^(\$.*)?$", r)
            if not m or m.group(1) not in EXPECTED_SAFE:
                continue
            self.assertIn("$all", r, "追踪规则 %r 缺 $all" % r)

    def test_no_third_party_only_rules(self):
        """$third-party / $~third-party 不适用于同域或无 referer 场景。"""
        for r in self.rules:
            self.assertNotIn("third-party", r,
                             "规则 %r 使用了 third-party 修饰符" % r)

    def test_missed_snapshot_accounted_for(self):
        """43 个漏网域名必须都有明确结论: 已加 或 明确列为不拦。"""
        if not os.path.exists(MISSED):
            self.SkipTest("缺少漏网快照")
        with open(MISSED, encoding="utf-8") as f:
            missed = json.load(f)
        unaccounted = [m for _, m in missed
                       if m not in self.blocked and m not in FORBIDDEN]
        self.assertEqual(
            [], unaccounted,
            "以下漏网域名既未拦截也未记录原因: %s" % unaccounted)


if __name__ == "__main__":
    unittest.main()
