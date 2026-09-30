#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_filters — 广告过滤规则收集·转换·合并·去重引擎
====================================================

输入兼容: Adblock Plus / uBlock Origin / AdGuard 扩展语法, AdGuard Home,
         Pi-hole (hosts 式 / POSIX ERE 正则), 纯域名列表。

输出(由 merge 阶段生成, 详见 README):
  - all.txt            原样保留全部语法 (ABP/uBO/AdGuard 可订阅)
  - adguard.txt        DNS 场景可用的 ||domain^ + @@例外 + $dnsrewrite
  - hosts.txt          0.0.0.0 domain hosts 式
  - domains.txt        纯域名列表

本文件当前实现: 词法解析层 parse_line()。
依据: 《广告拦截软件过滤规则语法大全.md》(同目录上级)。
"""
from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request
from glob import glob
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

__version__ = "0.1.0"

# ---------------------------------------------------------------------------
# 规则类别常量
# ---------------------------------------------------------------------------
K_COMMENT = "comment"      # 注释/头部元数据/空行 — 丢弃
K_PREPROC = "preproc"     # !#include / !#if 等 uBO 预解析指令 — 不进入合并输出
K_HEADER = "header"        # [Adblock Plus 2.0] 列表头 — 丢弃
K_COSMETIC = "cosmetic"   # ## 元素隐藏 / #$# CSS / #%# JS / ##+js / $$ HTML — 原样保留
K_DOMAIN = "domain"       # 可归并为 DNS 域名语义的规则 (||d^ / 裸域名 / hosts / *.d)
K_NETWORK = "network"     # 网络规则 (带内容类型/行为修饰符或正则/子串模式) — 原样保留
K_EXCEPTION = "exception" # @@ 例外规则 — 原样保留, 且 dns_relevant 者进 DNS 白名单
K_INVALID = "invalid"     # 无法解析的行 — 丢弃

# ---------------------------------------------------------------------------
# 词法辅助
# ---------------------------------------------------------------------------

# 元素隐藏/注入类分隔符, 按"最长优先"排列; 匹配时取出现位置最早者。
COSMETIC_SEPS = (
    "#@$?#",   # AdGuard 扩展CSS样式注入例外
    "#@?#",    # AdGuard 扩展选择器例外
    "#@%#",    # AdGuard scriptlet/JS 注入例外
    "#@$#",    # AdGuard CSS 注入例外
    "#$?#",    # AdGuard 扩展CSS样式注入
    "#@#",     # 元素隐藏例外 (uBO: 例外 scriptlet 前缀)
    "#$#",     # AdGuard CSS 注入 / ABP 片段过滤器
    "#?#",     # 扩展选择器 (ABP/AdGuard)
    "#%#",     # AdGuard 内联 JS 注入
    "##",      # 元素隐藏 (uBO: 含 ##^ HTML过滤 / ##+js scriptlet)
)

# 例外规则中"仅浏览器侧生效"的修饰符 — 对 DNS 输出无意义 (语法文档 §4)
_COSMETIC_ONLY_EXC_MODS = {
    "elemhide", "ehide", "generichide", "ghide", "specifichide", "shide",
    "jsinject", "content", "extension", "stealth", "cname", "urlskip",
    "inline-script", "inline-font", "csp", "permissions", "replace",
    "removeheader", "removeparam", "urltransform", "uritransform",
    "hls", "jsonprune", "xmlprune", "cookie",
}
# 例外规则中 DNS 侧可兑现的修饰符: 空/document/doc/important
_DNS_OK_EXC_MODS = {"document", "doc", "important"}

# 拦截规则可归并为纯域名规则的修饰符子集 (语法文档 §8: AGH 仅支持少数修饰符)
_DNS_SAFE_BLOCK_MODS = {"important"}

# hosts 式行的本机/保留名 — 全部出现则该行无有效域名, 丢弃
_HOSTS_LOCAL_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "ip6-allinterfaces", "ip6-localnet", "ip6-mcastprefix",
    "0.0.0.0", "255.255.255.255",
}

# 单个主机名标签: 字母数字开头/结尾, 中间可连字符, ≤63
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
# 严格域名: ≥2 个标签, TLD 以字母开头且 ≥2 字符 (排除裸 IP)
_TLD = r"[a-z][a-z0-9-]{1,62}"
# 严格域名: 首标签 + 0..n 个中间标签 + TLD (即 ≥2 标签), TLD 以字母开头 (排除裸 IP)
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.{_TLD}$")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6ISH_RE = re.compile(r"^[0-9a-f:.%]+$")

# ||domain^ 或 ||domain — 纯域名锚点形式
_ANCHOR_RE = re.compile(r"^\|\|([a-z0-9.-]+?)(\^?)$", re.IGNORECASE)
# *.domain
_WILD_PREFIX_RE = re.compile(r"^\*\.([a-z0-9.-]+?)(\^?)$", re.IGNORECASE)
# Pi-hole 常见正则形状: (^|\.)a\.b$  →  a.b
_PIHOLE_SUB_RE = re.compile(r"^\(\^\|\\\.\)((?:[a-z0-9-]+\\\.)*[a-z0-9-]+)\$$", re.IGNORECASE)
# ^a\.b$ 形状
_PIHOLE_EXACT_RE = re.compile(r"^\^((?:[a-z0-9-]+\\\.)*[a-z0-9-]+)\$$", re.IGNORECASE)


@dataclass
class Rule:
    """一行规则(或被丢弃的行)的解析结果。"""
    raw: str = ""                       # 原始行 (已 strip)
    kind: str = K_INVALID
    dropped: bool = False                # 是否不进入任何输出
    domains: Tuple[str, ...] = ()       # K_DOMAIN: 归并出的域名 (小写)
    pattern: str = ""                   # K_NETWORK/K_EXCEPTION: URL 模式部分
    modifiers: str = ""                 # 修饰符原文 ($ 后部分)
    domain: str = ""                    # 从模式提取的主域名 (诊断/统计用)
    dns_relevant: bool = False          # K_EXCEPTION: 该例外是否对 DNS 输出生效
    important: bool = False             # 是否含 $important
    source: str = ""                    # 来源列表短名

    def __bool__(self) -> bool:         # 便于 `if rule:` 判定"保留行"
        return not self.dropped


def _is_host(s: str) -> bool:
    """宽松主机名校验 (用于元素隐藏的域名前缀): 允许单标签。"""
    return bool(s) and bool(_HOST_RE.match(s))


def _is_domain(s: str) -> bool:
    """严格域名校验: ≥2 标签 + 字母开头 TLD (排除 IP 形如 1.2.3.4)。"""
    return bool(s) and bool(_DOMAIN_RE.match(s))


def norm_domain(d: str) -> str:
    """域名规范化: 小写、去 FQDN 尾点。"""
    return d.strip().strip(".").lower()


def _split_modifiers(s: str) -> Tuple[str, str]:
    """把规则拆成 (pattern, modifiers)。识别开头的 /regex/ 字面量;
    其余按第一个未转义的 `$` 切分。"""
    if s.startswith("/") and len(s) > 1:
        # 找闭合的未转义 '/'
        i = 1
        while i < len(s):
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == "/":
                rest = s[i + 1:]
                if rest.startswith("$"):
                    return s[: i + 1], rest[1:]
                return s[: i + 1], ""
            i += 1
        return s, ""
    # 普通模式: 第一个未转义 $
    i = 0
    while i < len(s):
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "$":
            return s[:i], s[i + 1:]
        i += 1
    return s, ""


def split_mod_tokens(mods: str):
    """按未转义逗号切分修饰符 (值中 `\,` 不切)。"""
    out, buf, i = [], [], 0
    while i < len(mods):
        c = mods[i]
        if c == "\\" and i + 1 < len(mods):
            buf.append(mods[i + 1])
            i += 2
            continue
        if c == ",":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return [t.strip() for t in out if t.strip()]


def _mods_subset_of(mods: str, allowed) -> bool:
    """空/纯空白修饰符视为无修饰符。"""
    return set(split_mod_tokens(mods.lower())) <= allowed


def _find_cosmetic(s: str) -> Optional[int]:
    """返回最早的元素隐藏/注入分隔符位置; 前缀须是合法域名列表, 否则 None。"""
    best = None
    for sep in COSMETIC_SEPS:
        idx = s.find(sep)
        if idx < 0:
            continue
        if best is None or idx < best:
            best = idx
    if best is None:
        return None
    if not _valid_cosmetic_prefix(s[:best]):
        return None
    return best


def _valid_cosmetic_prefix(p: str) -> bool:
    """元素隐藏分隔符之前的部分须为: 空 / * / 域名列表 / [$...] 修饰符 / 主机名正则。"""
    p = p.strip()
    if p == "" or p == "*":
        return True
    if p.startswith("[") and p.endswith("]") and p.startswith("[$"):
        return True
    for part in p.split(","):
        part = part.strip()
        if part.startswith("~"):
            part = part[1:]
        if part.startswith("/") and part.endswith("/") and len(part) > 2:
            continue                       # /^example\.org$/ 主机名正则
        if part.startswith("*."):
            part = part[2:]
        core = part.split("/")[0]          # example.org/checkout → example.org
        if core.endswith(".*"):
            core = core[:-2]               # 实体通配 google.* → google
        if not _is_host(core):
            return False
    return True


def _domain_like_token(tok: str):
    """hosts/杂行扫描: 该 token 是否像一个可拦截域名。"""
    if tok.endswith(".arpa"):              # in-addr.arpa / ip6.arpa 保留
        return None
    tok = norm_domain(tok)
    return tok if _is_domain(tok) else None


def _extract_anchor_domain(pattern: str) -> str:
    """从 `||domain^` 类模式提取域名; 失败返回空。"""
    m = _ANCHOR_RE.match(pattern)
    if not m:
        return ""
    d = norm_domain(m.group(1))
    return d if _is_domain(d) else ""


def _parse_exception(s: str, source: str = "") -> Rule:
    body = s[2:]
    pattern, mods = _split_modifiers(body)
    dom = _extract_anchor_domain(pattern) if pattern.startswith("||") else ""
    lower_mods = {m.split("=", 1)[0] for m in split_mod_tokens(mods.lower())}
    # DNS 相关: 修饰符为空或全属 {document, important} (client/ctag/dnstype/内容类型等不可在纯域名输出兑现)
    dns_rel = bool(dom) and lower_mods <= _DNS_OK_EXC_MODS
    return Rule(raw=s, kind=K_EXCEPTION, pattern=pattern, modifiers=mods,
                domain=dom, dns_relevant=dns_rel,
                important="important" in lower_mods, source=source)


def _parse_single_token(s: str, source: str = "") -> Rule:
    """无空白的规则行: ||锚点 / /regex/ / Pi-hole 正则 / *.域 / 裸域名 / 网络模式。"""
    pattern, mods = _split_modifiers(s)
    lower_mods = {m.split("=", 1)[0] for m in split_mod_tokens(mods.lower())}

    # Pi-hole 正则形状 → 等价域名 (子域含本身, ≡ ||domain^)
    if not mods:
        m = _PIHOLE_SUB_RE.match(s) or _PIHOLE_EXACT_RE.match(s)
        if m:
            d = norm_domain(m.group(1).replace("\\.", "."))
            if _is_domain(d):
                return Rule(raw=s, kind=K_DOMAIN, domains=(d,), domain=d, source=source)

    # ||domain 锚点
    if pattern.startswith("||"):
        d = _extract_anchor_domain(pattern)
        if d and _mods_subset_of(mods, _DNS_SAFE_BLOCK_MODS):
            return Rule(raw=s, kind=K_DOMAIN, domains=(d,), domain=d,
                        important="important" in lower_mods, source=source)
        return Rule(raw=s, kind=K_NETWORK, pattern=pattern, modifiers=mods,
                    domain=d, important="important" in lower_mods, source=source)

    # *.domain 通配前缀
    m = _WILD_PREFIX_RE.match(pattern)
    if m and _mods_subset_of(mods, _DNS_SAFE_BLOCK_MODS):
        d = norm_domain(m.group(1))
        if _is_domain(d):
            return Rule(raw=s, kind=K_DOMAIN, domains=(d,), domain=d, source=source)

    # 裸 IP 行 (hosts 文件脏数据): 无域名可拦, 丢弃而非当成子串网络规则
    if not mods and (_IPV4_RE.match(s) or (":" in s and _IPV6ISH_RE.match(s))):
        return Rule(raw=s, kind=K_INVALID, dropped=True, source=source)

    # 裸域名 (无任何修饰符/通配符/锚点); 允许 FQDN 尾点, 先规范化再校验
    if not mods:
        d = norm_domain(s)
        if _is_domain(d):
            return Rule(raw=s, kind=K_DOMAIN, domains=(d,), domain=d, source=source)

    # 其余一律按网络规则保留 (子串模式/正则/带修饰符)
    return Rule(raw=s, kind=K_NETWORK, pattern=pattern, modifiers=mods,
                important="important" in lower_mods, source=source)


def _parse_tokens(s: str, source: str = "") -> Rule:
    """含空白的行: hosts 式 (IP 开头) 或杂行。收集其中所有像域名的 token。"""
    toks = s.split()
    start = 0
    if toks and (_IPV4_RE.match(toks[0]) or (":" in toks[0] and _IPV6ISH_RE.match(toks[0]))):
        start = 1                        # 跳过 IP, 进入域名扫描
    doms = []
    for tok in toks[start:]:
        if tok.startswith("#"):           # 行内注释, 停止
            break
        d = _domain_like_token(tok)
        if d and d not in _HOSTS_LOCAL_NAMES and d not in doms:
            doms.append(d)
    if not doms:
        return Rule(raw=s, kind=K_INVALID, dropped=True, source=source)
    return Rule(raw=s, kind=K_DOMAIN, domains=tuple(doms), domain=doms[0],
                source=source)


def parse_line(line: str, source: str = "") -> Rule:
    """解析单行, 返回 Rule。这是整个引擎的词法核心。"""
    s = line.strip().lstrip("﻿")
    if not s:
        return Rule(raw="", kind=K_INVALID, dropped=True, source=source)

    # uBO 预解析指令 (先于普通注释: `!#include` 以 `!` 开头)
    if s.startswith("!#"):
        return Rule(raw=s, kind=K_PREPROC, dropped=True, source=source)

    # 元素隐藏/CSS/JS/HTML 注入类 — 最早分隔符 + 合法域名前缀
    idx = _find_cosmetic(s)
    if idx is not None:
        return Rule(raw=s, kind=K_COSMETIC, source=source)

    # 列表头 [Adblock Plus 2.0] / [uBlock Origin ...]
    if s.startswith("[") and s.endswith("]") and "]" not in s[:-1]:
        return Rule(raw=s, kind=K_HEADER, dropped=True, source=source)

    # 注释行 (! 或 # 开头)
    if s[0] in "!#":
        return Rule(raw=s, kind=K_COMMENT, dropped=True, source=source)

    # 例外规则 (@@) — 先于杂行扫描: 修饰符值可含空格
    if s.startswith("@@"):
        return _parse_exception(s, source)

    # AdGuard HTML 过滤: domain$$selector / 例外 domain$@$selector
    if "$@$" in s or "$$" in s:
        cut = s.find("$@$")
        if cut < 0:
            cut = s.find("$$")
        if cut > 0 and _is_host(s[:cut].strip().split("/")[0]):
            return Rule(raw=s, kind=K_COSMETIC, source=source)

    # 含空白 → 判定是「hosts 式/杂行」还是「修饰符值含空格的规则」:
    # 规则形态 = 第一个空白前的部分含 "$" 或以 "||"/"@@"/"|" 开头 (如 $csp=script-src 'none',
    # $dnsrewrite=NOERROR;MX;32 example.mail, $header=/foo\, bar$/) → 按单 token 规则解析;
    # hosts 形态 = 空白前是 IP/裸域名 (如 "0.0.0.0 a.com") → hosts 扫描。
    if any(ch.isspace() for ch in s):
        first_tok = s.split(None, 1)[0]
        if ("$" in first_tok or first_tok.startswith("||")
                or first_tok.startswith("@@") or first_tok.startswith("|")):
            return _parse_single_token(s, source)
        return _parse_tokens(s, source)

    # 单 token 规则
    return _parse_single_token(s, source)


# ---------------------------------------------------------------------------
# 2. 合并层: Merger / MergeResult
# ---------------------------------------------------------------------------

# AdGuard Home 可兑现的网络修饰符 (语法文档 §8) — 用于筛选可进 DNS 输出的网络规则
_DNS_NET_MODS = {"dnsrewrite", "dnstype", "client", "ctag", "important", "denyallow"}


def _canon_key(pattern: str, mod_tokens) -> str:
    """规则语义键: pattern + 规范化(排序)修饰符。修饰符顺序无关 → 同键去重。"""
    if not mod_tokens:
        return pattern
    return pattern + "$" + ",".join(sorted(mod_tokens))


def _net_canon_key(rule: Rule) -> str:
    return _canon_key(rule.pattern, split_mod_tokens(rule.modifiers))


@dataclass
class MergeResult:
    """finalize() 的产物。各字段均为可直接写出的行列表。"""
    all_blocks: List[str] = field(default_factory=list)      # 全格式输出: ||d^ 域名拦截
    all_network: List[str] = field(default_factory=list)     # 全格式输出: 网络规则原文
    all_cosmetic: List[str] = field(default_factory=list)    # 全格式输出: 元素隐藏/注入
    all_exceptions: List[str] = field(default_factory=list)  # 全格式输出: @@ 例外
    adguard_blocks: List[str] = field(default_factory=list)  # AGH: 子域折叠+例外剔除后的 ||d^
    adguard_dns: List[str] = field(default_factory=list)     # AGH: 完整订阅(blocks+DNS网络规则+白名单)
    hosts: List[str] = field(default_factory=list)          # 0.0.0.0 d
    domains: List[str] = field(default_factory=list)         # 纯域名
    whitelist: List[str] = field(default_factory=list)       # DNS 白名单 (@@ 原文)
    stats: dict = field(default_factory=dict)


class Merger:
    """规则汇合器: 精确+语义去重, badfilter, 例外保护, 子域折叠。"""

    def __init__(self, collapse_subdomains: bool = True):
        self.collapse = collapse_subdomains
        self._dom_imp: Dict[str, bool] = {}      # 域名 → 是否 $important
        self._net: Dict[str, str] = {}           # 语义键 → 原文
        self._cosmetic: Dict[str, str] = {}
        self._exc: Dict[str, Rule] = {}           # 例外原文 → Rule
        self._badfilter_targets: Set[str] = set()
        self._stats_dropped = 0
        self._local_count = 0

    # -- 收集 ------------------------------------------------------------
    def add_rule(self, rule: Rule) -> None:
        if rule.dropped:
            self._stats_dropped += 1
            return
        if rule.source == "local-additions":
            self._local_count += 1
        if rule.kind == K_DOMAIN:
            for d in rule.domains:
                self._dom_imp[d] = self._dom_imp.get(d, False) or rule.important
        elif rule.kind == K_NETWORK:
            mods = {m.split("=", 1)[0] for m in split_mod_tokens(rule.modifiers.lower())}
            if "badfilter" in mods:
                # badfilter 规则自身不拦截; 其语义键(去除 badfilter 后)即失效目标
                keep = [t for t in split_mod_tokens(rule.modifiers) if t.lower() != "badfilter"]
                self._badfilter_targets.add(_canon_key(rule.pattern, keep))
            else:
                self._net.setdefault(_net_canon_key(rule), rule.raw)
        elif rule.kind == K_COSMETIC:
            self._cosmetic.setdefault(rule.raw, rule.raw)
        elif rule.kind == K_EXCEPTION:
            self._exc.setdefault(rule.raw, rule)

    def add_lines(self, lines: Iterable[str], source: str = "") -> None:
        for ln in lines:
            self.add_rule(parse_line(ln, source))

    # -- 收敛 ------------------------------------------------------------
    def finalize(self) -> MergeResult:
        res = MergeResult()
        bad = self._badfilter_targets

        # 网络规则: 去除被 badfilter 击中的
        res.all_network = sorted(raw for key, raw in self._net.items() if key not in bad)

        # 例外: DNS 相关白名单 + 每域名 important 标记
        exc_imp: Dict[str, bool] = {}
        for r in self._exc.values():
            if r.dns_relevant:
                exc_imp[r.domain] = exc_imp.get(r.domain, False) or r.important
        res.whitelist = sorted({r.raw for r in self._exc.values()
                                if r.dns_relevant and r.domain})
        res.all_exceptions = sorted(self._exc)

        # 域名条目: (domain, important, canonical)
        items = []
        for d in sorted(self._dom_imp):
            imp = self._dom_imp[d]
            canon = "||{}^".format(d) + ("$important" if imp else "")
            if canon in bad:                    # 被 badfilter 击中 → 全输出剔除
                continue
            items.append((d, imp, canon))

        # DNS 输出裁决: 例外赢, 除非 拦截带important 且 例外不带
        survive = []
        for d, imp, canon in items:
            if d in exc_imp and not (imp and not exc_imp[d]):
                continue
            survive.append((d, imp, canon))

        # 浏览器输出 (all_blocks): 剔除被 @@ DNS 例外解锁的域名 (防止拦了又解),
        # 纯域名规则超过阈值时截断 — 大量 ||d^ 来自 DNS 列表, 对浏览器价值低且
        # 会让订阅体积膨胀到加载失败 (即"订阅了但无拦截"的根因)。
        BROWSER_DOMAIN_CAP = 150_000
        browser_items = [(d, imp, canon) for d, imp, canon in survive
                         if not (d in exc_imp and not (imp and not exc_imp[d]))]
        if len(browser_items) > BROWSER_DOMAIN_CAP:
            # 保留顺序: $important 优先, 其余按域名稳定序
            browser_items.sort(key=lambda t: (not t[1], t[0]))
            browser_items = browser_items[:BROWSER_DOMAIN_CAP]
            browser_items.sort(key=lambda t: t[2])     # 输出仍按规则文本排序
        res.all_blocks = [c for _, _, c in browser_items]

        # hosts / domains: 精确匹配语义, 保留子域, 排序
        res.domains = [d for d, _, _ in survive]
        res.hosts = ["0.0.0.0 " + d for d, _, _ in survive]

        # adguard_blocks: ||d^ 含子域语义 → 可折叠被父域覆盖的子域
        blocked = {d for d, _, _ in survive}
        res.adguard_blocks = []
        for d, imp, canon in survive:
            if self.collapse:
                parts = d.split(".")
                if any(".".join(parts[k:]) in blocked for k in range(1, len(parts))):
                    continue
            res.adguard_blocks.append(canon)

        # AGH 完整订阅: blocks + DNS 可兑现网络规则 + DNS 白名单
        dns_net = self._dns_capable_network(bad)
        res.adguard_dns = res.adguard_blocks + dns_net + res.whitelist

        res.all_cosmetic = sorted(self._cosmetic)
        res.stats = {
            "local_additions": self._local_count,
            "domains_unique": len(res.domains),   # 与 DNS 输出一致 (例外已剔除)
            "network_unique": len(res.all_network),
            "cosmetic_unique": len(res.all_cosmetic),
            "exceptions_unique": len(res.all_exceptions),
            "whitelist_unique": len(res.whitelist),
            "badfilter_targets": len(bad),
            "dropped": self._stats_dropped,
        }
        return res

    def _dns_capable_network(self, bad: Set[str]) -> List[str]:
        """修饰符全部属于 AGH 支持集的网络规则 (dnsrewrite/dnstype/client/...)。"""
        out, seen = [], set()
        for key, raw in self._net.items():
            if key in bad or key in seen:
                continue
            pattern, mods = _split_modifiers(raw)
            keys = {m.split("=", 1)[0] for m in split_mod_tokens(mods.lower())}
            if keys and keys <= _DNS_NET_MODS:
                seen.add(key)
                out.append(raw)
        return sorted(out)


# ---------------------------------------------------------------------------
# 3. 下载层: fetch_text + 重试
# ---------------------------------------------------------------------------

class FetchError(Exception):
    """所有下载失败的统一异常。"""


class HTTPStatusError(FetchError):
    def __init__(self, status: int):
        super().__init__(f"HTTP {status}")
        self.status = status


# 不重试的 4xx: 客户端错误, 重试无意义 (429 Too Busy 除外, 会重试)
_NO_RETRY_STATUS = {400, 401, 403, 404, 405, 406, 410}

DEFAULT_UA = ("Mozilla/5.0 (compatible; AdFilterMerge/{}; +https://github.com)"
              .format(__version__))


def _urllib_transport(url: str, timeout: float = 30) -> str:
    """默认传输: urllib (零第三方依赖)。requests 可用在环境时优先使用。"""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _urllib_status_error(exc: urllib.error.HTTPError) -> HTTPStatusError:
    return HTTPStatusError(exc.code)


def fetch_text(url: str, *, transport=None, retries: int = 3,
               retry_delay: float = 2.0, timeout: float = 30) -> str:
    """下载一个上游列表, 返回解码文本。带指数退避重试。"""
    import time as _time

    transport = transport or _urllib_transport
    last_exc: Exception = None
    for attempt in range(max(1, retries)):
        try:
            return transport(url, timeout)
        except HTTPStatusError as e:
            if e.status in _NO_RETRY_STATUS:
                raise FetchError(f"{url}: HTTP {e.status} (不重试)") from e
            last_exc = e
        except urllib.error.HTTPError as e:          # 默认传输抛出
            if e.code in _NO_RETRY_STATUS:
                raise FetchError(f"{url}: HTTP {e.code} (不重试)") from e
            last_exc = _urllib_status_error(e)
        except Exception as e:                        # OSError / 超时 / 解码异常
            last_exc = e
        if attempt < retries - 1 and retry_delay > 0:
            _time.sleep(retry_delay * (2 ** attempt))
    raise FetchError(f"{url}: {last_exc}") from last_exc


# ---------------------------------------------------------------------------
# 4. 配置加载: load_sources (config.json / config.yaml)
# ---------------------------------------------------------------------------

def load_sources(path: str) -> List[dict]:
    """读取配置文件, 返回启用的 sources 列表 (按 URL 去重, 保序)。"""
    import json

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    if path.endswith((".yaml", ".yml")):
        try:
            import yaml                                    # 可选依赖
            data = yaml.safe_load(text)
        except ImportError:
            raise RuntimeError("YAML 配置需要 pyyaml: pip install pyyaml")
    else:
        data = json.loads(text)

    out, seen = [], set()
    for src in data.get("sources", []):
        if not src.get("enabled", True):
            continue
        url = src.get("url", "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"name": src.get("name") or url.rsplit("/", 1)[-1] or url,
                    "url": url})
    return out


def load_extra_rules(path: str) -> List[str]:
    """读取配置的 extra_rules: 本地补充规则 (上游未覆盖的缺口, 自主可控)。"""
    import json

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise RuntimeError("YAML 配置需要 pyyaml")
    else:
        data = json.loads(text)
    out = []
    for ln in data.get("extra_rules", []):
        ln = ln.strip()
        if ln and ln not in out:
            out.append(ln)
    return out


# ---------------------------------------------------------------------------
# 5. 输出层: write_outputs
# ---------------------------------------------------------------------------

# 北京时间 (开发文案: "时间对接北京时间")
BJT = timezone(timedelta(hours=8))

# ABP 兼容客户端 (Adblock Plus 等) 严格要求的首行语法声明
ABP_HEADER = "[Adblock Plus 2.0]"


def now_bjt() -> str:
    return datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S +0800")


def _header_lines(title: str, now: str, count: int, kind: str,
                  abp: bool = False) -> List[str]:
    title = title or "AdFilter Merge Base"   # 空 → 默认; 非空不作二次包装
    head = [ABP_HEADER] if abp else []       # ABP/uBO/AdGuard 认首行语法声明
    return head + [
        f"! Title: {title} · {kind}",
        f"! Description: 多上游广告过滤规则自动合并 (去重/归并/例外保护) — {kind} 格式",
        "! Homepage: https://github.com/wansheng8/LJGZ",
        "! Licence: 各上游列表许可证的并集, 见 README 致谢部分",
        f"! Version: {now}",
        f"! Last Modified: {now} (北京时间 UTC+8)",
        f"! Expires: 12 hours",
        f"! Rules: {count}",
        "",
    ]


def _write(path: str, lines: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")


def _chunk_by_bytes(lines: List[str], *, max_bytes: int) -> List[List[str]]:
    """把行列表切成若干卷, 每卷字节数 (含换行) ≤ max_bytes; 保持行序。"""
    chunks, cur, cur_bytes = [], [], 0
    for ln in lines:
        cost = len(ln.encode("utf-8")) + 1
        if cur and cur_bytes + cost > max_bytes:
            chunks.append(cur)
            cur, cur_bytes = [], 0
        cur.append(ln)
        cur_bytes += cost
    if cur:
        chunks.append(cur)
    return chunks


# ---------------------------------------------------------------------------
# 5.1 徽章文件: shields.io endpoint JSON + 本地静态 SVG (墙内可见, 不依赖外站)
# ---------------------------------------------------------------------------

def _fmt_wan(n: int) -> str:
    """449997 → '45.0万'; 123 → '123' (不足一万显示原数)。"""
    if n < 10000:
        return str(n)
    return f"{n / 10000:.1f}万"


def _strip_tz_bjt(now: str) -> str:
    """"2026-09-27 02:41:00 +0800" → "2026-09-27 02:41"。"""
    return now.split("+")[0].strip()[:16]


def _text_w(s: str, fs: int = 11) -> int:
    """估算文本像素宽 (CJK 全宽, 其余按比例)。"""
    import unicodedata
    w = 0.0
    for ch in s:
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            w += fs
        elif ch == " ":
            w += fs * 0.36
        elif ch in "·|-–/:.":
            w += fs * 0.40
        elif ch.isdigit() or ch.isupper():
            w += fs * 0.66
        else:
            w += fs * 0.55
    return int(round(w))


def _svg_badge(label: str, message: str, color: str) -> str:
    """生成 shields 风格的静态 SVG 徽章 (双段圆角矩形)。color 为无 # 的 hex。"""
    fs, pad, H = 11, 11, 20
    lw = _text_w(label, fs) + pad * 2
    mw = _text_w(message, fs) + pad * 2
    W = lw + mw
    AMP = chr(38); LT = chr(60); GT = chr(62); QUOT = chr(34)
    def esc(s: str) -> str:
        return (s.replace(AMP, AMP + "amp;").replace(LT, AMP + "lt;")
                .replace(GT, AMP + "gt;").replace(QUOT, AMP + "quot;"))
    font = ("Segoe UI, PingFang SC, Hiragino Sans GB, Microsoft YaHei, "
            "Helvetica, Arial, sans-serif")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'role="img" aria-label="{esc(label)}: {esc(message)}">'
        f'<title>{esc(label)}: {esc(message)}</title>'
        f'<clipPath id="c"><rect width="{W}" height="{H}" rx="6"/></clipPath>'
        f'<g clip-path="url(#c)">'
        f'<rect width="{lw}" height="{H}" fill="#24292f"/>'
        f'<rect x="{lw}" width="{mw}" height="{H}" fill="#{color}"/>'
        f'<text x="{pad}" y="14.5" font-family="{font}" font-size="{fs}" '
        f'font-weight="600" fill="#ffffff">{esc(label)}</text>'
        f'<text x="{lw + pad}" y="14.5" font-family="{font}" font-size="{fs}" '
        f'font-weight="700" fill="#ffffff">{esc(message)}</text>'
        f'</g></svg>'
    )


def write_badge_files(outdir: str, stats: dict, now: str) -> Dict[str, str]:
    """生成 output/badge-*.json (shields endpoint) 与 badge-*.svg (README 直用)。"""
    import json as _json

    os.makedirs(outdir, exist_ok=True)
    domains = stats.get("domains_unique", 0)
    rules = sum(stats.get(k, 0) for k in
                ("domains_unique", "network_unique",
                 "cosmetic_unique", "exceptions_unique"))
    updated = _strip_tz_bjt(now)
    specs = [
        ("rules",   "规则总数",     _fmt_wan(rules),   "10b981"),
        ("domains", "拦截域名",     _fmt_wan(domains), "3b82f6"),
        ("updated", "北京时间更新", updated,           "f59e0b"),
    ]
    paths: Dict[str, str] = {}
    for key, label, message, color in specs:
        endpoint = {"schemaVersion": 1, "label": label, "message": message,
                    "color": color, "cacheSeconds": 3600}
        jpath = os.path.join(outdir, f"badge-{key}.json")
        with open(jpath, "w", encoding="utf-8", newline="\n") as f:
            _json.dump(endpoint, f, ensure_ascii=False)
        paths[f"badge-{key}"] = jpath
        spath = os.path.join(outdir, f"badge-{key}.svg")
        with open(spath, "w", encoding="utf-8", newline="\n") as f:
            f.write(_svg_badge(label, message, color))
    # 固定信息徽章 (无数据依赖)
    for key, label, message, color in [
        ("cadence", "更新节奏", "每日 08:00 / 20:00", "8b5cf6"),
        ("compat",  "兼容",     "ABP · uBO · AdGuard · AGH · Pi-hole", "0891b2"),
    ]:
        with open(os.path.join(outdir, f"badge-{key}.svg"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(_svg_badge(label, message, color))
    return paths


def write_outputs(res: MergeResult, outdir: str, *, title: str,
                  now: Optional[str] = None,
                  max_part_bytes: int = 18_000_000) -> Dict[str, str]:
    """把 MergeResult 写出为 6 个文件, 返回 {用途: 路径} 映射。

    all-part-*.txt: 把 all.txt 正文按 max_part_bytes 切卷, 每卷自带完整头部
    (含 [Adblock Plus 2.0] 首行), 多卷全部订阅 == 完整 all.txt;
    用于绕过 jsDelivr 20MB 单文件上限。
    """
    os.makedirs(outdir, exist_ok=True)
    now = now or now_bjt()

    n_all = (len(res.all_blocks) + len(res.all_network) +
             len(res.all_cosmetic) + len(res.all_exceptions))
    n_dns = len(res.adguard_dns)
    n_hosts = len(res.hosts)
    n_dom = len(res.domains)

    paths = {}

    all_body = res.all_blocks + res.all_network + res.all_cosmetic + res.all_exceptions
    # 清理上一轮遗留的分卷文件 (本轮可能不再产生, 或卷数减少)
    for old in glob(os.path.join(outdir, "all-part-*.txt")):
        os.remove(old)
    paths["all"] = os.path.join(outdir, "all.txt")
    _write(paths["all"],
           _header_lines(title, now, n_all, "全格式", abp=True) + all_body)

    # CDN 分卷 (jsDelivr 单文件 <20MB)
    all_path_size = os.path.getsize(paths["all"])
    if all_path_size > max_part_bytes:
        chunks = _chunk_by_bytes(all_body, max_bytes=max_part_bytes - 4096)
        for ix, chunk in enumerate(chunks, 1):
            key = f"all-part-{ix:02d}"
            paths[key] = os.path.join(outdir, key + ".txt")
            _write(paths[key],
                   _header_lines(title, now, len(chunk),
                                 f"全格式 分卷 {ix}/{len(chunks)}", abp=True)
                   + chunk)

    paths["adguard"] = os.path.join(outdir, "adguard.txt")
    _write(paths["adguard"],
           _header_lines(title, now, n_dns, "AdGuard Home DNS", abp=True)
           + res.adguard_dns)

    paths["hosts"] = os.path.join(outdir, "hosts.txt")
    hosts_lines = []
    for ln in _header_lines(title, now, n_hosts, "hosts"):
        hosts_lines.append("# " + ln[2:] if ln.startswith("! ") else ln)
    _write(paths["hosts"], hosts_lines + res.hosts)

    paths["domains"] = os.path.join(outdir, "domains.txt")
    dom_head = [("# " + ln[2:]) if ln.startswith("! ") else ln
                for ln in _header_lines(title, now, n_dom, "纯域名")]
    _write(paths["domains"], dom_head + res.domains)

    paths["whitelist"] = os.path.join(outdir, "whitelist.txt")
    wl_head = [("# " + ln[2:]) if ln.startswith("! ") else ln
               for ln in _header_lines(title, now, len(res.whitelist), "DNS 白名单")]
    _write(paths["whitelist"], wl_head + res.whitelist)

    paths["stats"] = os.path.join(outdir, "stats.json")
    import json as _json
    with open(paths["stats"], "w", encoding="utf-8") as f:
        _json.dump(res.stats, f, ensure_ascii=False, indent=2, sort_keys=True)

    paths.update(write_badge_files(outdir, res.stats, now))

    return paths


# ---------------------------------------------------------------------------
# 6. 主流程: run() + CLI
# ---------------------------------------------------------------------------

def run(config_path: str, *, outdir: str, transport=None,
        retries: int = 3, retry_delay: float = 2.0) -> dict:
    """下载全部源 → 解析合并 → 写出输出。返回运行报告 dict。"""
    sources = load_sources(config_path)
    merger = Merger()
    ok, failed = [], []

    for src in sources:
        try:
            text = fetch_text(src["url"], transport=transport,
                              retries=retries, retry_delay=retry_delay)
        except FetchError as e:
            failed.append({"name": src["name"], "error": str(e)})
            print(f"[warn] 源下载失败, 跳过: {src['name']} — {e}", file=sys.stderr)
            continue
        n_before = len(merger._dom_imp) + len(merger._net) + \
            len(merger._cosmetic) + len(merger._exc)
        merger.add_lines(text.splitlines(), source=src["name"])
        n_after = len(merger._dom_imp) + len(merger._net) + \
            len(merger._cosmetic) + len(merger._exc)
        ok.append({"name": src["name"], "rules_added": n_after - n_before})

    if not ok:
        raise FetchError("所有上游源均下载失败, 拒绝生成空列表")

    # 本地补充规则 (config 的 extra_rules) — 最后合入, 优先级最高
    extras = load_extra_rules(config_path)
    if extras:
        merger.add_lines(extras, source="local-additions")

    res = merger.finalize()
    # 源统计并入 stats.json (订阅中心/徽章动态化数据源)
    res.stats["sources_total"] = len(sources)
    res.stats["sources_ok"] = len(ok)
    res.stats["sources_failed"] = len(failed)
    paths = write_outputs(res, outdir, title="AdFilter Merge")

    return {
        "paths": paths,
        "sources_ok": len(ok),
        "sources_failed": len(failed),
        "sources_detail": ok + failed,
        "stats": res.stats,
        "now_bjt": now_bjt(),
    }


def main(argv=None) -> int:
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(
        prog="merge_filters",
        description="广告过滤规则收集·转换·合并·去重引擎 (北京时间)")
    ap.add_argument("--config", default="config.json",
                    help="配置文件 (config.json 或 config.yaml)")
    ap.add_argument("--outdir", default=None,
                    help="输出目录 (默认: 配置文件中的 output.dir 或 ./output)")
    ap.add_argument("--test", action="store_true",
                    help="仅运行内置自检 (解析/合并样例), 不下载不写文件")
    args = ap.parse_args(argv)

    if args.test:
        return _selftest()

    outdir = args.outdir
    if not outdir:
        with open(args.config, "r", encoding="utf-8") as f:
            text = f.read()
        if args.config.endswith((".yaml", ".yml")):
            try:
                import yaml
                data = yaml.safe_load(text)
            except ImportError:
                raise SystemExit("YAML 配置需要 pyyaml")
        else:
            data = _json.loads(text)
        outdir = (data.get("output") or {}).get("dir") or "output"

    report = run(args.config, outdir=outdir)
    print(_json.dumps({
        "sources_ok": report["sources_ok"],
        "sources_failed": report["sources_failed"],
        "stats": report["stats"],
        "now_bjt": report["now_bjt"],
        "paths": report["paths"],
    }, ensure_ascii=False, indent=2))
    return 0 if report["sources_failed"] == 0 else 1


def _selftest() -> int:
    """快速冒烟: 若干代表性行进解析+合并, 打印分类计数。"""
    sample = [
        "||example.com^", "0.0.0.0 ads.example.com", "js.io",
        "||ads.com^$script", "@@||good.com^$document", "a.com##.ad",
        "! comment", "[Adblock Plus 2.0]", "", "junk line",
    ]
    m = Merger()
    m.add_lines(sample)
    res = m.finalize()
    import json as _json
    print(_json.dumps(res.stats, ensure_ascii=False, indent=2))
    print(f"domains={res.domains}")
    print(f"selftest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
