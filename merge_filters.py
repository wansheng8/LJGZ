#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_filters — 广告过滤规则收集·转换·合并·去重引擎
====================================================

输入兼容: Adblock Plus / uBlock Origin / AdGuard 扩展语法, AdGuard Home,
         Pi-hole (hosts 式 / POSIX ERE 正则), 纯域名列表。

输出(由 merge 阶段生成, 详见 README):
  - all.txt            原样保留全部语法 (ABP/uBO/AdGuard 可订阅)
  - adguard.txt        DNS 场景可用的 ||domain^ + @@例外 + $dnstype/$denyallow 等 DNS 修饰符规则
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

# 例外规则中 DNS 侧可兑现的修饰符: 空(裸例外, 会被丢弃) / important
# $document / $doc 是浏览器内容类型 —— 只放行"页面文档", 不能升级为整域
# DNS 放行, 否则会把同域接口/图片/脚本一并放开。
_DNS_OK_EXC_MODS = {"important"}

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

# ||domain^ 或 ||domain — 纯域名锚点形式 (含 AdGuard 的 ||domain^|)
_ANCHOR_RE = re.compile(r"^\|\|([a-z0-9.-]+?)(\^|\|\^)?\|?$", re.IGNORECASE)
# AGH pattern 允许的形状: 主机名掩码 ||host^ / ||host / ||*.host^ (域名内允许 * 通配)
_DNS_HOST_MASK_RE = re.compile(r"^\|\|[a-z0-9_.*-]+\^?\|?$", re.IGNORECASE)
# *.domain
_WILD_PREFIX_RE = re.compile(r"^\*\.([a-z0-9.-]+?)(\^?)$", re.IGNORECASE)
# Pi-hole 常见正则形状: (^|\.)a\.b$ / (\.|^)a\.b$  →  a.b
_PIHOLE_SUB_RE = re.compile(
    r"^\((?:\\\.\|\^|\^\|\\\.)\)((?:[a-z0-9-]+\\\.)*[a-z0-9-]+)\$$",
    re.IGNORECASE,
)
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


# 上游列表混入的非语义修饰符记号: 任何引擎都不认, 会让客户端把整行当无效
# 规则丢弃 (拦不住)。它们不承载过滤语义, 去掉后规则回归标准语法:
#   · `_____`   占位符 (出现在带 denyallow 的规则里)
#   · `reason=` 人读的原因说明 (malicious / tracker …)
_NON_SEMANTIC_MOD_TOKENS = {"_____"}
_NON_SEMANTIC_MOD_PREFIXES = ("reason=",)


def _split_mods_raw(mods: str):
    """按未转义逗号切分, 但保留原文 (含 `\\,` 转义), 便于原样拼回。"""
    out, buf, i = [], [], 0
    while i < len(mods):
        c = mods[i]
        if c == "\\" and i + 1 < len(mods):
            buf.append(mods[i:i + 2])
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
    return out


def _sanitize_modifiers(mods: str) -> str:
    """去掉非语义修饰符; 未命中时原样返回, 不做无谓改写。"""
    if not mods:
        return mods
    parts = _split_mods_raw(mods)
    keep = [p for p in parts
            if p.strip().lower() not in _NON_SEMANTIC_MOD_TOKENS
            and not p.strip().lower().startswith(_NON_SEMANTIC_MOD_PREFIXES)]
    if len(keep) == len(parts):
        return mods
    return ",".join(keep).strip()


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
    # `###…` 行的 `##` 之后必须接着 id 选择器。若是空白/#/行尾, 那是上游用 `#`
    # 画的分隔注释 (如 `### Version: …` / `####…`), 不是元素隐藏规则。
    if best == 0 and s.startswith("##"):
        sel = s[2:]
        if sel[:1] == "#" and (len(sel) == 1 or sel[1] in "# \t"):
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


def _is_reserved_arpa(d: str) -> bool:
    """in-addr.arpa / ip6.arpa 等反向解析保留区 — 不是可拦截主机名。"""
    return norm_domain(d).endswith(".arpa")


def _domain_like_token(tok: str):
    """hosts/杂行扫描: 该 token 是否像一个可拦截域名。"""
    if _is_reserved_arpa(tok):             # in-addr.arpa / ip6.arpa 保留
        return None
    tok = norm_domain(tok)
    return tok if _is_domain(tok) else None


def _extract_anchor_domain(pattern: str) -> str:
    """从 `||domain^` 类模式提取域名; 失败返回空。"""
    m = _ANCHOR_RE.match(pattern)
    if not m:
        return ""
    d = norm_domain(m.group(1))
    if _is_reserved_arpa(d):               # 反向解析区不可归并为域名
        return ""
    return d if _is_domain(d) else ""


def _is_dns_pattern(pattern: str) -> bool:
    """AGH pattern 是否为 DNS 层可匹配的形状: 主机名掩码 或 /regex/。

    路径/查询串/端口只存在于 URL, DNS 查询只带主机名 — 这类规则进了
    adguard.txt 也永不命中 (部分 AGH 版本记为无效规则)。
    """
    p = pattern.strip()
    if p.startswith("/") and p.endswith("/") and len(p) > 2:
        return True
    return bool(_DNS_HOST_MASK_RE.match(p))


def _covered(d: str, blocked: Set[str]) -> bool:
    """d 是否已被"全请求类型"的域名拦截覆盖 (自身或任一祖先在 blocked)。

    `||d^` 的匹配含子域, 所以父域在 blocked 里也算覆盖。
    """
    if d in blocked:
        return True
    parts = d.split(".")
    for k in range(1, len(parts)):
        if ".".join(parts[k:]) in blocked:
            return True
    return False


def _parse_exception(s: str, source: str = "") -> Rule:
    body = s[2:]
    pattern, mods = _split_modifiers(body)
    clean = _sanitize_modifiers(mods)
    if clean != mods:                       # 去掉上游非语义记号, 原文同步改写
        s = "@@" + pattern + ("$" + clean if clean else "")
        mods = clean
    dom = _extract_anchor_domain(pattern) if pattern.startswith("||") else ""
    lower_mods = {m.split("=", 1)[0] for m in split_mod_tokens(mods.lower())}
    # DNS 相关: 修饰符为空或仅 $important (client/ctag/dnstype/内容类型
    # 含 $document/$doc 均不可在纯域名输出兑现 — 它们只管浏览器层)
    dns_rel = bool(dom) and lower_mods <= _DNS_OK_EXC_MODS
    return Rule(raw=s, kind=K_EXCEPTION, pattern=pattern, modifiers=mods,
                domain=dom, dns_relevant=dns_rel,
                important="important" in lower_mods, source=source)


def _parse_single_token(s: str, source: str = "") -> Rule:
    """无空白的规则行: ||锚点 / /regex/ / Pi-hole 正则 / *.域 / 裸域名 / 网络模式。"""
    pattern, mods = _split_modifiers(s)
    clean = _sanitize_modifiers(mods)
    if clean != mods:                       # 去掉上游非语义记号, 原文同步改写
        s = pattern + ("$" + clean if clean else "")
        mods = clean
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
        if _is_domain(d) and not _is_reserved_arpa(d):
            return Rule(raw=s, kind=K_DOMAIN, domains=(d,), domain=d, source=source)

    # 裸 IP 行 (hosts 文件脏数据): 无域名可拦, 丢弃而非当成子串网络规则
    if not mods and (_IPV4_RE.match(s) or (":" in s and _IPV6ISH_RE.match(s))):
        return Rule(raw=s, kind=K_INVALID, dropped=True, source=source)

    # 裸域名 (无任何修饰符/通配符/锚点); 允许 FQDN 尾点, 先规范化再校验
    if not mods:
        d = norm_domain(s)
        if _is_reserved_arpa(d):           # 反向解析区: 无可拦截域名, 丢弃
            return Rule(raw=s, kind=K_INVALID, dropped=True, source=source)
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
        # scriptlet (##+js, #%#//scriptlet) 与 HTML 过滤 (##^) 含 JS 片段参数,
        # 括号/引号不配对的截断规则客户端会整体跳过, 留着只占体积。
        # 普通 CSS 选择器 (##, #$#, #?#, $@# 等) 不做这层校验 — _parens_balanced
        # 会把 :has-text(/\(/) 这种含括号的正则字面量里的括号当成规则括号计数,
        # 那会误杀合法规则。
        marker = next((m for m in ("##+js(", "##+js?", "##+abp",
                                   "#%#//scriptlet(", "##^")
                       if m in s), None)
        if marker is not None and not _parens_balanced(s):
            return Rule(raw=s, kind=K_INVALID, dropped=True, source=source)
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


# 可被"裸域名块 ||d^"完全覆盖的纯请求类型/上下文修饰符。
# 这些标签只是收窄"拦哪种资源", 而裸 ||d^ 已拦该域所有请求 → 同域窄规则冗余。
# 凡含 =值(domain=/to=)、~否定、redirect/rewrite、$all、$important、denyallow
# 的规则都不在此集内 → 一律保留 (各有独立语义, 误删会漏拦)。
_SUBSUME_OK_MODS = {
    "script", "image", "stylesheet", "object", "subdocument",
    "xmlhttprequest", "ximage-request", "websocket", "webrtc",
    "ping", "beacon", "other", "doc", "document", "iframe", "font",
    "3p", "third-party", "1p", "first-party",
}
# 网络规则正文形如 ||d^ (纯域锚点, 无路径/通配) 才可参与同域消解
_TYPERULE_RE = re.compile(r"^\|\|([a-z0-9.-]+)\^$", re.I)


def _canon_key(pattern: str, mod_tokens) -> str:
    """规则语义键: pattern + 规范化(排序)修饰符。修饰符顺序无关 → 同键去重。"""
    if not mod_tokens:
        return pattern
    return pattern + "$" + ",".join(sorted(mod_tokens))


def _net_canon_key(rule: Rule) -> str:
    return _canon_key(rule.pattern, split_mod_tokens(rule.modifiers))


def _excepted(domain: str, exc: Set[str]) -> bool:
    """域名自身或任一上级域在例外集中 → 视为已放行。

    与 `||d^` 的子域语义对称: 拦 d 会连带拦 sub.d, 放行 d 也应连带放行 sub.d。
    """
    parts = domain.split(".")
    for k in range(len(parts)):
        if ".".join(parts[k:]) in exc:
            return True
    return False


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
    dropped_bare_exceptions: int = 0       # 被丢弃的裸整域无条件例外数


class Merger:
    """规则汇合器: 精确+语义去重, badfilter, 例外保护, 子域折叠。"""

    def __init__(self, collapse_subdomains: bool = True,
                 subsume_type_rules: bool = True):
        self.collapse = collapse_subdomains
        self.subsume_types = subsume_type_rules
        self._dom_imp: Dict[str, bool] = {}      # 域名 → 是否 $important
        self._net: Dict[str, str] = {}           # 语义键 → 原文
        self._cosmetic: Dict[str, str] = {}
        self._exc: Dict[str, Rule] = {}           # 例外原文 → Rule
        self._badfilter_targets: Set[str] = set()
        self._stats_dropped = 0
        self._local_count = 0
        self._subsumed_count = 0

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

    @staticmethod
    def _has_numeric_label(d: str) -> bool:
        """域名是否含"全数字 label 段"。IP 段 (9.9.9.9 / 10.0.0.1) 在 AdBlock
        语义里有歧义, 且数字段域名罕见 — 一律不折叠 (保守保护)。"""
        return any(re.fullmatch(r"\d+", seg) for seg in d.split(".") if seg)

    def _fold_redundant(self, items):
        """子域折叠。

        items: [(domain, important, canon)] (finalize 的 survive 列表)。
        返回 kept — 未被折叠的条目 (IP 数字 label 保护, 不折叠; 折叠关闭时
        全保留)。

        折叠判据必须保住 `$important`: 子域被父域覆盖时, 只有父域链上存在
        同等强度的拦截 (父域也带 $important) 才能丢; 否则丢掉子域的
        `$important` 会让上游 `@@` 例外重新盖住它 ——
        test_safe_tracking_domains 的前提就是"只有 $important 能压过例外"。
        子域的 $important 仍不向父域提升 (提升会连带压过兄弟子域的例外),
        只保留子域自身那条。
        """
        if not self.collapse:
            return list(items)
        blocked_any = {d for d, _, _ in items}
        blocked_imp = {d for d, imp, _ in items if imp}
        kept = []
        for d, imp, canon in items:
            if self._has_numeric_label(d):
                kept.append((d, imp, canon))
                continue
            parts = d.split(".")
            folded = False
            for k in range(1, len(parts)):
                anc = ".".join(parts[k:])
                # 子域非 important: 父域任意拦截都已覆盖; 子域 important:
                # 必须父域拦截也带 $important 才算覆盖。
                if anc in blocked_imp or (not imp and anc in blocked_any):
                    folded = True
                    break
            if not folded:
                kept.append((d, imp, canon))
        return kept

    def _subsume_type_rules(self, candidates: List[str],
                            browser_items: List[Tuple[str, bool, str]]) -> List[str]:
        """同域纯 type 网络规则消解。

        candidates: all_network 候选 (已去 badfilter)。
        browser_items: 截断后的浏览器域名块 (domain, important, canon)。

        若某域 d 已进 all_blocks (即 ||d^ 全请求类型拦截), 则同域"纯 type"
        窄规则 (||d^$script 等) 是严格子集 → 删除 (拦截结果不变, 省体积)。
        红线: 含 =值 / ~ / redirect / rewrite / $all / $important / denyallow
        的窄规则一律保留; 数字 label (IP 段) 跳过; 被截断掉的域的窄规则也
        保留 (裸规则不在 all.txt, 删了会漏拦)。
        """
        if not self.subsume_types:
            return candidates
        covered = {d for d, _, _ in browser_items}
        keep = []
        removed = 0
        for raw in candidates:
            pattern, mods = _split_modifiers(raw)
            m = _TYPERULE_RE.match(pattern)
            can_drop = False
            if m:
                d = m.group(1).lower().rstrip(".")
                if d in covered and not self._has_numeric_label(d):
                    tok = [t.lower() for t in split_mod_tokens(mods)]
                    # 必须全部是纯 type/上下文标签, 且非空
                    if tok and all(t in _SUBSUME_OK_MODS for t in tok):
                        can_drop = True
            if can_drop:
                removed += 1
            else:
                keep.append(raw)
        self._subsumed_count = removed
        return keep

    # -- 收敛 ------------------------------------------------------------
    def _all_mirrors(self, items, net_candidates):
        """`$all` 兼容镜像: AdGuard 专有修饰符 → 跨引擎等价规则。

        `$all` 只有 AdGuard 认; uBO / ABP 会把整行判为无效并丢弃。镜像就是
        "去掉 $all 的同一规则": 无类型修饰符即全请求类型, 与 $all 强度相同,
        但**不用 $important** —— 不提高优先级, 站点自己的 `@@` 仍可放行。

        纯域形态 `||d^$all` 只在该域尚无其它全类型拦截时才补 (否则上千条
        冗余); 路径/正则/带 `domain=` 等复合形态按原式去 $all 补一条。

        返回 (域名镜像, 网络镜像)。
        """
        blocked = {d for d, _, _ in items}
        dom_mirrors = []
        net_mirrors = []
        for raw in net_candidates:
            pattern, mods = _split_modifiers(raw)
            toks = _split_mods_raw(mods)
            keys = {t.split("=", 1)[0].strip().lower() for t in toks}
            if "all" not in keys or "badfilter" in keys:
                continue
            rest = [t for t in toks
                    if t.split("=", 1)[0].strip().lower() != "all"]
            body = ",".join(rest).strip()
            m = _ANCHOR_RE.match(pattern)
            if m and not body:
                d = norm_domain(m.group(1))
                if (_is_domain(d) and not self._has_numeric_label(d)
                        and not _covered(d, blocked)):
                    dom_mirrors.append((d, False, "||{}^".format(d)))
                continue
            mirror = pattern + ("$" + body if body else "")
            if mirror != raw:
                net_mirrors.append(mirror)
        return dom_mirrors, net_mirrors

    def finalize(self) -> MergeResult:
        res = MergeResult()
        bad = self._badfilter_targets

        # 网络规则候选: 去除被 badfilter 击中的 (同域 type 消解在 all_blocks
        # 截断后统一做, 需要 browser_items 的覆盖集合, 见下)。
        net_candidates = sorted(raw for key, raw in self._net.items() if key not in bad)

        # 例外裁决拆成互不引用的两层:
        #   ① 浏览器层 (all.txt): 只清理"裸整域例外", 其余 @@ 原样输出, 交给
        #      客户端自己仲裁; 拦截规则不因例外剔除 —— $document 在 uBO /
        #      AdGuard 里本就是整站放行, 客户端算得比我们猜更准。
        #   ② DNS 层 (adguard / hosts / domains / whitelist): DNS 端没有内容
        #      类型概念, 只认 $important 例外; 命中才把该域从 DNS 拦截产物
        #      剔除并写入白名单。$document / $doc 只作用于浏览器层, 不升级
        #      为整域 DNS 放行 (否则同域接口/图片会一起被放开)。
        # 裸整域例外 (无修饰符的 @@||d^) 两层都不认: 它会全盘架空对应域的
        # 拦截, 且常来自上游"放行合法点击链接"的误判 (实测 314 条中 25 个域
        # 的全部拦截被打穿, 是"订阅了却拦不住"的根因)。
        bare_whole_domain = 0
        for r in list(self._exc.values()):
            if r.dns_relevant and not r.important and not r.modifiers.strip():
                del self._exc[r.raw]
                bare_whole_domain += 1

        # ① 浏览器层: 例外原样输出 (含 $document 等, 由客户端仲裁)
        res.all_exceptions = sorted(self._exc)
        res.dropped_bare_exceptions = bare_whole_domain

        # ② DNS 层: 独立计算可兑现例外 + 白名单
        # 只收 $important 例外 (裸例外上面已删); $document / $doc 属浏览器
        # 内容类型, 不进白名单, 也不从 DNS 拦截产物剔除该域。
        dns_exc: Set[str] = {r.domain for r in self._exc.values() if r.dns_relevant}
        # 白名单必须写 `@@||d^` (双竖线): 单竖线 `@@|d^` 的 `|` 锚定的是 URL
        # 开头, 而客户端匹配的是 `https://d/...`, `|d` 永远匹配不上 → 该条在
        # AdGuard Home / uBO 里是死规则 (本仓库 benchmark.py / live_benchmark.py
        # 的正则也只认 `@@||d^`, 单竖线连自家跑分都读不到)。
        res.whitelist = sorted("@@||{}^$important".format(d) for d in dns_exc)

        # 域名条目: (domain, important, canonical)
        items = []
        for d in sorted(self._dom_imp):
            imp = self._dom_imp[d]
            canon = "||{}^".format(d) + ("$important" if imp else "")
            if canon in bad:                    # 被 badfilter 击中 → 全输出剔除
                continue
            items.append((d, imp, canon))

        # `$all` 兼容镜像 (见 _all_mirrors): 域镜像在折叠 / DNS 例外 / hosts
        # 裁决之前并入, 与普通拦截走同一条流水线; 网络镜像在消解之后追加
        # (它们带独立 pattern, 不在域名集合里)。
        dom_mirrors, net_mirrors = self._all_mirrors(items, net_candidates)
        items.extend(dom_mirrors)
        items.sort()

        # DNS 输出裁决 (只看 DNS 层, 浏览器层不引用): 命中 $important 例外
        # 的域从 hosts / domains / adguard 剔除。结果只影响 DNS 产物。
        # 裁决沿祖先链继承: `||d^` 的拦截本身含子域语义, 例外必须对称地覆盖
        # 子域 —— 否则 hosts / domains 这种没有 @@ 机制的格式里, "放行 d" 会被
        # 上游仍在拦的 sub.d 打败, 白名单形同虚设 (声明放行却仍在拦)。
        # 与 benchmark.py / live_benchmark.py 的 is_blocked 判定保持一致。
        survive = []
        for d, imp, canon in items:
            if _excepted(d, dns_exc):
                continue
            survive.append((d, imp, canon))

        # 子域折叠 (不向父域提升 $important): 两套裁决各自折叠, 互不影响。
        #   · 浏览器 items: 不剔例外 → all_blocks 保留全部拦截, 由客户端用
        #     同文件里的 @@ 原文仲裁 ($document 即整站放行)。
        #   · DNS survive: 已剔例外 → adguard_blocks 与 hosts/domains 对齐。
        browser_items = self._fold_redundant(items)
        res.all_blocks = [c for _, _, c in browser_items]
        dns_kept = self._fold_redundant(survive)

        # 同域 type 消解 (高效拦截 + 省体积): 若域名 d 已被"全请求类型"拦截
        # (browser_items 里有 ||d^ / ||d^$important), 则同域纯类型窄规则
        # ||d^$script / ||d^$image 等是严格子集 — 裸规则已拦 d 的所有请求,
        # 删窄规则不改变任何拦截结果, 只省体积。保守红线:
        #   · 仅当所有修饰符都是纯"请求类型/上下文"标签才删 (SUBSUME_OK)
        #   · 含 =值(domain=/to=) / ~否定 / redirect / rewrite / $all /
        #     $important / denyallow 的一律保留 (有独立语义, 误删会漏拦)
        #   · 数字 label (IP 段) 跳过
        #   · 覆盖集用截断后的 browser_items: 被截断的域 (裸规则已不在 all.txt)
        #     的窄规则不会误删, 拦截能力 0 损失。
        res.all_network = self._subsume_type_rules(net_candidates,
                                                   browser_items)

        # `$all` 网络镜像 (路径/正则/带 domain= 的复合形态): 只在没有同式
        # 规则时追加, 避免重复。
        net_added = 0
        if net_mirrors:
            existing = set(res.all_network)
            add = sorted(set(net_mirrors) - existing)
            net_added = len(add)
            if add:
                res.all_network = sorted(res.all_network + add)

        # hosts / domains: 精确匹配语义, 保留子域 (不折叠), 排序
        res.domains = [d for d, _, _ in survive]
        res.hosts = ["0.0.0.0 " + d for d, _, _ in survive]

        # adguard_blocks: DNS 层折叠结果 (已剔例外, 与 hosts/domains 对齐)
        res.adguard_blocks = [c for _, _, c in dns_kept]

        # AGH 完整订阅: blocks + DNS 可兑现网络规则 + DNS 白名单
        dns_net = self._dns_capable_network(bad)
        res.adguard_dns = res.adguard_blocks + dns_net + res.whitelist

        res.all_cosmetic = sorted(self._cosmetic)
        res.stats = {
            "local_additions": self._local_count,
            # 与 all.txt 的域名规则行数一致 (折叠后): 四类计数之和 == 产物
            # 头部 `! Rules`。hosts/domains 按精确匹配语义另留子域, 故更长。
            "domains_unique": len(res.all_blocks),
            # 去重主机名数 = domains.txt / hosts.txt 的实际行数。徽章与订阅中心
            # 取这个 (用户能对着文件数出来), domains_unique 是折叠后的规则条数,
            # 两者相差的就是被父域覆盖掉的子域 (约 6 万)。
            "domains_lines": len(res.domains),
            "network_unique": len(res.all_network),
            "cosmetic_unique": len(res.all_cosmetic),
            "exceptions_unique": len(res.all_exceptions),
            "whitelist_unique": len(res.whitelist),
            "badfilter_targets": len(bad),
            "dropped": self._stats_dropped,
            "dropped_bare_exceptions": bare_whole_domain,
            "subsumed_type_rules": self._subsumed_count,
            "all_compat_mirrors": len(dom_mirrors) + net_added,
        }
        return res

    def _dns_capable_network(self, bad: Set[str]) -> List[str]:
        """修饰符属于 AGH 支持集, 且 pattern 是主机名掩码或 /regex/ 的网络规则。"""
        out, seen = [], set()
        for key, raw in self._net.items():
            if key in bad or key in seen:
                continue
            pattern, mods = _split_modifiers(raw)
            keys = {m.split("=", 1)[0] for m in split_mod_tokens(mods.lower())}
            if not keys or not keys <= _DNS_NET_MODS:
                continue
            if not _is_dns_pattern(pattern):
                continue
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

def sanitize_url(url: str) -> str:
    """清洗 URL: 自动剥掉首尾空白、反引号、单/双引号 — 防止 Markdown 格式被误写入配置。"""
    if not url:
        return ""
    return url.strip().strip("`").strip("'").strip('"').strip()
         
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
        raw_url = src.get("url", "")
        url = sanitize_url(raw_url)
        if url != raw_url.strip():
            name = src.get("name") or url.rsplit("/", 1)[-1] or url
            print(f"[config warn] 源 '{name}' 的 URL 含多余字符, 已自动清洗: "
                  f"{raw_url!r} → {url!r}", file=sys.stderr)
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"name": src.get("name") or url.rsplit("/", 1)[-1] or url,
                    "url": url})
    return out


def _load_config_data(path: str) -> dict:
    import json

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise RuntimeError("YAML 配置需要 pyyaml")
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_extra_rules(path: str) -> List[str]:
    """读取配置的 extra_rules: 本地补充规则 (上游未覆盖的缺口, 自主可控)。"""
    out = []
    for ln in _load_config_data(path).get("extra_rules", []):
        ln = ln.strip()
        if ln and ln not in out:
            out.append(ln)
    return out


# 订阅只能调用客户端内置的 scriptlet, 不能下发任意 JS
SCRIPTLET_MARKERS = ("##+js(", "#%#//scriptlet(")
# scriptlet 前缀的域名可以宽松一些 (仍会挡掉明显畸形值), 但**不能复用**
# _DOMAIN_RE —— 那会覆盖上面的严格域名校验, 让裸 IP / 通配 / 下划线混进
# hosts 与纯域名产物。
_SCRIPTLET_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9.*_-]*[a-z0-9])?(\.[a-z0-9_-]+)+$", re.I)


def _parens_balanced(s: str) -> bool:
    """括号配对检查, 跳过转义字符、引号字符串与字符类内的括号。

    朴素的 count("(") == count(")") 会把参数里含转义括号的合法正则
    (如 `##+js(acs, /a\\(b/)`) 误判成语法错误。
    """
    depth = 0
    quote = ""
    in_class = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
        i += 1
    return depth == 0 and not quote and not in_class


def load_scriptlet_rules(path: str) -> List[str]:
    """读取自研 scriptlet 文件 (config 的 scriptlet_file)。

    每行必须是 `<域名>` + `##+js(...)` / `#%#//scriptlet(...)`, 只允许调用
    客户端内置 scriptlet。语法错误直接抛 ValueError —— 带病规则会让整份
    订阅被扩展拒绝加载, 必须挡在合并之前。
    """
    if not path or not os.path.exists(path):
        return []
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            ln = raw.strip()
            if not ln or ln.startswith("!") or ln.startswith("#"):
                continue
            marker = next((m for m in SCRIPTLET_MARKERS if m in ln), None)
            if marker is None:
                raise ValueError(f"{path}:{lineno} 不是 scriptlet 规则: {ln!r}")
            domain = ln.split(marker, 1)[0].strip()
            if not _SCRIPTLET_DOMAIN_RE.match(domain):
                raise ValueError(f"{path}:{lineno} 域名不合法: {domain!r}")
            if not _parens_balanced(ln):
                raise ValueError(f"{path}:{lineno} 括号不配对: {ln!r}")
            # 名称允许带引号写法: #%#//scriptlet('name', ...)
            if not re.search(re.escape(marker) + r"\s*['\"]?[a-z0-9-]+", ln, re.I):
                raise ValueError(f"{path}:{lineno} 缺少 scriptlet 名称: {ln!r}")
            if ln not in out:
                out.append(ln)
    return out


def load_scriptlet_file(config_path: str) -> List[str]:
    """按 config.scriptlet_file 读取, 路径相对配置文件所在目录。"""
    data = _load_config_data(config_path)
    rel = str(data.get("scriptlet_file") or "").strip()
    if not rel:
        return []
    base = os.path.dirname(os.path.abspath(config_path))
    return load_scriptlet_rules(os.path.join(base, rel))


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
        f"! Description: 多上游广告过滤规则自动合并 (去重/归并/例外保护) — {kind}",
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


def write_badge_files(outdir: str, stats: dict, now: str,
                      domains_lines: Optional[int] = None) -> Dict[str, str]:
    """生成 output/badge-*.json (shields endpoint) 与 badge-*.svg (README 直用)。

    domains_lines: hosts/domains 的实际行数 (去重后的主机名数)。徽章取自它,
    而不是折叠后的 all.txt 域名规则数 —— 用户订阅的是 domains.txt, 拿徽章
    数字去数文件行数必须对得上。
    """
    import json as _json

    os.makedirs(outdir, exist_ok=True)
    domains = domains_lines if domains_lines is not None \
        else stats.get("domains_unique", 0)
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
    # 内容是 ABP 例外规则 (@@...), 按订阅格式写: ABP 头 + ! 注释
    _write(paths["whitelist"],
           _header_lines(title, now, len(res.whitelist), "DNS 白名单", abp=True)
           + res.whitelist)

    paths["stats"] = os.path.join(outdir, "stats.json")
    import json as _json
    with open(paths["stats"], "w", encoding="utf-8", newline="\n") as f:
        _json.dump(res.stats, f, ensure_ascii=False, indent=2, sort_keys=True)

    paths.update(write_badge_files(outdir, res.stats, now,
                                   domains_lines=len(res.domains)))

    return paths


# ---------------------------------------------------------------------------
# 6. 主流程: run() + CLI
# ---------------------------------------------------------------------------

def run(config_path: str, *, outdir: str, transport=None,
        retries: int = 3, retry_delay: float = 2.0,
        max_workers: int = 6) -> dict:
    """下载全部源 → 解析合并 → 写出输出。返回运行报告 dict。

    下载阶段并行 (ThreadPoolExecutor, 默认 6 worker): 串行时 22 源 × 最坏
    94s/源 ≈ 35 分钟, 会顶爆 CI 的 job timeout (30min) 被取消 (2026-10-05
    schedule run 实测 15min cancelled 即此类); 并行 6 路后最坏 ≈ 7 分钟。
    合并阶段仍串行 (Merger 非线程安全), 按源序保序填充报告。
    """
    import concurrent.futures

    sources = load_sources(config_path)
    texts: Dict[str, str] = {}       # url → 下载文本
    failed = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(fetch_text, src["url"], transport=transport,
                            retries=retries, retry_delay=retry_delay): src
                for src in sources}
        for fut in concurrent.futures.as_completed(futs):
            src = futs[fut]
            try:
                texts[src["url"]] = fut.result()
            except FetchError as e:
                failed.append({"name": src["name"], "error": str(e)})
                print(f"[warn] 源下载失败, 跳过: {src['name']} — {e}",
                      file=sys.stderr)

    if not texts:
        raise FetchError("所有上游源均下载失败, 拒绝生成空列表")

    merger = Merger()
    ok = []
    for src in sources:                          # 按源序合并, 报告保序
        if src["url"] not in texts:
            continue
        n_before = len(merger._dom_imp) + len(merger._net) + \
            len(merger._cosmetic) + len(merger._exc)
        merger.add_lines(texts[src["url"]].splitlines(), source=src["name"])
        n_after = len(merger._dom_imp) + len(merger._net) + \
            len(merger._cosmetic) + len(merger._exc)
        ok.append({"name": src["name"], "rules_added": n_after - n_before})

    # 本地补充规则 (config 的 extra_rules) — 最后合入, 优先级最高
    extras = load_extra_rules(config_path)
    if extras:
        merger.add_lines(extras, source="local-additions")
    # 自研 scriptlet — 优先级也是最高, 放在最后
    scriptlets = load_scriptlet_file(config_path)
    if scriptlets:
        merger.add_lines(scriptlets, source="local-scriptlets")

    res = merger.finalize()
    # 源统计并入 stats.json (订阅中心/徽章动态化数据源)
    res.stats["sources_total"] = len(sources)
    res.stats["sources_ok"] = len(ok)
    res.stats["sources_failed"] = len(failed)
    res.stats["scriptlet_rules"] = sum(
        1 for ln in res.all_cosmetic
        if any(m in ln for m in SCRIPTLET_MARKERS))
    title = str(_load_config_data(config_path).get("title") or "AdFilter Merge")
    paths = write_outputs(res, outdir, title=title)

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
