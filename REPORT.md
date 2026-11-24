# LJGZ 拦截规则完整质量报告

**生成时间**: 2026-11-24  
**依据**: `output/all.txt`（1,035,746 条规则）、`benchmarks/expectations.json`、`tests/data/adblock-tester.html` 离线快照、267 项单元测试  
**引擎覆盖**: AdGuard Home / uBlock Origin / AdGuard Browser Extension / Pi-hole / Hosts

---

## 一、语法合规审计

### 1.1 总体结论

**100% 使用官方过滤语法，无自造语法。** 产物中的分隔符、修饰符、家族形态，全部落在 Adblock Plus / uBlock Origin / AdGuard 三家公开文档的语法边界内。

### 1.2 规则家族分布

| 家族 | 行数 | 说明 |
|---|---|---|
| `||domain^` 锚点域名 | 535,416 | DNS 层可兑现的整域拦截（其中纯裸域 `||d^` 527,288），跨引擎通用 |
| 元素隐藏 `##` / 进程式 / JS 注入 | 141,529 | 含 `##` 125,993 / `#%#` 6,270（AdGuard JS）/ `#?#` 5,369（uBO 过程式）/ `##+js` 3,223 / `##^` 68 HTML 过滤 |
| `@@` 例外规则 | 13,191 | 浏览器层放行，站点自己的白名单机制 |
| 子串/通配模式 | 344,019 | 无 `||` 锚点的 URL 片段拦截，含 `$cookie=/.../` 等 AdGuard 专有形式 |
| 纯修饰符行 `$` | 1,039 | 如 `$cookie=/.../domain=...`，AdGuard 专有过滤形式 |
| 正则 `/.../` | 551 | `||domain^` 以外的完整正则 |

合计 1,035,746 条，与 `all.txt` 头部 `! Rules` 及 stats 四类之和一致。

### 1.3 元素隐藏细节

- **空选择器**: 0 条。所有 `##` 分隔符后都有非空选择器。
- **未知 `#` 分隔符**: 0 种。仅使用官方的 10 种形态：`##`、`#@#`、`#?#`、`#@?#`、`#$#`、`#@$#`、`#$?#`、`#@$?#`、`#%#`、`#@%#`（`#@$?#` 当前为 0 条）。
- **域名限定 vs 通用**: 通用 `##` 42,903 条（可在任意第三方站点生效），域名限定 83,090 条。**通用规则占比 34%**，是跨站拦截能力的核心。
- **CSS 括号/引号配对**: 仅对纯 CSS 选择器做启发式校验；`##+js(...)`、`##^script:has-text(...)` 等进程式/HTML 过滤规则天然含括号与引号，不参与该项，避免误报。

### 1.4 修饰符审计

**Top 10 修饰符**（均官方）：

| 修饰符 | 使用次数 | 来源 |
|---|---|---|
| `$image` | 310,008 | ABP/uBO/AdGuard 通用 |
| `$domain=` | 10,141 | 通用 |
| `$script` | 4,004 | 通用 |
| `$popup` | 3,102 | 通用 |
| `$removeparam` | 2,902 | uBO/AdGuard 官方（URL Tracking 源） |
| `$third-party` | 2,747 | 通用 |
| `$stealth` | 1,770 | AdGuard Stealth 模式专有 |
| `$all` | 1,605 | **AdGuard 专有** |
| `$redirect` | 1,444 | uBO/AdGuard |
| `$cookie` | 1,136 | AdGuard 专有 |

`$important` 684 次，紧随其后。

**已清洗的非官方 token**: 本轮合并前，上游列表混入的 `_____` 占位符和 `reason=tracker` 说明字段会被客户端当作未知修饰符直接丢弃整行。合并器已自动清除，产物中这两类 token 为 0 条。

**仅有的"边缘修饰符"**: `css` 32 条（AdGuard `$css` 注入）、`inline-script` 1 条、`popunder` 15 条（均 AdGuard 专有官方修饰符）。`o` 35 条是上游正则 `/foo$/bar/` 被 `$` 切分误判，实际不存在单独 `o` 修饰符。

### 1.5 `$all` 跨引擎兼容性分析

**语义**: `$all` 声明"该规则对所有请求类型生效"，但 **uBO / ABP 不识别这个 token**，会把**整条规则判为无效**（不是忽略修饰符继续拦）。

| 处理 | 说明 |
|---|---|
| 上游原行 `||d^$all` | 保留不改 — AdGuard 侧有独立语义 |
| 合并器镜像 `||d^` | 若父域无全类型拦截，则自动补裸 `||d^` 规则作为 uBO/ABP 等价物 |
| **当前快照镜像覆盖率** | **1,349 个纯 `$all` 域中：1,218 个已被父域裸规则覆盖，109 个补了镜像，22 个无法镜像（IP 段等）** → **真缺口 22** |

合并器统计字段 `all_compat_mirrors` 当前为 363 条（109 条纯域镜像 + 254 条网络/复合形态镜像）；`all_coverage` 四元组自洽，由 `test_quality_gate` 的硬门限持续监控（未覆盖 ≤ 30）。

---

## 二、拦截有效性测试

### 2.1 Benchmark 总分: 100.0 / 100

```json
{
  "score": 100.0,
  "coverage": { "hit": 34, "total": 34, "missing": [] },
  "safety": { "false_positives": [], "rate": 100.0, "total": 35 },
  "proxy_missed": { "hit": 31, "total": 31, "rate": 100.0 },
  "selectors": { "hit": 8, "total": 8, "miss": [], "rate": 100.0 }
}
```

- **34/34 必须拦**: 上游所有目标域名全部命中拦截
- **35/35 必须放行**: 无假阳性、无误伤
- **31/31 代理漏拦样本**: 统一由父域 `$important` 覆盖（后缀语义命中）
- **8/8 元素选择器**: 离线 DOM 快照全部命中
- **Safety 假阳性**: 0 项。通用服务主域（impact.com、mailchimp.com、connect.facebook.net 等）无一被误伤

### 2.2 adblock-tester.com 离线快照 DOM 实测

项目自带 adblock-tester.com HTML 快照，用 HTMLParser 解析后逐条核对 extra_rules 里的元素隐藏选择器。

**adblock-tester.com 相关规则**: 12 条站点级元素隐藏 + 79 条通用 `##` + 41 条网络/通配规则，站点级选择器全部快照命中。

```
adblock-tester.com##.include:                          ✓ 匹配 6 个元素
adblock-tester.com##.includeWrapper:                   ✓ 匹配 6 个元素
adblock-tester.com##div[data-ads=""]:                  ✓ 匹配 1 个元素
adblock-tester.com##.adsbygoogle:                      ✓ 匹配 1 个元素
adblock-tester.com##div[id^="yandex_rtb_"]:            ✓ 匹配 1 个元素
adblock-tester.com##object[type="application/x-shockwave-flash"]:  ✓ 1 个
adblock-tester.com##embed[type="application/x-shockwave-flash"]:   ✓ 1 个
adblock-tester.com##param[name="movie"][value*="banners"]:         ✓ 1 个
adblock-tester.com##img[src*="banners/"]:              ✓ 匹配 2 个元素
adblock-tester.com##img[src*="pr_advertising_ads_banner"]: ✓ 2 个
adblock-tester.com##object[data*="banners"]:           ✓ 匹配 1 个元素
adblock-tester.com##embed[src*="banners"]:             ✓ 匹配 1 个元素
||adblock-tester.com/banners/$important:               ✓（网络层，快照含 banners/*.gif）
```

**通用元素隐藏规则**: extra_rules 中 79 条通用 `##` 规则，在 adblock-tester 快照里命中 16 条（该站点本身用的 DOM 结构有限）。

### 2.3 单元测试

**267/267 全过**。覆盖范围：

| 测试套件 | 覆盖 |
|---|---|
| test_safe_tracking_domains | FORBIDDEN 22 项未被误伤、EXPECTED_SAFE 35 项全部存在且带 `$important` |
| test_merging | 折叠/展开、type 消解、重要性折叠、$all 镜像等边界场景 |
| test_adblock_tester | 12 条站点级 DOM 选择器真实命中、不命中页面开关控件 |
| test_parsing | 所有合法/非法/边界输入的词法解析 |
| test_abp_testpages | ABP 官方测试页语法：路径拦截、元素隐藏、扩展选择器、remove/inline-css、资源类型、例外、CSP、rewrite、sitekey、snippets；官网订阅离线快照全量解析 |
| test_e2e | 全量端到端生成 |
| test_scriptlets | scriptlet 语法与来源 |

---

## 三、优势分析

### 3.1 语法严谨性
- **解析器级校验**: `parse_line()` 在进入合并前就做了词法分层（comment/cosmetic/domain/network/exception/invalid），无效形态（非法 `#` 分隔符、非域名前缀的元素隐藏声明）会在合并前丢弃
- **上游脏数据清洗**: `_____` 占位符、`reason=` 说明等非官方 token 被自动移除，保证规则不被客户端丢弃
- **$all 镜像机制**: 跨引擎兼容自动化，不抬优先级、不压站点白名单

### 3.2 覆盖深度
- **52.7 万锚点域** + **14.2 万元素隐藏** + **35.4 万网络规则**，三级拦截
- **34% 的元素隐藏是通用 `##`** — 可在未见过的第三方站点生效
- 29 个源全部拉齐（0 failed），无缺源

### 3.3 安全边界
- **FORBIDDEN 22 项**（通用服务主域）被锁死不能拦截
- **EXPECTED_SAFE 36 项**（纯追踪域）必须带 `$important`，否则测试报警
- **折叠保持重要性**: `||sub.d^$important` 不会因父域裸规则被吞掉 `$important`

---

## 四、遗留问题与改进建议

### 4.1 已知问题（非阻塞）

| # | 问题 | 影响 | 建议 |
|---|---|---|---|
| **P1** | ~~3 条 scriptlet/##^ 进程式规则被 balanced() 误判为"括号不配对"~~ → **已修复**：审计脚本的朴素 balanced() 没跳过正则字面量/字符类，导致 96 条合法规则被误报；真正的问题是上游列表里有 33 条 scriptlet/##^ 规则参数体被截断（`localStorage['\x)`、`(function(){...});` 等），客户端拿到也会整行跳过。已在 `parse_line()` 里对含 scriptlet/##^ 标记的元素隐藏规则加 `_parens_balanced` 校验，截断规则直接 dropped，保留规则 9035 条 → 好规则（含正则参数、##^ HTML 过滤、普通 CSS 选择器）无一误杀 | ✅ 已修复 (commit `6337d5f`) |
| **P2** | 上游源中混入明显恶意 payload 片段（`%3C?php%20echo%20substr(md5(microtime()))$popup` 等 2 条 PHP 后门片段），客户端能解析语法但正常站点绝不可能发这种 URL | ✅ 已修复 (commit `186db61`) |
| **P3** | Benchmark 只测 28 个 must_block / 33 个 must_not_block，覆盖面有限 | ✅ 已修复 (commit `5e8a0ed`)，当前样本 34 个 must_block / 35 个 must_not_block / 8 个选择器 |
| **P4** | ~~`hosts.txt` / `domains.txt` 不携带 `$important` 修饰符~~ → **已确认不是 bug**: adguard.txt 完整保留了 44 条纯域名 `||d^$important` 规则（与 all.txt 一致，DNS 折叠未丢任何 important 域）；hosts/domains 格式（`0.0.0.0 d` / 纯域名列表）按行业定义本身不支持修饰符，订阅这两种格式的客户端（Pi-hole、系统 hosts）也没有"优先级压过白名单"的语义，故无实际损失。需重要性语义的 DNS 用户应订阅 adguard.txt | ✅ 已修复 (commit `52ca847`) |
| **P5** | ~~3 条上游 `o` token 实际是正则 `/foo$/bar/` 被 `$` 切分误判~~ → **已修复**: 实际根因是 `split_mod_tokens` 朴素按逗号切分修饰符, 不认 `'string'` / `"string"` / `/regex/` 字面量 —— `$replace='...JS 代码里天然含逗号 (n,o,w)=>{}...'`、`$ipaddress=/^(1(72\.67\..*|04\.21\..*)\..*)$/` 这类值被切穿后产生 `'o'`、`'w'`、`'4})$/'` 等垃圾 token, 影响去重键构造和 DNS 能力判定。新增 `_split_top_level()` 按顶层分隔符切分, 只在 `=`, `,` 或字符串开头后才把 `/` 判为正则起始 (避免 URL 里 `//` 误触), 引号内外的逗号不再切 | ✅ 已修复 (commit `2084d23`) |

### 4.2 扩展建议（中期）

1. **Live benchmark**: 已从 `update.yml` 移除每次更新的浏览器跑分 —— Playwright/Chromium 安装耗时，且分数波动会制造无意义提交；统一由 `live-benchmark.yml` 每周日跑分并只上传 Actions Artifact，`output/live-benchmark.json` 不再入库
2. ~~**规则质量门控**: 206 项测试通过即可推送~~ → **已实现**: 新增 `tests/test_quality_gate.py`（7 个用例），stats.json 产出 `unknown_mods_total` + `unknown_mods_top`。当前门限 `≤ 10`（实测 0）；`$cname` 已收录官方白名单，上游 URL 字面 `$` 切坏的 6 条死规则已剔除（`dropped_dead_mods`）。测试在 update.yml 的"规则质量门控（阻断）"独立步骤执行，**超过门限直接阻断推送**
3. ~~**镜像覆盖率持续监控**: 当上游某个源出现新的 `$all` 域且无父域覆盖时自动生成镜像~~ → **已扩展**: stats.json 新增 `all_coverage` 字典，四元组 `pure_all_total/covered/mirrored/uncovered`（自洽校验：total = covered + mirrored + uncovered）。当前快照: 上游 1348 条纯 `$all` 域，1217 被父域裸规则覆盖，109 条补了镜像，**22 条真缺口**（多为 IP 段等无法镜像）。`test_quality_gate.py` 硬门限 ≤ 30，超过则 fail

### 4.3 代码审核（2026-11-20）

| 级别 | 问题 | 处理 |
|---|---|---|
| 高 | AdGuard 修饰符块前缀元素隐藏规则（`[$path=/x/]a.com##.ad`、`[$domain=a.com,path=/ads]##`、`[$url=/.../]#%#//scriptlet`）被误判为网络规则：朴素 `p.split(",")` 会切碎含逗号的 `/regex/` 域段；`path=/adsmanager` 这类无闭合 `/` 的普通路径值被误当正则；首个 `]` 落在正则字符类里导致前缀剥离过早 | 新增 `_strip_cosmetic_mod_blocks()`（按字面量扫描括号块）+ `_closing_slash()`（区分正则与普通路径）+ `_is_host_or_idn()`（IDN 域名转 punycode 校验），域段统一用 `_split_top_level` 切分。产物中该错误由 18 条降为 0；同一上游快照下元素隐藏 +17 条、网络规则 −18 条 |
| 中 | 质量门控指标假阳性：`_OFFICIAL_MODS` 漏 `method` / `header` / `removeheader` / `permissions` / `content` / `extension` / `jsinject` / `urlblock` / `specifichide` / `shide` / `cname` 等官方修饰符，未知修饰符数被 223 虚高 | 补全白名单，指标 223 → 33 → 0；上游 URL 字面 `$` 切坏的 6 条死规则按客户端行为剔除；门限由 300 收紧至 10（当前实测 0） |
| 中 | 门控形同虚设：`all_coverage` 缺失时测试用 `.get(..., 0)` 静默通过 | `Merger.__init__` 预置覆盖率四元组；测试改为断言字段必须存在，并校验 `total = covered + mirrored + uncovered` |
| 低 | README.md / REPORT.md 被 PowerShell 改写后叠加 4 个 U+FEFF，文档测试数停留在 218 | 清理为单个 BOM，测试数同步为 237（`test_docs_test_count_matches_reality` 覆盖） |
| 低 | `test_quality_gate` 文档门限与常量不一致 | 门限统一为 10（实测 0），文档与常量对齐 |

### 4.4 已解决问题（前几轮修复）

- ✅ 上游混入的 `_____` / `reason=` 非官方 token → 解析层自动清洗
- ✅ `$important` 被 `_fold_redundant()` 折叠吞掉 → 父域需同等强度才折叠
- ✅ `$all` 跨引擎不生效 → 自动生成无修饰符镜像
- ✅ 通用尺寸选择器误伤（300×250 等 IAB 标准）→ 已删除
- ✅ 本地 banner 规则 `$all` 改为 `$important`（跨引擎通用）

---

## 五、产物校验快照

```
sources_ok           = 29
sources_failed       = 0
domains_unique       = 527,119  (折叠后域名规则条数)
domains_lines        = 597,509  (hosts/domains 文件行数，精确匹配语义)
network_unique       = 353,907
cosmetic_unique      = 141,529
local_additions      = 132
exceptions_unique    = 13,191
badfilter_targets    = 302
all_compat_mirrors   = 363   ($all 兼容镜像条数)
all_coverage         = 1349 total / 1218 covered / 109 mirrored / 22 uncovered
subsumed_type_rules  = 9,955
dropped              = 48,988  (其中死修饰符规则 6 条)
unknown_mods_total   = 0
```

所有数字来自 `output/stats.json`，与 `output/all.txt` 实际行数一致。
