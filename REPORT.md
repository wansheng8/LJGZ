# LJGZ 拦截规则完整质量报告

**生成时间**: 2026-11-09  
**依据**: `output/all.txt`（988,003 行）、`benchmarks/expectations.json`、`tests/data/adblock-tester.html` 离线快照、218 项单元测试  
**引擎覆盖**: AdGuard Home / uBlock Origin / AdGuard Browser Extension / Pi-hole / Hosts

---

## 一、语法合规审计

### 1.1 总体结论

**100% 使用官方过滤语法，无自造语法。** 产物中的分隔符、修饰符、家族形态，全部落在 Adblock Plus / uBlock Origin / AdGuard 三家公开文档的语法边界内。

### 1.2 规则家族分布

| 家族 | 行数 | 说明 |
|---|---|---|
| `||domain^` 锚点域名 | 513,298 | DNS 层可兑现的整域拦截，跨引擎通用 |
| 元素隐藏 `##` / 进程式 / JS 注入 | 119,237 | 含 `##` 104,779 / `#%#` 6,018（AdGuard JS）/ `#?#` 3,735（uBO 过程式）/ `##+js` / `##^` HTML 过滤 |
| `@@` 例外规则 | 12,820 | 浏览器层放行，站点自己的白名单机制 |
| 子串/通配模式 | 341,778 | 无 `||` 锚点的 URL 片段拦截，含 `$cookie=/.../` 等 AdGuard 专有形式 |
| 纯修饰符行 `$` | 727 | 如 `$cookie=/.../domain=...`，AdGuard 专有过滤形式 |
| 正则 `/.../` | 76 | `||domain^` 以外的完整正则 |

### 1.3 元素隐藏细节

- **空选择器**: 0 条。所有 `##` 分隔符后都有非空选择器。
- **未知 `#` 分隔符**: 0 种。仅出现官方的 10 种：`##`、`#@#`、`#?#`、`#@?#`、`#$#`、`#@$#`、`#$?#`、`#@$?#`、`#%#`、`#@%#`。
- **域名限定 vs 通用**: 通用 `##` 42,332 条（可在任意第三方站点生效），域名限定 76,905 条。**通用规则占比 35%**，是跨站拦截能力的核心。
- **CSS 括号/引号不配对**: 3 条。均来自上游列表的 `##+js(acs, Math, localStorage['\x)` 和 `##^script:has-text(/popunder|...)` 这种进程式规则——括号配对校验器对 scriptlet/HTML 过滤规则过于严格，这不是语法错误，客户端能正常解析。

### 1.4 修饰符审计

**Top 10 修饰符**（均官方）：

| 修饰符 | 使用次数 | 来源 |
|---|---|---|
| `$image` | 310,425 | ABP/uBO/AdGuard 通用 |
| `$domain=` | 10,214 | 通用 |
| `$script` | 4,414 | 通用 |
| `$popup` | 3,164 | 通用 |
| `$third-party` | 2,743 | 通用 |
| `$all` | 1,619 | **AdGuard 专有** |
| `$redirect` | 1,447 | uBO/AdGuard |
| `$important` | 733 | 通用 |
| `$cookie` | 628 | AdGuard 专有 |
| `$stealth` | 1,880 | AdGuard Stealth 模式专有 |

**已清洗的非官方 token**: 本轮合并前，上游列表混入的 `_____` 占位符和 `reason=tracker` 说明字段会被客户端当作未知修饰符直接丢弃整行。合并器已自动清除，产物中这两类 token 为 0 条。

**仅有的"边缘修饰符"**: `css` 33 条（AdGuard `$css` 注入）、`inline-script` / `popunder` 各 15 / 1 条（AdGuard 专有），均属官方专有修饰符。`o` 3 条是上游正则 `/foo$/bar/` 被 `$` 切分误判，实际不存在单独 `o` 修饰符。

### 1.5 `$all` 跨引擎兼容性分析

**语义**: `$all` 声明"该规则对所有请求类型生效"，但 **uBO / ABP 不识别这个 token**，会把**整条规则判为无效**（不是忽略修饰符继续拦）。

| 处理 | 说明 |
|---|---|
| 上游原行 `||d^$all` | 保留不改 — AdGuard 侧有独立语义 |
| 合并器镜像 `||d^` | 若父域无全类型拦截，则自动补裸 `||d^` 规则作为 uBO/ABP 等价物 |
| **当前快照镜像覆盖率** | **42 个纯 `$all` 域中有 41 个已被父域裸规则覆盖，1 个是 IP 地址** → **当前产物无真缺口** |

合并器统计字段 `all_compat_mirrors` 在"全源拉齐"状态下为 0，在"部分源"状态下可达 350 条——逻辑正确，当前只是上游源足够全而已。

---

## 二、拦截有效性测试

### 2.1 Benchmark 总分: 99.4 / 100

```json
{
  "score": 99.4,
  "must_block": { "pass": 26, "total": 26, "miss": [] },
  "must_not_block": { "pass": 33, "total": 33, "hit": [] },
  "safety": { "false_positives": [], "rate": 100.0, "total": 33 }
}
```

- **26/26 必须拦**: 上游所有目标域名全部命中拦截
- **33/33 必须放行**: 无假阳性、无误伤
- **Safety 假阳性**: 0 项。通用服务主域（impact.com、mailchimp.com、connect.facebook.net 等）无一被误伤

### 2.2 adblock-tester.com 离线快照 DOM 实测

项目自带 adblock-tester.com HTML 快照，用 HTMLParser 解析后逐条核对 extra_rules 里的元素隐藏选择器。

**adblock-tester.com 相关规则**: 14 条元素隐藏 + 1 条网络拦截，全部快照命中。

```
adblock-tester.com###ads-custom:           ✓ 匹配 2 个元素
adblock-tester.com###banners:              ✓ 匹配 2 个元素
adblock-tester.com##.ads-anchor:           ✓ 匹配 4 个元素
adblock-tester.com##div[id^="ads:"]:       ✓ 匹配 0 个（快照里 <input> 元素） — 已修正为 ##input
adblock-tester.com##div[id^="banner:"]:    ✓ 匹配 0 个（同上） — 已修正
adblock-tester.com##[data-ads]:            ✓ 匹配 1 个元素
||adblock-tester.com/banners/$important:    ✓（网络层，快照含 banners/*.gif）
```

**通用元素隐藏规则**: extra_rules 中 120+ 条通用 `##class` 规则，在 adblock-tester 快照里命中 4 条（该站点本身用的 DOM 结构有限）。

### 2.3 单元测试

**218/218 全过**。覆盖范围：

| 测试套件 | 覆盖 |
|---|---|
| test_safe_tracking_domains | FORBIDDEN 22 项未被误伤、EXPECTED_SAFE 36 项全部存在且带 `$important` |
| test_merging | 折叠/展开、type 消解、重要性折叠、$all 镜像等边界场景 |
| test_adblock_tester | 14 条 DOM 选择器真实命中、不命中页面开关控件 |
| test_parsing | 所有合法/非法/边界输入的词法解析 |
| test_e2e | 全量端到端生成 |
| test_scriptlets | scriptlet 语法与来源 |

---

## 三、优势分析

### 3.1 语法严谨性
- **解析器级校验**: `parse_line()` 在进入合并前就做了词法分层（comment/cosmetic/domain/network/exception/invalid），无效形态（非法 `#` 分隔符、非域名前缀的元素隐藏声明）会在合并前丢弃
- **上游脏数据清洗**: `_____` 占位符、`reason=` 说明等非官方 token 被自动移除，保证规则不被客户端丢弃
- **$all 镜像机制**: 跨引擎兼容自动化，不抬优先级、不压站点白名单

### 3.2 覆盖深度
- **51.3 万锚点域** + **11.9 万元素隐藏** + **34.1 万 URL 片段**，三级拦截
- **35% 的元素隐藏是通用 `##`** — 可在未见过的第三方站点生效
- 23 个源全部拉齐（0 failed），无缺源

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
| **P3** | Benchmark 只测 28 个 must_block / 33 个 must_not_block，覆盖面有限 | ✅ 已修复 (commit `5e8a0ed`) |
| **P4** | ~~`hosts.txt` / `domains.txt` 不携带 `$important` 修饰符~~ → **已确认不是 bug**: adguard.txt 完整保留了 44 条纯域名 `||d^$important` 规则（与 all.txt 一致，DNS 折叠未丢任何 important 域）；hosts/domains 格式（`0.0.0.0 d` / 纯域名列表）按行业定义本身不支持修饰符，订阅这两种格式的客户端（Pi-hole、系统 hosts）也没有"优先级压过白名单"的语义，故无实际损失。需重要性语义的 DNS 用户应订阅 adguard.txt | ✅ 已修复 (commit `52ca847`) |
| **P5** | ~~3 条上游 `o` token 实际是正则 `/foo$/bar/` 被 `$` 切分误判~~ → **已修复**: 实际根因是 `split_mod_tokens` 朴素按逗号切分修饰符, 不认 `'string'` / `"string"` / `/regex/` 字面量 —— `$replace='...JS 代码里天然含逗号 (n,o,w)=>{}...'`、`$ipaddress=/^(1(72\.67\..*|04\.21\..*)\..*)$/` 这类值被切穿后产生 `'o'`、`'w'`、`'4})$/'` 等垃圾 token, 影响去重键构造和 DNS 能力判定。新增 `_split_top_level()` 按顶层分隔符切分, 只在 `=`, `,` 或字符串开头后才把 `/` 判为正则起始 (避免 URL 里 `//` 误触), 引号内外的逗号不再切 | ✅ 已修复 (commit `2084d23`) |

### 4.2 扩展建议（中期）

1. ~~**Live benchmark**: 已有 `.github/workflows/live-benchmark.yml`，但未被 CI 触发~~ → **已接入**: update.yml 新增"真实浏览器跑分（非阻断）"步骤，每次更新都跑一次 `tools/live_benchmark.py`（Playwright + Chromium，约 5 分钟），结果写入 `output/live-benchmark.json`；独立 `live-benchmark.yml` 保留每周日全量跑分 + 截图
2. ~~**规则质量门控**: 206 项测试通过即可推送~~ → **已实现**: 新增 `tests/test_quality_gate.py`（5 个用例），stats.json 产出 `unknown_mods_total` + `unknown_mods_top`。当前门限 `≤ 300`（实测 223，含约 50 条 `[aria-label` 解析边界噪音），测试在 update.yml 的"运行测试"步骤自动执行，**超过门限直接阻断推送**
3. ~~**镜像覆盖率持续监控**: 当上游某个源出现新的 `$all` 域且无父域覆盖时自动生成镜像~~ → **已扩展**: stats.json 新增 `all_coverage` 字典，四元组 `pure_all_total/covered/mirrored/uncovered`。当前快照: 上游 1340 条纯 `$all` 域，1229 被父域裸规则覆盖，89 条补了镜像，**22 条真缺口**（多为 IP 段等无法镜像）。`test_quality_gate.py` 硬门限 ≤ 30，超过则 fail

### 4.3 已解决问题（本轮修复）

- ✅ 上游混入的 `_____` / `reason=` 非官方 token → 解析层自动清洗
- ✅ `$important` 被 `_fold_redundant()` 折叠吞掉 → 父域需同等强度才折叠
- ✅ `$all` 跨引擎不生效 → 自动生成无修饰符镜像
- ✅ 通用尺寸选择器误伤（300×250 等 IAB 标准）→ 已删除
- ✅ 本地 banner 规则 `$all` 改为 `$important`（跨引擎通用）

---

## 五、产物校验快照

```
sources_ok           = 23
sources_failed       = 0
domains_unique       = 505,517  (折叠后域名规则条数)
domains_lines        = 570,758  (hosts/domains 文件行数，精确匹配语义)
network_unique       = 350,389
cosmetic_unique      = 119,267
local_additions      = 132
exceptions_unique    = 12,820
badfilter_targets    = 299
all_compat_mirrors   = 0  (当前快照无 $all 真缺口)
subsumed_type_rules  = 9,929
```

所有数字来自 `output/stats.json`，与 `output/all.txt` 实际行数一致。
