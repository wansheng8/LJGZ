<div align="center">

<img src="docs/logo.svg" width="96" alt="LJGZ Logo"/>

# LJGZ · 广告过滤规则聚合

**一键订阅 · 每日北京时间自动更新 · 兼容主流拦截软件**

EasyList 系 / uBO 官方 / AdGuard 官方 / Fanboy / OISD / hagezi / anti-AD / CJX
StevenBlack / URLhaus / Blackbook —— **22 个上游**自动收集 · 语义去重 · 合并输出
涵盖：广告 · 隐私追踪 · 恶意软件 · 钓鱼网站 · 挖矿 · 烦恼元素 · 中文专项

<img src="https://wansheng8.github.io/LJGZ/badge-rules.svg" alt="规则总数"/>
<img src="https://wansheng8.github.io/LJGZ/badge-domains.svg" alt="拦截域名"/>
<img src="https://wansheng8.github.io/LJGZ/badge-updated.svg" alt="更新时间"/>
<img src="https://wansheng8.github.io/LJGZ/badge-cadence.svg" alt="更新节奏"/>
<br/>
<img src="https://wansheng8.github.io/LJGZ/badge-compat.svg" alt="兼容"/>
<img src="https://github.com/wansheng8/LJGZ/actions/workflows/update.yml/badge.svg" alt="工作流"/>

**🌐 [在线订阅中心](https://wansheng8.github.io/LJGZ/)** — 点开即复制，无需看文档

</div>

---

## 📥 一键订阅

| 场景 | 首选 (GitHub Pages) | 备选 (jsDelivr) | 备用 (raw) |
|---|---|---|---|
| 🧩 **浏览器扩展**<br><sub>uBlock Origin · AdGuard · Adblock Plus</sub> | [**all.txt**](https://wansheng8.github.io/LJGZ/all.txt) | [分卷1](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/all-part-01.txt) + [分卷2](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/all-part-02.txt) † | [all.txt](https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/all.txt) |
| 🏠 **AdGuard Home**<br><sub>AdGuard Home · AdGuard DNS</sub> | [adguard.txt](https://wansheng8.github.io/LJGZ/adguard.txt) | [adguard.txt](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/adguard.txt) | [adguard.txt](https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/adguard.txt) |
| 🕳 **Pi-hole / hosts**<br><sub>Pi-hole · SwitchHosts · 路由器</sub> | [hosts.txt](https://wansheng8.github.io/LJGZ/hosts.txt) | [hosts.txt](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/hosts.txt) | [hosts.txt](https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/hosts.txt) |
| 📃 **纯域名列表**<br><sub>Cloudflare Gateway · NextDNS</sub> | [domains.txt](https://wansheng8.github.io/LJGZ/domains.txt) | [domains.txt](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/domains.txt) | [domains.txt](https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/domains.txt) |
| ✅ **DNS 白名单**<br><sub>误拦截放行 · 例外列表</sub> | [whitelist.txt](https://wansheng8.github.io/LJGZ/whitelist.txt) | [whitelist.txt](https://cdn.jsdelivr.net/gh/wansheng8/LJGZ@main/output/whitelist.txt) | [whitelist.txt](https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/whitelist.txt) |

> **⚠️ 请优先用 GitHub Pages 那一列。** jsDelivr 有 20MB 单文件上限，分卷卡在 18MB 边缘，实测出现过 `Failed to fetch ... from GitHub.`（返回 48 字节错误文本）。若浏览器扩展报"下载失败"或规则数明显偏少，先删掉 jsDelivr 分卷、只留 Pages 的 `all.txt`。
>
> † **jsDelivr 单文件上限 20MB**，`all.txt` 完整版 22MB 超限，只能用分卷 1 + 分卷 2（两个都加，效果 = 完整版）。
> 💡 浏览器扩展用户：uBO → 设置 → 过滤器列表 → 导入；AdGuard → 设置 → 内容拦截 → 添加。

## ⚙️ 引擎特性

- **全语法识别** — ABP / uBO / AdGuard 网络规则、`##` 元素隐藏、`##+js()` 脚本注入、`@@` 例外、`$dnsrewrite`、hosts 式、Pi-hole 正则 `(^|\.)ad\.com$`、纯域名，一网打尽
- **语义去重合并** — `||d^` ≡ `d` ≡ `0.0.0.0 d` ≡ `*.d` ≡ Pi-hole 正则归并为一条；修饰符顺序无关；大小写/FQDN 尾点归一
- **智能仲裁** — `$badfilter` 失效规则、`@@` 例外保护 DNS 输出、`$important` 压过普通例外（与 AdGuard 语义一致）、子域折叠
- **格式分诊** — `||ads.com^$script` 等浏览器专用规则不污染 DNS/hosts 输出；localhost/`.arpa`/本机 IP 自动清除
- **零依赖** — 纯 stdlib 单文件，`python merge_filters.py` 即跑

## 🔧 DIY 定制

```bash
git clone https://github.com/wansheng8/LJGZ.git
cd LJGZ
python merge_filters.py --test              # 冒烟自检
python -m unittest discover -s tests         # 145 项测试
python merge_filters.py                      # 下载合并 → ./output/
```

编辑 `config.json` 增删上游（任何 ABP 兼容列表均可）：

```json
{ "name": "我的列表", "url": "https://example.com/filter.txt", "enabled": true }
```

Fork 后 `.github/workflows/update.yml` 自动生效，产出你自己的订阅。

<details>
<summary><b>📁 合并/去重算法细节</b></summary>

1. **精确去重** — 文本相同的行只保留一条
2. **语义等价归并** — 同一域名的 5 种写法归并为一条
3. **修饰符规范化** — `$script,image` ≡ `$image,script`
4. **badfilter** — 命中 `$badfilter` 的规则从全部输出剔除
5. **例外保护** — DNS 相关 `@@` 例外：域名移出 DNS 输出、进白名单；`$important` 拦截可压过普通例外
6. **子域折叠**（仅 adguard.txt）— 父域已拦截时折叠子域
7. **DNS 能力筛选** — AdGuard Home 不支持的修饰符规则不进 DNS 输出
8. **本机条目清除** — localhost、`*.arpa`、广播地址全部剔除

</details>

<details>
<summary><b>🚀 部署说明（每日北京时间 08:00 / 20:00 自动更新）</b></summary>

- 工作流：`.github/workflows/update.yml`（cron `0 0,12 * * *` UTC = 北京 08:00/20:00，`TZ=Asia/Shanghai`）
- 流程：145 项测试 → 下载 22 源 → 合并 → 无变化跳过提交，有变化自动 commit + push → 部署 Pages
- **GitHub Pages**：`wansheng8.github.io/LJGZ` 托管订阅中心 + 全部订阅文件（Settings → Pages → Source 已设为 GitHub Actions）
- 输出头部含 `! Last Modified: ... (北京时间 UTC+8)` 与 `! Expires: 12 hours`
- 徽章 SVG 由引擎每次运行自动重新生成（`output/badge-*.svg`），数字始终与最新一次合并一致

</details>

<details>
<summary><b>🗺 项目结构</b></summary>

```
merge_filters.py               # 核心引擎: 解析 → 合并 → 下载 → 输出 → 徽章 → CLI
config.json                    # 上游列表配置 (DIY 入口)
docs/index.html                # 在线订阅中心 (GitHub Pages)
docs/logo.svg                  # Logo
tests/  (145 项, 无网络)         # 词法分类 / 合并去重 / 下载重试 / 徽章 / 端到端 / adblock-tester 回归 / 追踪域安全边界 / 裸例外仲裁
.github/workflows/update.yml   # 每日更新 + Pages 部署
output/                        # 订阅文件 (CI 自动重新生成)
```

</details>

---

<div align="center">

**⭐ 觉得有用请给个 Star！**

上游列表版权归各作者 · 许可证以各列表头部声明为准（EasyList GPL-3+/CC-BY-SA 类，AdGuard SDNS LGPL-2.1 等）

</div>
