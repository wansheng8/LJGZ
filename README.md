# AdFilter Merge — 广告过滤规则合并引擎

一个将众多上游广告过滤器列表**自动收集、转化、去重、合并**的 Python 程序，
输出可被 Adblock Plus / uBlock Origin / AdGuard / AdGuard Home / Pi-hole 等
常见拦截软件直接订阅的规则文件。全部时间戳使用**北京时间 (UTC+8)**。

> 依据《广告拦截软件过滤规则语法大全.md》实现（ABP / uBO / AdGuard / AdGuard Home / Pi-hole 官方语法）。

## 输出文件

| 文件 | 用途 | 格式 |
|---|---|---|
| `output/all.txt` | 浏览器扩展订阅 (ABP/uBO/AdGuard) | 全格式: `\|\|域名^` + 网络规则 + 元素隐藏 + `@@` 例外 |
| `output/adguard.txt` | AdGuard Home / AdGuard DNS 订阅 | `\|\|域名^` (子域折叠) + `$dnsrewrite` 等 DNS 规则 + DNS 白名单 |
| `output/hosts.txt` | Pi-hole / 任意 hosts 方案 | `0.0.0.0 域名` |
| `output/domains.txt` | 纯域名场景 (Cloudflare Gateway 等) | 一行一域 |
| `output/whitelist.txt` | DNS 白名单 (订阅为例外) | `@@\|\|域名^` |
| `output/stats.json` | 本次运行统计 | JSON |

订阅地址（已部署到 https://github.com/wansheng8/LJGZ）：

```
https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/all.txt
https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/adguard.txt
https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/hosts.txt
https://raw.githubusercontent.com/wansheng8/LJGZ/main/output/domains.txt
```

## 本地使用

```bash
# 零第三方依赖 (纯 stdlib)。如用 YAML 配置才需要: pip install pyyaml
python merge_filters.py --test                 # 内置冒烟自检
python -m unittest discover -s tests           # 完整测试套件 (67 项)
python merge_filters.py                        # 按 config.json 下载+合并 → ./output/
python merge_filters.py --outdir D:/rules      # 自定义输出路径
```

## DIY 定制（添加上游列表）

编辑 `config.json`：

```json
{
  "sources": [
    { "name": "我的列表", "url": "https://example.com/filter.txt", "enabled": true }
  ]
}
```

- 任何兼容 **Adblock Plus 语法** 的列表均可（`||domain^`、`$script`、`##元素隐藏`、`@@例外`、
  hosts 式 `0.0.0.0 domain`、Pi-hole 正则 `(^|\.)ad\.com$`、纯域名列表——全部自动识别）。
- `"enabled": false` 可临时停用某源；重复 URL 自动去重。
- 开发文案中列举的规则类别（URL/资源/域名/CSS选择器/脚本注入/隐私/Cookie/白名单/关键
  字/正则/网络/字体样式/重定向/反指纹/欺诈/钓鱼/滥用/挖矿/垃圾邮件/僵尸网络/地理追踪/音视
  频广告/社交插件/点击劫持/弹窗/下载劫持等）都是这些语法的组合，由对应上游列表提供，本程序
  原样保留进 `all.txt`。

## 合并/去重逻辑

1. **精确去重** — 文本完全相同的行只保留一条。
2. **语义等价归并** — `||example.com^` ≡ `example.com` ≡ `0.0.0.0 example.com` ≡
   `*.example.com` ≡ Pi-hole `(^|\.)example\.com$`，同一域名只输出一条（大小写/尾点归一）。
3. **修饰符规范化** — 修饰符顺序不同视为同一规则（`$script,image` ≡ `$image,script`）。
4. **badfilter** — `||ads.com^$badfilter` 使语义相同的 `||ads.com^` 失效，全输出剔除。
5. **例外保护** — `@@` DNS 相关例外把该域名从 DNS 输出剔除并进白名单；带 `$important`
   的拦截可压过普通例外（与 AdGuard 仲裁规则一致）；仅浏览器侧的例外（`$elemhide` 等）
   不影响 DNS 输出。
6. **子域折叠**（仅 adguard.txt）— 父域已拦截时折叠 `||sub.parent.com^`；hosts/domains
   为精确匹配语义，保留子域。
7. **DNS 能力筛选** — `||ads.com^$script` 等浏览器专用规则**不会**混入 DNS/hosts 输出；
   `$dnsrewrite` / `$dnstype` 等 AdGuard Home 支持的规则保留在 adguard.txt。
8. **本机条目清除** — `localhost`、`*.arpa`、本机 IP 段不进任何输出。

## 部署到 GitHub（每天自动更新，北京时间）

1. 在 GitHub 新建一个 **Public** 仓库（Private 仓库 raw 订阅地址不可用）。
2. 把本目录全部内容推上去：

   ```bash
   cd 拦截广告
   git init -b main
   git add .
   git commit -m "init: 广告过滤规则合并引擎"
   git remote add origin https://github.com/<user>/<repo>.git
   git push -u origin main
   ```

3. 推送后 `.github/workflows/update.yml` 自动生效：
   - 触发：每天**北京时间 08:00 与 20:00**、手动 (`workflow_dispatch`)、推送代码。
   - 流程：先跑完整测试 → 下载/合并 → `output/` 无变化则跳过提交，有变化则自动 commit+push。
4. 到仓库 **Actions** 页确认第一次运行成功，然后用上面的 raw 链接订阅。

> 时间对接：workflow 设 `TZ: Asia/Shanghai`，cron 用 UTC 表达的固定双时点 + 输出文件头
> 的 `! Last Modified: ... (北京时间 UTC+8)`，规则头部时间即可与北京时间一致。

## 项目结构

```
merge_filters.py        # 全部核心: 解析 → 合并 → 下载 → 输出 → CLI (零依赖, 单文件)
config.json             # 上游列表配置 (DIY 入口)
tests/                  # 67 项单元/集成测试 (unittest, 无网络)
  test_parsing.py       #   词法分类: 各家语法逐条覆盖
  test_merging.py       #   去重/例外/badfilter/子域折叠
  test_fetch_io.py      #   重试/配置加载/输出文件/北京时间头部
  test_e2e.py           #   端到端 (假下载器注入)
.github/workflows/update.yml  # GitHub Actions 每日定时更新
```

## 致谢与许可

上游列表版权归各自作者，许可证以各列表头部声明为准（EasyList 系为 GPL-3+ /
CC-BY-SA 类，AdGuard SDNS 为 LGPL-2.1 等）。再分发 output/ 时请保留来源致谢。
