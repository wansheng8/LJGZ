#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""误杀/漏拦 Issue 自动初筛: 解析表单里的域名, 对照 all.txt 给出结论。

只做初筛与回复, 不自动改规则 —— 加白/补规则仍需人工判断。
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import benchmark  # noqa: E402


def extract_domain(body, title=""):
    """从 GitHub Issue 表单正文里取第一个合法域名。"""
    text = (body or "").replace("\r\n", "\n")
    m = re.search(r"###\s*(?:域名|domain|Domain)\s*\n+\s*([^\s#]+)", text)
    raw = m.group(1) if m else ""
    if not raw:
        m = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", text, re.I)
        raw = m.group(1) if m else ""
    if not raw:
        m = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", title or "", re.I)
        raw = m.group(1) if m else ""
    raw = re.sub(r"^https?://", "", raw.strip(), flags=re.I)
    raw = raw.split("/")[0].split("?")[0].split(":")[0].strip(".")
    return raw.lower() if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", raw, re.I) else ""


def analyze(domain, all_path):
    pure, mod, exc = benchmark.load_rules(all_path)
    if benchmark.is_blocked(domain, pure, exc):
        hit = next((s for s in (".".join(domain.split(".")[i:])
                                for i in range(len(domain.split(".")) - 1))
                    if s in pure), domain)
        return {"verdict": "blocked", "matched": hit,
                "message": f"命中域名级拦截：`||{hit}^`"}
    for i in range(len(domain.split(".")) - 1):
        suffix = ".".join(domain.split(".")[i:])
        if suffix in exc:
            return {"verdict": "excepted", "matched": suffix,
                    "message": f"已被无条件例外放行：`@@||{suffix}^`"}
    lines = []
    with open(all_path, encoding="utf-8", errors="replace") as f:
        want = "||" + domain
        for line in f:
            if line.startswith(want):
                lines.append(line.strip())
                if len(lines) >= 5:
                    break
    if lines:
        return {"verdict": "partial", "matched": domain, "rules": lines,
                "message": "只有部分规则命中（可能仅限特定类型/路径）"}
    return {"verdict": "none", "matched": "", "message": "当前订阅未命中该域名"}


def build_comment(kind, domain, result):
    title = "误杀反馈" if kind == "false-positive" else "漏拦反馈"
    lines = [f"## 自动初筛 · {title}", ""]
    if not domain:
        lines += ["未能从表单中解析出域名，请按模板补填后再试。", ""]
        return "\n".join(lines)
    lines += [f"- 域名：`{domain}`", f"- 结论：{result['message']}"]
    if result.get("rules"):
        lines += ["", "命中的规则：", ""]
        lines += [f"```\n{r}\n```" for r in result["rules"][:5]]
    lines += ["", "---", ""]
    if kind == "false-positive":
        if result["verdict"] == "blocked":
            lines.append("这是域名级拦截，通常来自上游 DNS 列表。确认页面功能受影响后，"
                         "维护者会评估加入 `extra_rules` 白名单。请补充具体页面 URL 与复现步骤。")
        else:
            lines.append("当前订阅没有整域拦截它，误杀可能来自路径规则、元素隐藏或上游规则。"
                         "请提供具体页面与截图，便于定位。")
    else:
        if result["verdict"] == "blocked":
            lines.append("该域名已经在拦截列表里。若广告仍出现，请补充页面 URL、"
                         "广告元素截图和浏览器扩展版本。")
        else:
            lines.append("该域名尚未覆盖。请补充广告/追踪请求的来源 URL（开发者工具 Network 面板），"
                         "维护者会评估并入 `extra_rules`。")
    lines += ["", f"<!-- triage: {kind}:{domain or 'none'}:{result['verdict']} -->"]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="triage_issue")
    ap.add_argument("--body", default=os.environ.get("ISSUE_BODY", ""))
    ap.add_argument("--title", default=os.environ.get("ISSUE_TITLE", ""))
    ap.add_argument("--kind", required=True,
                    choices=["false-positive", "missed-ad"])
    ap.add_argument("--all", default=os.path.join(REPO, "output", "all.txt"))
    ap.add_argument("--comment-out", default="triage-comment.md")
    ap.add_argument("--labels-out", default="triage-labels.txt")
    args = ap.parse_args(argv)

    domain = extract_domain(args.body, args.title)
    result = analyze(domain, args.all) if domain else {"verdict": "none", "matched": ""}
    comment = build_comment(args.kind, domain, result)
    with open(args.comment_out, "w", encoding="utf-8") as f:
        f.write(comment + "\n")

    labels = [args.kind, "needs-triage" if result["verdict"] != "blocked" else "confirmed"]
    with open(args.labels_out, "w", encoding="utf-8") as f:
        f.write("\n".join(labels) + "\n")
    print(json.dumps({"domain": domain, "verdict": result["verdict"], "labels": labels},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
