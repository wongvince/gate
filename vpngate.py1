#!/usr/bin/env python3
"""
通用代理抓取与筛选流水线 (ProxyScrape JSON 版)
==============================================
流程:
  1. 从 ProxyScrape JSON API 获取代理列表
  2. 转换为通用节点格式
  3. 按 uptime / latency 过滤
  4. 去重、排序、截断
  5. 生成 public/data.json + public/index.html + public/nodes.txt
"""

import json
import html
import os
import sys
import time
from datetime import datetime, timezone

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置（可通过环境变量覆盖）
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

PROXIES_URL = os.environ.get(
    "PROXIES_URL",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json",
)
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))

# 输出上限（按 uptime 降序 / latency 升序截断），0 表示不限制
MAX_NODES = int(os.environ.get("MAX_NODES", "1000"))

# 质量门槛
MIN_UPTIME = float(os.environ.get("MIN_UPTIME", "30"))          # 百分比
MAX_LATENCY_MS = float(os.environ.get("MAX_LATENCY_MS", "2000"))  # 毫秒

# 允许的协议（逗号分隔），留空表示全部
ALLOWED_PROTOCOLS = [
    p.strip().lower()
    for p in os.environ.get("ALLOWED_PROTOCOLS", "http,socks5,socks4").split(",")
    if p.strip()
]

# 只保留指定国家（逗号分隔 ISO 代码，如 JP,US,HK），留空表示全部
ALLOWED_COUNTRIES = [
    c.strip().upper()
    for c in os.environ.get("ALLOWED_COUNTRIES", "").split(",")
    if c.strip()
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "LV": "拉脱维亚",
    "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克", "SI": "斯洛文尼亚",
    "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚", "MD": "摩尔多瓦",
    "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 抓取
# ---------------------------------------------------------------------------
def fetch_proxies():
    log("PROXYSCRAPE", f"请求 JSON API: {PROXIES_URL}")
    try:
        resp = requests.get(
            PROXIES_URL,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (gate-checker)"},
        )
        resp.raise_for_status()

        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(
                f"JSON 解析失败: {exc}; content-type={resp.headers.get('Content-Type')}; "
                f"body={resp.text[:200]!r}"
            )

        if not isinstance(data, list):
            raise RuntimeError(f"JSON 顶层不是数组，实际是 {type(data).__name__}")
        if not data:
            raise RuntimeError("JSON API 返回空数组")

        log("PROXYSCRAPE", f"获取到 {len(data)} 条原始代理")
        return data
    except Exception as exc:
        die(f"ProxyScrape JSON API 获取失败：{type(exc).__name__}: {exc}")

# ---------------------------------------------------------------------------
# 转换
# ---------------------------------------------------------------------------
def to_proxy_nodes(raw_proxies):
    nodes = []
    skipped_protocol = 0
    skipped_country = 0
    skipped_invalid = 0

    for p in raw_proxies:
        if not isinstance(p, dict):
            skipped_invalid += 1
            continue

        ip = str(p.get("ip", "")).strip()
        protocol = str(p.get("protocol", "")).strip().lower()
        country_code = str(p.get("country_code", "")).strip().upper()

        try:
            port = int(p.get("port", 0))
        except (ValueError, TypeError):
            skipped_invalid += 1
            continue

        if not ip or not protocol or not (1 <= port <= 65535):
            skipped_invalid += 1
            continue

        if ALLOWED_PROTOCOLS and protocol not in ALLOWED_PROTOCOLS:
            skipped_protocol += 1
            continue

        if ALLOWED_COUNTRIES and country_code not in ALLOWED_COUNTRIES:
            skipped_country += 1
            continue

        try:
            uptime = float(p.get("uptime_percent") or 0)
        except (ValueError, TypeError):
            uptime = 0.0

        try:
            latency = float(p.get("latency_ms") or 99999)
        except (ValueError, TypeError):
            latency = 99999.0

        nodes.append({
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "link": f"{protocol}://{ip}:{port}",
            "country": str(p.get("country", "")).strip(),
            "country_code": country_code,
            "city": str(p.get("city", "")).strip(),
            "anonymity": str(p.get("anonymity", "")).strip(),
            "uptime_percent": uptime,
            "latency_ms": latency,
            "asn": str(p.get("asn", "")).strip(),
            "isp": str(p.get("isp", "")).strip(),
        })

    log(
        "CONVERT",
        f"转换完成: 有效 {len(nodes)}, 跳过协议不匹配 {skipped_protocol}, "
        f"跳过国家不匹配 {skipped_country}, 跳过格式异常 {skipped_invalid}",
    )
    return nodes

# ---------------------------------------------------------------------------
# 过滤 / 去重 / 排序
# ---------------------------------------------------------------------------
def filter_nodes(nodes):
    before = len(nodes)
    filtered = [
        n for n in nodes
        if n["uptime_percent"] >= MIN_UPTIME and n["latency_ms"] <= MAX_LATENCY_MS
    ]
    log(
        "FILTER",
        f"质量过滤 (uptime >= {MIN_UPTIME}%, latency <= {MAX_LATENCY_MS}ms): "
        f"{before} -> {len(filtered)}",
    )
    return filtered

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["protocol"], n["ip"], n["port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    log("DEDUPE", f"去重后: {len(out)}")
    return out

def rank_and_truncate(nodes):
    ranked = sorted(
        nodes,
        key=lambda n: (-n["uptime_percent"], n["latency_ms"]),
    )
    if MAX_NODES > 0 and len(ranked) > MAX_NODES:
        ranked = ranked[:MAX_NODES]
        log("RANK", f"按 uptime/latency 排序后截取前 {MAX_NODES} 个")
    return ranked

# ---------------------------------------------------------------------------
# 生成输出
# ---------------------------------------------------------------------------
def build_data(nodes, raw_count, source):
    countries = {}
    protocol_stats = {}

    for n in nodes:
        c = n["country"] or "未知"
        countries.setdefault(
            c, {"code": n["country_code"] or "?", "nodes": []}
        )["nodes"].append(n)
        protocol_stats[n["protocol"]] = protocol_stats.get(n["protocol"], 0) + 1

    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["nodes"].sort(
            key=lambda n: (-n["uptime_percent"], n["latency_ms"])
        )
        by_country[name] = grp

    stats = {
        "raw_nodes": raw_count,
        "final_nodes": len(nodes),
        "countries": len(countries),
        "protocols": protocol_stats,
        "avg_uptime": round(
            sum(n["uptime_percent"] for n in nodes) / len(nodes), 2
        ) if nodes else 0,
        "avg_latency_ms": round(
            sum(n["latency_ms"] for n in nodes) / len(nodes), 2
        ) if nodes else 0,
    }

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "filters": {
            "min_uptime": MIN_UPTIME,
            "max_latency_ms": MAX_LATENCY_MS,
            "allowed_protocols": ALLOWED_PROTOCOLS,
            "allowed_countries": ALLOWED_COUNTRIES,
            "max_nodes": MAX_NODES,
        },
        "stats": stats,
        "countries": by_country,
        "available": nodes,
    }

def build_nodes_text(data):
    lines = []
    ordered = sorted(
        data["countries"].items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        for i, n in enumerate(grp["nodes"], 1):
            lines.append(
                f"{n['protocol']}://{n['ip']}:{n['port']}#{zh}-{n['protocol']}-{i:02d}"
            )
    return "\n".join(lines) + "\n"

def render_html(data):
    stats = data["stats"]
    protocols = stats.get("protocols", {})
    proto_str = " / ".join(f"{k}: {v}" for k, v in sorted(protocols.items())) or "无"

    # 国家筛选选项：显示当前数据中存在的地区，并始终保留“香港”选项。
    country_options = {}
    for _name, _grp in data.get("countries", {}).items():
        _code = str(_grp.get("code") or "?").upper()
        _zh = COUNTRY_ZH.get(_code) or _name
        country_options[_code] = (_zh, int(_grp.get("count") or 0))
    country_options.setdefault("HK", ("香港", 0))

    option_html = ['<option value="">全部地区</option>']
    for _code, (_zh, _count) in sorted(
        country_options.items(), key=lambda item: (item[1][0], item[0])
    ):
        option_html.append(
            f'<option value="{html.escape(_code, quote=True)}">'
            f'{html.escape(_zh)} ({_count})</option>'
        )

    top_countries = sorted(
        data.get("countries", {}).items(),
        key=lambda kv: -int(kv[1].get("count") or 0),
    )[:20]
    # 即使香港数量未进入 Top 20，也在统计表中显示香港这一行。
    if not any(str(g.get("code", "")).upper() == "HK" for _, g in top_countries):
        for _name, _grp in data.get("countries", {}).items():
            if str(_grp.get("code", "")).upper() == "HK":
                top_countries.append((_name, _grp))
                break

    rows_html = []
    for name, grp in top_countries:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or name
        rows_html.append(
            f"<tr><td>{html.escape(zh)}</td><td>{html.escape(code)}</td>"
            f"<td>{int(grp.get('count') or 0)}</td></tr>"
        )

    # 将当前页面已有的节点数据嵌入网页，筛选在浏览器本地完成，不额外请求接口。
    nodes_json = json.dumps(data.get("available", []), ensure_ascii=False)
    nodes_json = nodes_json.replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>代理池状态</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 1100px; margin: 2em auto; padding: 0 1em;
       background: #f5f5f7; color: #1d1d1f; }}
h1 {{ font-size: 1.6em; margin-bottom: 0.3em; }}
.card {{ background: #fff; padding: 1.2em; border-radius: 10px;
        margin: 1em 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1em; }}
.stat {{ text-align: center; }}
.stat .num {{ font-size: 1.8em; font-weight: 600; color: #0366d6; }}
.stat .label {{ color: #666; font-size: 0.85em; margin-top: 0.2em; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 0.55em 0.6em; text-align: left; border-bottom: 1px solid #eee; font-size: 0.92em; }}
th {{ background: #fafafa; font-weight: 600; }}
code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
a {{ color: #0366d6; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.muted {{ color: #888; font-size: 0.9em; }}
select {{ padding: 8px 10px; min-width: 190px; border: 1px solid #ccc; border-radius: 6px; background: #fff; }}
.table-wrap {{ overflow-x: auto; }}
</style>
</head>
<body>
<h1>代理池状态</h1>

<div class="card">
  <p class="muted">生成时间: <strong>{html.escape(str(data.get('generated_at', '')))}</strong></p>
  <p class="muted">数据源: <code>{html.escape(str(data.get('source', '')))}</code></p>
  <p class="muted">过滤条件: uptime &ge; {MIN_UPTIME}% &nbsp;|&nbsp; latency &le; {MAX_LATENCY_MS}ms &nbsp;|&nbsp; 协议 {html.escape(', '.join(ALLOWED_PROTOCOLS) or '全部')}</p>
</div>

<div class="card">
  <div class="stats">
    <div class="stat"><div class="num">{stats['raw_nodes']}</div><div class="label">原始</div></div>
    <div class="stat"><div class="num">{stats['final_nodes']}</div><div class="label">最终</div></div>
    <div class="stat"><div class="num">{stats['countries']}</div><div class="label">国家/地区</div></div>
    <div class="stat"><div class="num">{stats['avg_uptime']}%</div><div class="label">平均在线率</div></div>
    <div class="stat"><div class="num">{stats['avg_latency_ms']}ms</div><div class="label">平均延迟</div></div>
  </div>
</div>

<div class="card">
  <h3>协议分布</h3>
  <p>{html.escape(proto_str)}</p>
</div>

<div class="card">
  <h3>国家/地区筛选</h3>
  <p><label for="countryFilter">选择地区：</label>
  <select id="countryFilter">{''.join(option_html)}</select></p>
  <p class="muted" id="resultCount">正在加载节点……</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>国家/地区</th><th>协议</th><th>IP</th><th>端口</th><th>延迟</th><th>在线率</th></tr></thead>
      <tbody id="nodesBody"><tr><td colspan="6" class="muted">正在加载……</td></tr></tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3>国家/地区 Top 20</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>国家/地区</th><th>代码</th><th>数量</th></tr></thead>
      <tbody>{''.join(rows_html) if rows_html else '<tr><td colspan="3" class="muted">无数据</td></tr>'}</tbody>
    </table>
  </div>
</div>

<div class="card">
  <h3>下载</h3>
  <p><a href="nodes.txt">nodes.txt</a> &nbsp;(每行 <code>protocol://ip:port</code>)<br>
  <a href="data.json">data.json</a> &nbsp;(完整元数据)</p>
</div>

<script>
const allNodes = {nodes_json};
const countryNames = {json.dumps(COUNTRY_ZH, ensure_ascii=False)};
const countryFilter = document.getElementById('countryFilter');
const nodesBody = document.getElementById('nodesBody');
const resultCount = document.getElementById('resultCount');

function renderNodes() {{
  const selected = countryFilter.value;
  const filtered = allNodes.filter(node => !selected || String(node.country_code || '').toUpperCase() === selected);
  resultCount.textContent = `找到 ${{filtered.length}} 个节点`;
  nodesBody.replaceChildren();
  if (!filtered.length) {{
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'muted';
    td.textContent = selected === 'HK' ? '当前数据中没有符合筛选条件的香港代理。下次自动更新后会再次检查。' : '当前筛选条件下没有节点。';
    tr.appendChild(td);
    nodesBody.appendChild(tr);
    return;
  }}
  for (const node of filtered) {{
    const tr = document.createElement('tr');
    const code = String(node.country_code || '').toUpperCase();
    const values = [countryNames[code] || node.country || code || '未知', node.protocol || '', node.ip || '', node.port ?? '', node.latency_ms == null ? '' : `${{node.latency_ms}} ms`, node.uptime_percent == null ? '' : `${{node.uptime_percent}}%`];
    for (const value of values) {{
      const td = document.createElement('td');
      td.textContent = String(value);
      tr.appendChild(td);
    }}
    nodesBody.appendChild(tr);
  }}
}}
countryFilter.addEventListener('change', renderNodes);
renderNodes();
</script>
</body>
</html>
"""

def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(data))

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data))

    return data_path, html_path, nodes_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    t0 = time.time()

    raw = fetch_proxies()
    raw_count = len(raw)

    nodes = to_proxy_nodes(raw)
    if not nodes:
        die("转换后没有任何有效节点 (检查 ALLOWED_PROTOCOLS / ALLOWED_COUNTRIES 配置)")

    nodes = filter_nodes(nodes)
    if not nodes:
        die("质量过滤后没有任何可用节点 (可调低 MIN_UPTIME 或调高 MAX_LATENCY_MS)")

    nodes = dedupe(nodes)
    nodes = rank_and_truncate(nodes)

    log("RESULT", f"最终输出: {len(nodes)} 个节点")

    data = build_data(nodes, raw_count, "ProxyScrape JSON API")
    data_path, html_path, nodes_path = write_outputs(data)

    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("DONE", f"总耗时: {time.time() - t0:.1f}s")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
