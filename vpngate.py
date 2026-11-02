#!/usr/bin/env python3
"""
VPN Gate SSTP 节点流水线
========================
输出格式 (public/nodes.txt):
  优选入口IP:端口#国家-类型-序号$sstp://vpn:vpn@opengw域名:端口

流程:
  1. 从 VPN Gate 官方 API 获取原始节点 (CSV)
  2. 解析 OpenVPN 配置, 只保留 proto tcp 的 SSTP 节点
  3. 去重
  4. [可选] 提交 Cloudflare Worker 检测 (未配置则跳过, 用 host 名启发式分类)
  5. 合并静态 + 动态 Cloudflare 优选入口
  6. 生成 public/nodes.txt / data.json / index.html
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

import requests

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (全部可用环境变量覆盖)
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))

# VPN Gate 官方 API (如被墙可换成 GeorgeXie2333 镜像 CSV)
VPNGATE_API = os.environ.get(
    "VPNGATE_API",
    "https://www.vpngate.net/api/iphone/",
)

# 检测 Worker (可选)。留空或含 "你的域名" 表示不启用检测
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "").strip()
USE_WORKER = bool(WORKER_CHECK_URL) and "你的域名" not in WORKER_CHECK_URL
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "60"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
MAX_NODES = int(os.environ.get("MAX_NODES", "0"))  # 0 = 不限制

# 静态 Cloudflare 优选入口池 (IP:端口)
EDGE_HOSTS_STATIC = [
    e.strip()
    for e in os.environ.get(
        "EDGE_HOSTS",
        "172.66.1.119:443,172.66.0.65:443,104.17.153.127:443,"
        "8.35.211.112:443,172.66.1.115:443,104.18.33.33:443",
    ).split(",")
    if e.strip()
]

# 动态优选 API (可逗号分隔多个); 返回每行 ip:port#备注 形式
OPTIMAL_API = os.environ.get("OPTIMAL_API", "").strip()

NODES_URL = os.environ.get(
    "NODES_URL", "https://wongvince.github.io/gate/nodes.txt"
)

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
# 1. 抓取 VPN Gate 官方 CSV
# ---------------------------------------------------------------------------
def fetch_vpngate():
    log("VPN GATE", f"请求官方 API: {VPNGATE_API}")
    try:
        resp = requests.get(
            VPNGATE_API,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"},
        )
        resp.raise_for_status()
    except Exception as exc:
        die(f"请求失败: {type(exc).__name__}: {exc}")

    text = resp.text
    if not text or not text.strip():
        die("API 返回空内容")

    head = text[:500].lower()
    if "<html" in head or "<!doctype" in head:
        die(f"API 返回 HTML 而非 CSV (可能被拦截): {text[:200]!r}")

    log("VPN GATE", f"响应预览: {text[:160]!r}")

    try:
        rows = parse_csv(text)
    except Exception as exc:
        die(f"CSV 解析失败: {type(exc).__name__}: {exc}")

    if not rows:
        die("解析到 0 条有效记录")

    log("VPN GATE", f"获取到 {len(rows)} 条原始节点")
    return rows

def parse_csv(text):
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    header_idx = None
    for i, ln in enumerate(lines):
        probe = ln.strip().lstrip("\ufeff").lstrip("#*").strip().lower()
        if probe.startswith("hostname") or "openvpn_configdata_base64" in probe:
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError(
            "找不到 CSV 表头行; 预览: " + repr("\n".join(lines[:4])[:200])
        )

    raw_header = lines[header_idx].strip().lstrip("\ufeff").lstrip("#*")
    header = [h.strip().lstrip("*").strip() for h in next(csv.reader(io.StringIO(raw_header)))]

    def find_col(*names):
        for name in names:
            for i, h in enumerate(header):
                if h.lower() == name.lower():
                    return i
        return None

    idx = {
        "hostname": find_col("HostName", "hostname"),
        "ip": find_col("IP", "ip"),
        "country_long": find_col("CountryLong", "countrylong"),
        "country_short": find_col("CountryShort", "countryshort"),
        "b64": find_col("OpenVPN_ConfigData_Base64", "openvpn_configdata_base64"),
    }
    if idx["b64"] is None:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["b64"] = i
                break
    if idx["hostname"] is None or idx["ip"] is None:
        raise RuntimeError(f"表头缺少 HostName/IP 列: {header}")

    rows = []
    for ln in lines[header_idx + 1:]:
        s = ln.strip()
        if not s or s.startswith(("*", "#")):
            continue
        try:
            fields = next(csv.reader(io.StringIO(ln)))
        except Exception:
            continue
        if len(fields) <= max(idx["hostname"], idx["ip"]):
            continue
        host = fields[idx["hostname"]].strip()
        ip = fields[idx["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[idx["country_long"]].strip()
                if idx["country_long"] is not None and len(fields) > idx["country_long"] else "",
            "country_short": fields[idx["country_short"]].strip()
                if idx["country_short"] is not None and len(fields) > idx["country_short"] else "",
            "config_b64": fields[idx["b64"]].strip()
                if idx["b64"] is not None and len(fields) > idx["b64"] else "",
        })
    return rows

# ---------------------------------------------------------------------------
# 2. 过滤出 SSTP (TCP) 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    skipped_notcp = 0
    skipped_noport = 0
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg):
            skipped_notcp += 1
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            skipped_noport += 1
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            skipped_noport += 1
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "country": r["country_long"],
            "country_code": r["country_short"].upper() if r["country_short"] else "",
        })
    log(
        "SSTP",
        f"TCP 节点 {len(nodes)} 个 (非 TCP 跳过 {skipped_notcp}, 无端口跳过 {skipped_noport})",
    )
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    log("DEDUPE", f"去重后: {len(out)}")
    return out

# ---------------------------------------------------------------------------
# 3. 分类 (住宅 / 机房) —— Worker 可选, 否则启发式
# ---------------------------------------------------------------------------
def classify_heuristic(host):
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["residential"] = classify_heuristic(node["host"])
    out["latency_ms"] = None
    try:
        r = session.get(
            url,
            timeout=CHECK_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (gate-checker)", "Accept": "application/json"},
        )
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}: {r.text[:200]!r}"
            return out
        j = r.json()
        if not isinstance(j, dict):
            out["error"] = "Worker 返回非 JSON 对象"
            return out
        ok = bool(j.get("success"))
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        exit_info = j.get("exit") or {}
        if isinstance(exit_info, dict) and exit_info:
            is_dc = exit_info.get("is_datacenter")
            if is_dc is True:
                out["residential"] = "datacenter"
            elif is_dc is False:
                out["residential"] = "residential"
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

def check_all(nodes, session):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 4. Cloudflare 优选入口
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    if not api_urls_str:
        return []
    endpoints = []
    for url in [u.strip() for u in api_urls_str.split(",") if u.strip()]:
        try:
            log("OPTIMAL API", f"请求: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                count = 0
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"获取 {count} 个端点")
            else:
                log("OPTIMAL API", f"状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)
    combined = []
    seen = set()
    for h in EDGE_HOSTS_STATIC + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)
    log(
        "EDGE POOL",
        f"静态 {len(EDGE_HOSTS_STATIC)} 个, API {len(api_hosts)} 个, 合并共 {len(combined)} 个",
    )
    return combined if combined else EDGE_HOSTS_STATIC

# ---------------------------------------------------------------------------
# 5. 生成输出 (核心: nodes.txt 格式)
# ---------------------------------------------------------------------------
def build_nodes_text(nodes, edge_hosts):
    """
    按 国家 -> 住宅在前、机房在后、延迟升序 排序
    每行: {entry}#{国家中文}-{住宅|机房}-{序号}$sstp://vpn:vpn@{host}:{port}
    """
    by_country = {}
    for n in nodes:
        key = n.get("country") or "未知"
        by_country.setdefault(key, []).append(n)

    ordered_countries = sorted(
        by_country.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )

    lines = []
    idx = 0
    for cname, group in ordered_countries:
        # 国家中文名: 优先用 code 映射, 否则用 country 原文
        code = (group[0].get("country_code") or "").upper()
        zh = COUNTRY_ZH.get(code) or cname

        residential = [n for n in group if n.get("residential") == "residential"]
        datacenter = [n for n in group if n.get("residential") == "datacenter"]
        unknown = [n for n in group if n.get("residential") not in ("residential", "datacenter")]

        def sort_key(n):
            return (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"])

        for bucket_name, bucket in (
            ("住宅", sorted(residential, key=sort_key)),
            ("机房", sorted(datacenter, key=sort_key)),
            ("未知", sorted(unknown, key=sort_key)),
        ):
            for i, n in enumerate(bucket, 1):
                entry = edge_hosts[idx % len(edge_hosts)]
                idx += 1
                lines.append(
                    f"{entry}#{zh}-{bucket_name}-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}"
                )
    return "\n".join(lines) + "\n"

def build_data(nodes, raw_count, sstp_count, source):
    countries = {}
    for n in nodes:
        c = n.get("country") or "未知"
        countries.setdefault(c, {"code": n.get("country_code") or "?", "nodes": []})["nodes"].append(n)

    for grp in countries.values():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for x in grp["nodes"] if x.get("residential") == "residential")
        grp["datacenter"] = sum(1 for x in grp["nodes"] if x.get("residential") == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "final_nodes": len(nodes),
        "countries": len(countries),
        "residential": sum(1 for n in nodes if n.get("residential") == "residential"),
        "datacenter": sum(1 for n in nodes if n.get("residential") == "datacenter"),
        "worker_used": USE_WORKER,
    }

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "stats": stats,
        "countries": countries,
        "available": nodes,
    }

def render_html(data):
    s = data["stats"]
    top = sorted(data["countries"].items(), key=lambda kv: -kv[1]["count"])[:20]
    rows = "".join(
        f"<tr><td>{COUNTRY_ZH.get(str(g.get('code') or '').upper(), name)}</td>"
        f"<td>{g.get('code') or '?'}</td><td>{g['count']}</td>"
        f"<td>{g['residential']}</td><td>{g['datacenter']}</td></tr>"
        for name, g in top
    )
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Gate SSTP 节点</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
max-width:960px;margin:2em auto;padding:0 1em;background:#f5f5f7;color:#1d1d1f}}
h1{{font-size:1.6em}}.card{{background:#fff;padding:1.2em;border-radius:10px;
margin:1em 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:1em}}
.stat{{text-align:center}}.num{{font-size:1.7em;font-weight:600;color:#0366d6}}
.label{{color:#666;font-size:.85em}}.muted{{color:#888;font-size:.9em}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:.5em .6em;text-align:left;border-bottom:1px solid #eee;font-size:.95em}}
th{{background:#fafafa;font-weight:600}}
code{{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:.9em}}
a{{color:#0366d6;text-decoration:none}}a:hover{{text-decoration:underline}}
</style></head><body>
<h1>VPN Gate SSTP 节点</h1>
<div class="card">
<p class="muted">生成时间: <strong>{data['generated_at']}</strong></p>
<p class="muted">数据源: <code>{data['source']}</code></p>
<p class="muted">检测 Worker: {'已启用' if s['worker_used'] else '未启用 (启发式分类)'}</p>
</div>
<div class="card"><div class="stats">
<div class="stat"><div class="num">{s['raw_nodes']}</div><div class="label">原始</div></div>
<div class="stat"><div class="num">{s['sstp_nodes']}</div><div class="label">SSTP</div></div>
<div class="stat"><div class="num">{s['final_nodes']}</div><div class="label">最终</div></div>
<div class="stat"><div class="num">{s['countries']}</div><div class="label">国家/地区</div></div>
<div class="stat"><div class="num">{s['residential']}</div><div class="label">住宅</div></div>
<div class="stat"><div class="num">{s['datacenter']}</div><div class="label">机房</div></div>
</div></div>
<div class="card"><h3>国家/地区 Top 20</h3>
<table><thead><tr><th>国家/地区</th><th>代码</th><th>总数</th><th>住宅</th><th>机房</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5" class="muted">无数据</td></tr>'}</tbody></table></div>
<div class="card"><h3>下载</h3>
<p><a href="nodes.txt">nodes.txt</a> &nbsp;(edgetunnel 可直接使用)<br>
<a href="data.json">data.json</a> &nbsp;(完整元数据)</p></div>
</body></html>"""

def write_outputs(data, nodes, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(data))

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    text = build_nodes_text(nodes, edge_hosts)
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(text)
    return data_path, html_path, nodes_path, len(text.splitlines())

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    t0 = time.time()
    session = requests.Session()

    rows = fetch_vpngate()
    raw_count = len(rows)

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 条原始记录中未解析出任何 SSTP(TCP) 节点")

    uniq = dedupe(sstp_nodes)

    if USE_WORKER:
        log("WORKER", f"提交检测 {len(uniq)} 个 (并发 {CONCURRENCY}, 超时 {CHECK_TIMEOUT}s)")
        results = check_all(uniq, session)
        success = [r for r in results if r.get("status") == "success"]
        log("WORKER", f"检测成功 {len(success)} / {len(results)}")
        if success:
            final_nodes = success
        else:
            log("WORKER", "无成功结果, 回退使用全部节点 (启发式分类)")
            final_nodes = results
    else:
        log("WORKER", "未配置检测 Worker, 跳过检测, 使用启发式分类")
        final_nodes = []
        for n in uniq:
            m = dict(n)
            m["residential"] = classify_heuristic(n["host"])
            m["latency_ms"] = None
            m["status"] = "unknown"
            final_nodes.append(m)

    if MAX_NODES > 0:
        final_nodes = final_nodes[:MAX_NODES]

    edge_hosts = get_combined_edge_hosts()
    data = build_data(final_nodes, raw_count, sstp_count, "VPN Gate official API")

    data_path, html_path, nodes_path, line_count = write_outputs(data, final_nodes, edge_hosts)

    log("RESULT", f"最终节点: {len(final_nodes)}, 国家: {data['stats']['countries']}")
    log("RESULT", f"住宅: {data['stats']['residential']}, 机房: {data['stats']['datacenter']}")
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)} ({line_count} 行)")
    log("USAGE", f"把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框")
    log("DONE", f"总耗时: {time.time() - t0:.1f}s")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
