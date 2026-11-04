#!/usr/bin/env python3
# ProxyScrape 公共代理池：逐个实测能否访问 YouTube
# 需要依赖：requests[socks]
import concurrent.futures
import html
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
PROXIES_URL = os.environ.get(
    "PROXIES_URL",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json",
)
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TIMEOUT = int(os.environ.get("YOUTUBE_TIMEOUT", "10"))
MAX_NODES = int(os.environ.get("MAX_NODES", "500"))
WORKERS = int(os.environ.get("YOUTUBE_WORKERS", "30"))
YOUTUBE_URL = "https://www.youtube.com/"
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "HK": "香港", "TW": "台湾", "SG": "新加坡",
    "US": "美国", "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "RU": "俄罗斯", "TH": "泰国", "VN": "越南", "AU": "澳大利亚",
    "IN": "印度", "BR": "巴西", "ID": "印度尼西亚", "MY": "马来西亚",
}
ALLOWED = {"http", "https", "socks4", "socks5"}

def log(msg):
    print(msg, flush=True)

def fetch_candidates():
    log("[1/4] 正在获取 ProxyScrape 候选代理……")
    r = requests.get(PROXIES_URL, timeout=60, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, list):
        raise RuntimeError("代理 API 返回格式不是 JSON 数组")
    return data

def normalize(rows):
    out, seen = [], set()
    for p in rows:
        if not isinstance(p, dict):
            continue
        ip = str(p.get("ip") or "").strip()
        proto = str(p.get("protocol") or "").strip().lower()
        country = str(p.get("country_code") or "").strip().upper()
        try:
            port = int(p.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not ip or proto not in ALLOWED or not 1 <= port <= 65535:
            continue
        key = (proto, ip, port)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "ip": ip, "port": port, "protocol": proto,
            "country": str(p.get("country") or ""),
            "country_code": country,
            "city": str(p.get("city") or ""),
            "uptime_percent": p.get("uptime_percent"),
            "source_latency_ms": p.get("latency_ms"),
            "link": f"{proto}://{ip}:{port}",
        })
    return out[:MAX_NODES] if MAX_NODES > 0 else out

def test_one(node):
    proto, ip, port = node["protocol"], node["ip"], node["port"]
    proxy_url = f"{proto}://{ip}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    started = time.perf_counter()
    result = dict(node)
    try:
        # 请求 YouTube 首页并校验最终域名，不能只测 IP 端口或 TCP 握手。
        with requests.get(
            YOUTUBE_URL,
            proxies=proxies,
            timeout=(TIMEOUT, TIMEOUT),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"},
            allow_redirects=True,
            stream=True,
        ) as response:
            elapsed = round((time.perf_counter() - started) * 1000, 1)
            final_host = (urlsplit(response.url).hostname or "").lower()
            status_ok = 200 <= response.status_code < 400
            host_ok = final_host == "youtube.com" or final_host.endswith(".youtube.com")
            result.update({
                "youtube_ok": bool(status_ok and host_ok),
                "youtube_status": response.status_code,
                "youtube_latency_ms": elapsed,
                "youtube_final_url": response.url,
                "test_error": "" if status_ok and host_ok else "HTTP状态或最终域名不符合预期",
            })
    except Exception as exc:
        result.update({
            "youtube_ok": False,
            "youtube_status": None,
            "youtube_latency_ms": None,
            "youtube_final_url": "",
            "test_error": f"{type(exc).__name__}: {str(exc)[:180]}",
        })
    return result

def make_page(data):
    nodes = data["results"]
    countries = sorted({n.get("country_code") or "?" for n in nodes})
    country_options = ['<option value="">全部地区</option>']
    for c in countries:
        label = COUNTRY_ZH.get(c, c)
        country_options.append(f'<option value="{html.escape(c, quote=True)}">{html.escape(label)} ({sum(1 for n in nodes if (n.get("country_code") or "?") == c)})</option>')
    rows = []
    for n in nodes:
        c = n.get("country_code") or "?"
        label = COUNTRY_ZH.get(c, n.get("country") or c)
        ok = n.get("youtube_ok")
        status = "可访问" if ok else "不可访问"
        latency = f'{n["youtube_latency_ms"]} ms' if n.get("youtube_latency_ms") is not None else "-"
        rows.append(
            "<tr data-country='" + html.escape(c, quote=True) + "' data-ok='" + ("1" if ok else "0") + "'>"
            f"<td>{html.escape(label)}</td><td>{html.escape(n['protocol'])}</td>"
            f"<td>{html.escape(n['ip'])}:{n['port']}</td><td>{status}</td>"
            f"<td>{latency}</td><td>{html.escape(str(n.get('youtube_status') or '-'))}</td>"
            f"<td>{html.escape(n.get('test_error') or '')}</td></tr>"
        )
    ok_count = sum(1 for n in nodes if n.get("youtube_ok"))
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>YouTube 代理实测</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1200px;margin:24px auto;padding:0 14px;background:#f5f6f8;color:#222}}
.card{{background:white;padding:16px;border-radius:10px;margin:14px 0}}
.stats{{display:flex;gap:24px;flex-wrap:wrap}}.num{{font-size:26px;font-weight:bold}}
select{{padding:8px;margin:5px}}table{{border-collapse:collapse;width:100%;min-width:850px}}
th,td{{padding:9px;border-bottom:1px solid #eee;text-align:left;font-size:13px;word-break:break-word}}
th{{background:#f4f4f4}}.wrap{{overflow:auto}}.good{{color:green}}.bad{{color:#b33}}.note{{color:#666;font-size:13px}}
</style></head><body>
<h1>YouTube 代理实测结果</h1>
<div class="card"><p>更新时间：{html.escape(data['generated_at'])}</p>
<p class="note">测试方式：通过每个代理请求 https://www.youtube.com/，记录请求耗时、HTTP 状态和最终域名。此结果只代表本次 GitHub Actions 运行环境的测试结果，不保证你本地网络也能连接。</p>
<div class="stats"><div><div class="num">{len(nodes)}</div>已测试</div>
<div><div class="num good">{ok_count}</div>YouTube 可访问</div>
<div><div class="num bad">{len(nodes)-ok_count}</div>失败</div></div></div>
<div class="card"><label>地区筛选</label><select id="country">{''.join(country_options)}</select>
<label>结果</label><select id="status"><option value="">全部</option><option value="1">可访问</option><option value="0">不可访问</option></select>
<p id="count" class="note"></p><div class="wrap"><table><thead><tr><th>地区</th><th>协议</th><th>代理地址</th><th>测试结果</th><th>YouTube延迟</th><th>HTTP</th><th>失败原因</th></tr></thead>
<tbody id="body">{''.join(rows)}</tbody></table></div></div>
<div class="card"><a href="youtube_ok.txt">下载可访问节点列表</a>　|　<a href="data.json">完整 JSON</a></div>
<script>
const country=document.getElementById('country'),status=document.getElementById('status'),body=document.getElementById('body'),count=document.getElementById('count');
function filter(){{let n=0;for(const tr of body.rows){{let show=(!country.value||tr.dataset.country===country.value)&&(!status.value||tr.dataset.ok===status.value);tr.hidden=!show;if(show)n++;}}count.textContent='显示 '+n+' 条';}}
country.onchange=filter;status.onchange=filter;filter();
</script></body></html>"""

def main():
    started = time.time()
    raw = fetch_candidates()
    candidates = normalize(raw)
    log(f"[2/4] 候选代理 {len(candidates)} 个，开始逐个访问 YouTube（并发 {WORKERS}）……")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(test_one, n) for n in candidates]
        for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
            results.append(f.result())
            if i % 25 == 0 or i == len(futures):
                log(f"      已完成 {i}/{len(futures)}")
    results.sort(key=lambda n: (not n["youtube_ok"], n["youtube_latency_ms"] is None, n["youtube_latency_ms"] or 0))
    ok = [n for n in results if n["youtube_ok"]]
    log(f"[3/4] YouTube 可访问 {len(ok)} 个，失败 {len(results)-len(ok)} 个")
    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": PROXIES_URL,
        "test_target": YOUTUBE_URL,
        "test_method": "HTTPS GET YouTube homepage through each proxy",
        "tested": len(results),
        "youtube_ok": len(ok),
        "failed": len(results)-len(ok),
        "results": results,
    }
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    with open(os.path.join(PUBLIC_DIR, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    with open(os.path.join(PUBLIC_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(make_page(data))
    with open(os.path.join(PUBLIC_DIR, "youtube_ok.txt"), "w", encoding="utf-8") as f:
        for n in ok:
            f.write(f'{n["link"]}#YouTube-{n.get("country_code") or "unknown"}-{n["youtube_latency_ms"]}ms\n')
    log(f"[4/4] 已生成 public/data.json、public/index.html、public/youtube_ok.txt")
    log(f"总耗时：{time.time()-started:.1f} 秒")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"[失败] {type(exc).__name__}: {exc}")
        raise
