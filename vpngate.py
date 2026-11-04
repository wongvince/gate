from pathlib import Path

code = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProxyScrape -> Cloudflare Worker -> YouTube 可访问性检测

检测规则：
1. 只把 Cloudflare Worker 返回 JSON 中 success=true 的代理判定为成功。
2. 延迟只采用 Cloudflare Worker 返回的 responseTime。
3. 只将成功代理写入 nodes.txt 和 youtube_ok.txt。
4. 支持 HTTP、HTTPS、SOCKS5；不把 SOCKS4 或其他协议伪装成支持协议。

输出：
- public/data.json
- public/index.html
- public/nodes.txt
- public/youtube_ok.txt
"""

import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests


# Windows 控制台中文输出兼容
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 配置（可通过 GitHub Actions 环境变量覆盖）
# ---------------------------------------------------------------------------

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))

PROXYSCRAPE_API = os.environ.get(
    "PROXYSCRAPE_API",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json",
)

# 你的 Cloudflare Worker 根地址。不要在这里加 /check 或查询参数。
WORKER_BASE_URL = os.environ.get(
    "CHECK_WORKER",
    "https://wong.wong123.ccwu.cc",
).strip().rstrip("/")

CHECK_TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "45"))
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", "45"))
CONCURRENCY = max(1, min(50, int(os.environ.get("CHECK_CONCURRENCY", "20"))))
MAX_CHECK_NODES = max(0, int(os.environ.get("MAX_CHECK_NODES", "0")))

SUPPORTED_PROTOCOLS = {"http", "https", "socks5"}


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------

_CURRENT_SECTION = None


def log(section, message=""):
    global _CURRENT_SECTION
    if section != _CURRENT_SECTION:
        print(f"========== {section} ==========")
        _CURRENT_SECTION = section
    if message:
        print(message, flush=True)


def die(message):
    log("错误", message)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# ProxyScrape JSON 解析
# ---------------------------------------------------------------------------

def fetch_proxyscrape():
    log("PROXYSCRAPE", f"数据源：{PROXYSCRAPE_API}")

    response = requests.get(
        PROXYSCRAPE_API,
        timeout=FETCH_TIMEOUT,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ProxyScrape-Worker-Checker)"},
    )
    response.raise_for_status()

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"ProxyScrape 返回内容不是 JSON：{exc}") from exc

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = None
        for key in ("data", "proxies", "results", "items"):
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        if records is None:
            raise RuntimeError(
                "无法识别 ProxyScrape JSON 结构；顶层字段为："
                + ", ".join(str(k) for k in payload.keys())
            )
    else:
        raise RuntimeError("ProxyScrape JSON 顶层既不是数组也不是对象")

    log("PROXYSCRAPE", f"获取原始记录：{len(records)}")
    return records


def first_value(record, names, default=None):
    for name in names:
        value = record.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return default


def normalize_candidates(records):
    """
    兼容常见字段：
      IP: ip / ip_address / host
      端口: port
      协议: protocol / type / proxy_type / scheme
      国家: country / country_name
    """
    candidates = []
    seen = set()
    skipped_protocol = 0
    skipped_invalid = 0

    for item in records:
        if not isinstance(item, dict):
            skipped_invalid += 1
            continue

        host = str(first_value(item, ("ip", "ip_address", "host"), "")).strip()
        port_raw = first_value(item, ("port", "proxy_port"))
        protocol = str(
            first_value(item, ("protocol", "type", "proxy_type", "scheme"), "")
        ).strip().lower()

        protocol = protocol.replace("socks5h", "socks5")

        # 某些列表会把代理地址放在 proxy 字段中，例如 http://1.2.3.4:8080
        if not host:
            proxy_text = str(first_value(item, ("proxy", "address"), "")).strip()
            match = re.match(
                r"^(?:(https?|socks5)://)?(\[[0-9a-fA-F:]+\]|[^:/\s]+):(\d+)$",
                proxy_text,
                re.IGNORECASE,
            )
            if match:
                if not protocol:
                    protocol = (match.group(1) or "").lower()
                host = match.group(2).strip("[]")
                port_raw = port_raw or match.group(3)

        if protocol not in SUPPORTED_PROTOCOLS:
            skipped_protocol += 1
            continue

        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            skipped_invalid += 1
            continue

        if not host or not (1 <= port <= 65535):
            skipped_invalid += 1
            continue

        # 防止把 host 字段中的 IP:端口重复拼接
        if "://" in host:
            host = host.split("://", 1)[1]
        if host.count(":") == 1 and not host.startswith("["):
            maybe_host, maybe_port = host.rsplit(":", 1)
            if maybe_port.isdigit():
                if int(maybe_port) != port:
                    skipped_invalid += 1
                    continue
                host = maybe_host

        key = (protocol, host.lower(), port)
        if key in seen:
            continue
        seen.add(key)

        candidates.append({
            "host": host,
            "ip": host,
            "port": port,
            "protocol": protocol,
            "country": str(
                first_value(item, ("country", "country_name", "countryName"), "未知")
            ),
            "country_code": str(
                first_value(item, ("country_code", "countryCode", "country_short"), "?")
            ),
            # 保留源数据供查看，但绝不把它当作最终检测延迟
            "source_latency": first_value(
                item, ("latency", "latency_ms", "ping"), None
            ),
        })

    log("筛选", f"可提交 Worker 的候选节点：{len(candidates)}")
    log("筛选", f"跳过不支持协议：{skipped_protocol}")
    log("筛选", f"跳过无效记录：{skipped_invalid}")
    return candidates


# ---------------------------------------------------------------------------
# Cloudflare Worker 检测
# ---------------------------------------------------------------------------

def worker_check_url(node):
    # Worker 现有接口格式：/check?http=IP:PORT
    #                         /check?https=IP:PORT
    #                         /check?socks5=IP:PORT
    address = quote(f'{node["host"]}:{node["port"]}', safe="")
    return f'{WORKER_BASE_URL}/check?{node["protocol"]}={address}'


def check_one(node):
    result = dict(node)
    result.update({
        "success": False,
        "status": "failed",
        "latency_ms": None,
        "worker_response_time": None,
        "colo": None,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "error": None,
        "exit": None,
    })

    try:
        response = requests.get(
            worker_check_url(node),
            timeout=CHECK_TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; ProxyScrape-Worker-Checker)",
                "Accept": "application/json",
            },
        )

        if response.status_code != 200:
            result["error"] = (
                f"Worker HTTP {response.status_code}: {response.text[:200]}"
            )
            result["worker_error"] = True
            return result

        try:
            payload = response.json()
        except ValueError:
            result["error"] = f"Worker 没有返回 JSON：{response.text[:200]}"
            result["worker_error"] = True
            return result

        if not isinstance(payload, dict):
            result["error"] = "Worker JSON 顶层不是对象"
            result["worker_error"] = True
            return result

        # 唯一成功条件：Worker 明确返回 success=true
        success = payload.get("success") is True
        result["success"] = success
        result["status"] = "success" if success else "failed"

        # 延迟严格取 Worker responseTime，不使用 ProxyScrape 源延迟
        result["worker_response_time"] = payload.get("responseTime")
        result["latency_ms"] = payload.get("responseTime")
        result["colo"] = payload.get("colo")

        if not success:
            result["error"] = (
                payload.get("error")
                or payload.get("message")
                or "Worker 返回 success 不为 true"
            )

        exit_info = payload.get("exit")
        if isinstance(exit_info, dict):
            result["exit"] = exit_info

        return result

    except requests.RequestException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["worker_error"] = True
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["worker_error"] = True
        return result


def check_all(candidates):
    results = []

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(check_one, node) for node in candidates]

        for future in as_completed(futures):
            results.append(future.result())

    return results


# ---------------------------------------------------------------------------
# 生成输出文件
# ---------------------------------------------------------------------------

def write_outputs(results, raw_count):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    # 只有 success is True 的节点进入成功列表
    successful = [item for item in results if item.get("success") is True]

    def latency_sort_key(item):
        latency = item.get("latency_ms")
        if isinstance(latency, (int, float)):
            return (0, latency, item.get("host", ""))
        return (1, float("inf"), item.get("host", ""))

    successful.sort(key=latency_sort_key)

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": PROXYSCRAPE_API,
        "checker": "Cloudflare Worker",
        "worker": WORKER_BASE_URL,
        "target": "www.youtube.com",
        "success_rule": "Worker JSON success 必须严格等于 true",
        "latency_source": "Worker responseTime",
        "stats": {
            "raw_records": raw_count,
            "checked": len(results),
            "success": len(successful),
            "failed": len(results) - len(successful),
        },
        "available": successful,
    }

    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)

    # 纯节点列表：每行 protocol://IP:port
    node_lines = [
        f'{item["protocol"]}://{item["host"]}:{item["port"]}'
        for item in successful
    ]
    node_text = "\n".join(node_lines)
    if node_text:
        node_text += "\n"

    for filename in ("nodes.txt", "youtube_ok.txt"):
        with open(os.path.join(PUBLIC_DIR, filename), "w", encoding="utf-8") as file:
            file.write(node_text)

    html = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ProxyScrape YouTube 可用代理</title>
<style>
body{font-family:Arial,sans-serif;max-width:1000px;margin:30px auto;padding:0 16px}
pre{white-space:pre-wrap;word-break:break-all;background:#f5f5f5;padding:14px}
small{color:#666}
</style>
</head>
<body>
<h1>ProxyScrape YouTube 可用代理</h1>
<p id="stats">正在加载...</p>
<p>
<a href="data.json">data.json</a> |
<a href="nodes.txt">nodes.txt</a> |
<a href="youtube_ok.txt">youtube_ok.txt</a>
</p>
<small>成功标准：Cloudflare Worker 返回 success=true；延迟采用 Worker responseTime。
YouTube 首页可访问不代表视频 CDN 或视频播放一定正常。</small>
<h2>成功节点列表</h2>
<pre id="nodes"></pre>
<script>
fetch('data.json').then(r=>r.json()).then(d=>{
 const s=d.stats||{};
 document.getElementById('stats').textContent=
   `原始记录：${s.raw_records||0}；已检测：${s.checked||0}；成功：${s.success||0}；失败：${s.failed||0}`;
 document.getElementById('nodes').textContent=(d.available||[]).map(n=>
   `${n.protocol}://${n.host}:${n.port}    ${n.latency_ms==null?'Worker未提供延迟':n.latency_ms+' ms'}`
 ).join('\n') || '当前没有检测成功的节点';
}).catch(e=>document.getElementById('stats').textContent='加载失败：'+e);
</script>
</body>
</html>
"""

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    with open(html_path, "w", encoding="utf-8") as file:
        file.write(html)

    return len(successful)


# ---------------------------------------------------------------------------
# 主程序
# ---------------------------------------------------------------------------

def main():
    if not WORKER_BASE_URL.startswith("https://"):
        die("CHECK_WORKER 必须填写 https:// 开头的 Worker 根地址")

    if "你的域名" in WORKER_BASE_URL:
        die("请先把 CHECK_WORKER 改成你自己的 Worker 地址")

    records = fetch_proxyscrape()
    if not records:
        die("ProxyScrape 没有返回候选节点")

    candidates = normalize_candidates(records)
    if not candidates:
        die(
            "没有解析出 HTTP/HTTPS/SOCKS5 节点。"
            "请检查 ProxyScrape JSON 的实际字段结构。"
        )

    if MAX_CHECK_NODES > 0:
        candidates = candidates[:MAX_CHECK_NODES]

    log("CLOUDFLARE WORKER", f"检测地址：{WORKER_BASE_URL}/check")
    log(
        "CLOUDFLARE WORKER",
        f"提交节点：{len(candidates)}；并发：{CONCURRENCY}；超时：{CHECK_TIMEOUT}s",
    )

    start = time.time()
    results = check_all(candidates)
    elapsed = time.time() - start

    success_count = sum(1 for item in results if item.get("success") is True)
    worker_errors = sum(1 for item in results if item.get("worker_error"))

    log("检测结果", f"成功：{success_count}")
    log("检测结果", f"失败：{len(results) - success_count}")
    log("检测结果", f"Worker 请求异常：{worker_errors}")
    log("检测结果", f"总耗时：{elapsed:.1f}s")

    # 如果所有节点连 Worker JSON 都没拿到，判定为检测服务故障，
    # 不覆盖上一次成功生成的列表。
    if results and worker_errors == len(results):
        die("所有请求都没有得到有效 Worker JSON；本次不覆盖已有输出文件。")

    count = write_outputs(results, len(records))

    log("输出", f"成功节点数：{count}")
    log("输出", "public/data.json")
    log("输出", "public/index.html")
    log("输出", "public/nodes.txt")
    log("输出", "public/youtube_ok.txt")
    log("完成", "本次检测完成")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"{type(exc).__name__}: {exc}")
'''
path = Path("/mnt/data/vpngate.py")
path.write_text(code, encoding="utf-8")
print(f"已生成文件：{path}")
print(f"文件大小：{path.stat().st_size} 字节")
print(f"代码行数：{len(code.splitlines())}")
