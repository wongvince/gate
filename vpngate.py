
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ProxyScrape + Cloudflare Worker + YouTube 检测

成功条件：
1. ProxyScrape 提供代理候选
2. Cloudflare Worker 返回 HTTP 200
3. Worker JSON 中 success 必须为 true
4. 延迟只采用 Worker 返回的 responseTime

输出：
public/data.json
public/index.html
public/nodes.txt
public/youtube_ok.txt
"""

import os
import re
import json
import time
import html
import logging
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# =========================
# 基本配置
# =========================

PROXYSCRAPE_API = os.getenv(
    "PROXYSCRAPE_API",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json"
)

WORKER_BASE_URL = os.getenv(
    "CHECK_WORKER",
    "https://wong.wong123.ccwu.cc"
).rstrip("/")

PUBLIC_DIR = Path(os.getenv("PUBLIC_DIR", "public"))

MAX_WORKERS = int(os.getenv("MAX_WORKERS", "20"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "45"))

SUPPORTED_PROTOCOLS = {"http", "https", "socks5"}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


# =========================
# 获取 ProxyScrape 数据
# =========================

def fetch_proxyscrape():

    logging.info("========== 获取 ProxyScrape 数据 ==========")

    response = session.get(
        PROXYSCRAPE_API,
        timeout=30
    )

    response.raise_for_status()

    try:
        data = response.json()
    except Exception as exc:
        raise RuntimeError(
            f"ProxyScrape 返回的不是有效 JSON：{exc}"
        )

    records = extract_records(data)

    logging.info("ProxyScrape 原始记录：%s", len(records))

    return records


def extract_records(data):
    """
    兼容常见 JSON 结构：
    [...]
    {"data": [...]}
    {"proxies": [...]}
    {"results": [...]}
    """

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        for key in (
            "data",
            "proxies",
            "results",
            "items",
            "proxy_list"
        ):
            value = data.get(key)

            if isinstance(value, list):
                return value

    raise RuntimeError(
        "无法识别 ProxyScrape JSON 数据结构，请检查 API 返回格式"
    )


# =========================
# 解析代理地址
# =========================

def parse_proxy_address(address):

    address = str(address).strip()

    if "://" in address:

        parsed = urlparse(address)

        return (
            parsed.hostname,
            parsed.port,
            parsed.scheme.lower()
        )

    if address.count(":") == 1:

        host, port = address.rsplit(":", 1)

        if port.isdigit():
            return host, int(port), None

    return None, None, None


def valid_host(host):

    if not host:
        return False

    host = str(host).strip()

    if len(host) > 253:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return bool(
        re.fullmatch(
            r"[a-zA-Z0-9.-]+",
            host
        )
    )


def normalize_candidates(records):

    logging.info("========== 解析代理候选 ==========")

    candidates = []
    seen = set()

    for item in records:

        if not isinstance(item, dict):
            continue

        host = (
            item.get("ip")
            or item.get("ip_address")
            or item.get("host")
            or item.get("hostname")
        )

        port = item.get("port")

        protocol = (
            item.get("protocol")
            or item.get("type")
            or item.get("proxy_type")
            or item.get("scheme")
        )

        address = (
            item.get("proxy")
            or item.get("address")
            or item.get("proxy_address")
        )

        address_protocol = None

        if address:
            parsed_host, parsed_port, address_protocol = (
                parse_proxy_address(address)
            )

            host = host or parsed_host
            port = port or parsed_port

        protocol = str(
            protocol or address_protocol or ""
        ).lower().strip()

        protocol = protocol.replace("socks5h", "socks5")

        if protocol not in SUPPORTED_PROTOCOLS:
            continue

        if not valid_host(host):
            continue

        try:
            port = int(port)
        except (TypeError, ValueError):
            continue

        if not 1 <= port <= 65535:
            continue

        key = (protocol, str(host), port)

        if key in seen:
            continue

        seen.add(key)

        candidates.append({
            "protocol": protocol,
            "host": str(host),
            "port": port
        })

    logging.info(
        "有效候选代理：%s",
        len(candidates)
    )

    return candidates


# =========================
# Cloudflare Worker 检测
# =========================

def check_one(proxy):

    protocol = proxy["protocol"]
    host = proxy["host"]
    port = proxy["port"]

    address = f"{host}:{port}"

    check_url = f"{WORKER_BASE_URL}/check"

    try:

        response = session.get(
            check_url,
            params={
                protocol: address
            },
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:

            return {
                **proxy,
                "success": False,
                "error": f"Worker HTTP {response.status_code}"
            }

        try:
            result = response.json()
        except Exception:

            return {
                **proxy,
                "success": False,
                "error": "Worker 返回内容不是 JSON"
            }

        if not isinstance(result, dict):

            return {
                **proxy,
                "success": False,
                "error": "Worker JSON 格式错误"
            }

        success = result.get("success") is True

        if not success:

            return {
                **proxy,
                "success": False,
                "error": result.get("error", "YouTube 检测失败")
            }

        response_time = result.get("responseTime")

        try:
            response_time = float(response_time)
        except (TypeError, ValueError):
            response_time = None

        return {
            **proxy,
            "success": True,
            "responseTime": response_time,
            "target": result.get("target", "www.youtube.com"),
            "statusCode": result.get("statusCode"),
            "colo": result.get("colo")
        }

    except Exception as exc:

        return {
            **proxy,
            "success": False,
            "error": str(exc)
        }


# =========================
# 批量检测
# =========================

def check_all(candidates):

    logging.info("========== 开始 YouTube 检测 ==========")

    results = []

    if not candidates:
        logging.warning("没有可检测的代理")
        return results

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(check_one, proxy)
            for proxy in candidates
        ]

        for index, future in enumerate(
            as_completed(futures),
            start=1
        ):

            try:
                result = future.result()
                results.append(result)

                if result["success"]:

                    latency = result.get("responseTime")

                    logging.info(
                        "[成功] %s://%s:%s | Worker延迟：%s ms",
                        result["protocol"],
                        result["host"],
                        result["port"],
                        latency if latency is not None else "未知"
                    )

                else:

                    logging.info(
                        "[失败] %s://%s:%s | %s",
                        result["protocol"],
                        result["host"],
                        result["port"],
                        result.get("error", "检测失败")
                    )

            except Exception as exc:

                logging.error(
                    "检测任务异常：%s",
                    exc
                )

            if index % 20 == 0:
                logging.info(
                    "检测进度：%s/%s",
                    index,
                    len(futures)
                )

    return results


# =========================
# 输出文件
# =========================

def write_outputs(success_nodes, total, worker_errors):

    PUBLIC_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # Worker 全部请求异常时，不覆盖旧结果
    if total > 0 and worker_errors == total:

        logging.error(
            "所有 Worker 请求均异常，本次不覆盖旧文件"
        )

        return

    success_nodes.sort(
        key=lambda x: (
            x["responseTime"]
            if x.get("responseTime") is not None
            else float("inf")
        )
    )

    data = {
        "updated_at": time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.gmtime()
        ) + " UTC",
        "target": "https://www.youtube.com/",
        "candidate_count": total,
        "success_count": len(success_nodes),
        "success_nodes": success_nodes
    }

    # data.json
    (PUBLIC_DIR / "data.json").write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    # nodes.txt
    node_lines = []

    for node in success_nodes:

        node_lines.append(
            f'{node["protocol"]}://'
            f'{node["host"]}:{node["port"]}'
        )

    (PUBLIC_DIR / "nodes.txt").write_text(
        "\n".join(node_lines) + (
            "\n" if node_lines else ""
        ),
        encoding="utf-8"
    )

    # youtube_ok.txt
    youtube_lines = []

    for node in success_nodes:

        latency = node.get("responseTime")

        latency_text = (
            f"{latency} ms"
            if latency is not None
            else "未知延迟"
        )

        youtube_lines.append(
            f'{node["protocol"]}://'
            f'{node["host"]}:{node["port"]}'
            f'  # YouTube可访问 | {latency_text}'
        )

    (PUBLIC_DIR / "youtube_ok.txt").write_text(
        "\n".join(youtube_lines) + (
            "\n" if youtube_lines else ""
        ),
        encoding="utf-8"
    )

    # index.html
    rows = []

    for index, node in enumerate(success_nodes, 1):

        latency = node.get("responseTime")

        latency_text = (
            f"{latency} ms"
            if latency is not None
            else "未知"
        )

        proxy = (
            f'{node["protocol"]}://'
            f'{node["host"]}:{node["port"]}'
        )

        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{html.escape(proxy)}</td>"
            f"<td>{html.escape(latency_text)}</td>"
            f"<td>成功</td>"
            "</tr>"
        )

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YouTube 代理检测结果</title>
<style>
body{{font-family:Arial,sans-serif;margin:25px;background:#f5f5f5}}
h2{{color:#222}}
.box{{background:white;padding:18px;border-radius:8px}}
table{{width:100%;border-collapse:collapse;background:white}}
th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}
th{{background:#eee}}
.ok{{color:green;font-weight:bold}}
</style>
</head>
<body>
<div class="box">
<h2>ProxyScrape YouTube 代理检测</h2>
<p>目标：https://www.youtube.com/</p>
<p>候选数量：{total}</p>
<p>检测成功：{len(success_nodes)}</p>
<p>更新时间：{html.escape(data["updated_at"])}</p>
<table>
<tr><th>序号</th><th>代理地址</th><th>Worker延迟</th><th>结果</th></tr>
{''.join(rows)}
</table>
</div>
</body>
</html>
"""

    (PUBLIC_DIR / "index.html").write_text(
        page,
        encoding="utf-8"
    )

    logging.info("========== 输出完成 ==========")
    logging.info("成功节点：%s", len(success_nodes))
    logging.info("输出目录：%s", PUBLIC_DIR)


# =========================
# 主程序
# =========================

def main():

    logging.info("================================")
    logging.info("ProxyScrape YouTube 检测启动")
    logging.info("Worker：%s", WORKER_BASE_URL)
    logging.info("================================")

    records = fetch_proxyscrape()

    candidates = normalize_candidates(records)

    if not candidates:
        raise RuntimeError(
            "没有解析到可检测的 HTTP/HTTPS/SOCKS5 代理"
        )

    results = check_all(candidates)

    success_nodes = [
        item for item in results
        if item.get("success") is True
    ]

    worker_errors = sum(
        1 for item in results
        if item.get("error", "").startswith(
            "Worker HTTP"
        )
        or item.get("error", "").startswith(
            "Worker 返回"
        )
    )

    logging.info("================================")
    logging.info("候选代理：%s", len(candidates))
    logging.info("Worker 检测成功：%s", len(success_nodes))
    logging.info("Worker 请求异常：%s", worker_errors)
    logging.info("================================")

    write_outputs(
        success_nodes,
        len(candidates),
        worker_errors
    )


if __name__ == "__main__":
    main()
