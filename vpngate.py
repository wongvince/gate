
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import html
import logging
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
    FIRST_COMPLETED
)

import requests


# =====================================
# 配置
# =====================================

PROXYSCRAPE_API = os.getenv(
    "PROXYSCRAPE_API",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/all/data.json"
)

WORKER_BASE_URL = os.getenv(
    "CHECK_WORKER",
    "https://wong.wong123.ccwu.cc"
).rstrip("/")

PUBLIC_DIR = Path("public")

# 并发数
MAX_WORKERS = 20

# 最多测试多少个代理
MAX_TEST_NODES = 100

# 找到多少个成功代理就停止提交新任务
TARGET_SUCCESS = 30

# 单个 Worker 请求超时
REQUEST_TIMEOUT = 12

SUPPORTED_PROTOCOLS = {
    "http",
    "https",
    "socks5"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

session = requests.Session()
session.headers.update(HEADERS)


# =====================================
# 获取 ProxyScrape
# =====================================

def fetch_proxyscrape():

    logging.info("正在获取 ProxyScrape 代理列表")

    response = session.get(
        PROXYSCRAPE_API,
        timeout=25
    )

    response.raise_for_status()

    data = response.json()

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

            if isinstance(data.get(key), list):
                return data[key]

    raise RuntimeError(
        "无法识别 ProxyScrape 返回的数据结构"
    )


# =====================================
# 解析代理
# =====================================

def parse_address(address):

    try:

        parsed = urlparse(str(address))

        if parsed.scheme and parsed.hostname:

            return (
                parsed.hostname,
                parsed.port,
                parsed.scheme.lower()
            )

    except Exception:
        pass

    address = str(address).strip()

    if address.count(":") == 1:

        host, port = address.rsplit(":", 1)

        if port.isdigit():
            return host, int(port), None

    return None, None, None


def valid_host(host):

    if not host:
        return False

    try:
        ipaddress.ip_address(str(host))
        return True
    except ValueError:
        return bool(
            re.fullmatch(
                r"[a-zA-Z0-9.-]+",
                str(host)
            )
        )


def normalize_candidates(records):

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
                parse_address(address)
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

    return candidates


# =====================================
# Worker 检测 YouTube
# =====================================

def check_one(proxy):

    protocol = proxy["protocol"]
    host = proxy["host"]
    port = proxy["port"]

    try:

        response = session.get(
            WORKER_BASE_URL + "/check",
            params={
                protocol: f"{host}:{port}"
            },
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:

            return {
                **proxy,
                "success": False,
                "error": f"Worker HTTP {response.status_code}"
            }

        result = response.json()

        if not isinstance(result, dict):

            return {
                **proxy,
                "success": False,
                "error": "Worker JSON 格式错误"
            }

        if result.get("success") is not True:

            return {
                **proxy,
                "success": False,
                "error": result.get("error", "YouTube 检测失败")
            }

        latency = result.get("responseTime")

        try:
            latency = float(latency)
        except (TypeError, ValueError):
            latency = None

        return {
            **proxy,
            "success": True,
            "responseTime": latency,
            "target": result.get(
                "target",
                "www.youtube.com"
            ),
            "statusCode": result.get("statusCode"),
            "colo": result.get("colo")
        }

    except Exception as exc:

        return {
            **proxy,
            "success": False,
            "error": str(exc)
        }


# =====================================
# 智能并发检测
# 找到10个成功就不再提交新任务
# =====================================

def check_all(candidates):

    results = []
    next_index = 0
    success_count = 0
    worker_errors = 0

    total = len(candidates)

    logging.info("候选代理：%s", total)
    logging.info("并发数量：%s", MAX_WORKERS)
    logging.info("成功目标：%s", TARGET_SUCCESS)

    executor = ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    )

    pending = {}

    def submit_next():

        nonlocal next_index

        if next_index >= total:
            return False

        proxy = candidates[next_index]

        future = executor.submit(
            check_one,
            proxy
        )

        pending[future] = proxy

        next_index += 1

        return True

    try:

        # 先启动第一批
        for _ in range(
            min(MAX_WORKERS, total)
        ):
            submit_next()

        while pending:

            done, _ = wait(
                pending,
                return_when=FIRST_COMPLETED
            )

            for future in done:

                proxy = pending.pop(future)

                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        **proxy,
                        "success": False,
                        "error": str(exc)
                    }

                results.append(result)

                if result.get("success") is True:

                    success_count += 1

                    logging.info(
                        "[成功 %s/%s] %s://%s:%s | %s ms",
                        success_count,
                        TARGET_SUCCESS,
                        result["protocol"],
                        result["host"],
                        result["port"],
                        result.get("responseTime", "未知")
                    )

                else:

                    error = result.get("error", "")

                    if (
                        error.startswith("Worker HTTP")
                        or error.startswith("Worker JSON")
                    ):
                        worker_errors += 1

                    logging.info(
                        "[失败] %s://%s:%s",
                        proxy["protocol"],
                        proxy["host"],
                        proxy["port"]
                    )

            # 达到目标后不再提交新任务
            if success_count >= TARGET_SUCCESS:

                logging.info(
                    "已经找到 %s 个成功代理，停止提交新任务",
                    TARGET_SUCCESS
                )

                break

            # 只补充空出来的并发位置
            for _ in range(
                MAX_WORKERS - len(pending)
            ):

                if not submit_next():
                    break

    finally:

        # 取消尚未开始的任务
        for future in pending:
            future.cancel()

        executor.shutdown(
            wait=True,
            cancel_futures=True
        )

    logging.info(
        "本轮实际完成检测：%s 个",
        len(results)
    )

    logging.info(
        "成功代理：%s 个",
        success_count
    )

    return results, worker_errors


# =====================================
# 输出文件
# =====================================

def write_outputs(results, total, worker_errors):

    PUBLIC_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # 全部 Worker 请求异常时，不覆盖旧结果
    if total > 0 and worker_errors == len(results):

        logging.error(
            "Worker 请求全部异常，不覆盖旧文件"
        )

        return

    success_nodes = [
        item for item in results
        if item.get("success") is True
    ]

    success_nodes.sort(
        key=lambda item: (
            item["responseTime"]
            if item.get("responseTime") is not None
            else float("inf")
        )
    )

    data = {
        "updated_at": time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime()
        ),
        "target": "https://www.youtube.com/",
        "tested_count": len(results),
        "candidate_count": total,
        "success_count": len(success_nodes),
        "success_nodes": success_nodes
    }

    (PUBLIC_DIR / "data.json").write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    node_lines = []
    youtube_lines = []

    for node in success_nodes:

        address = (
            f'{node["protocol"]}://'
            f'{node["host"]}:{node["port"]}'
        )

        node_lines.append(address)

        latency = node.get("responseTime")

        latency_text = (
            f"{latency} ms"
            if latency is not None
            else "未知延迟"
        )

        youtube_lines.append(
            f"{address} # YouTube可访问 | {latency_text}"
        )

    (PUBLIC_DIR / "nodes.txt").write_text(
        "\n".join(node_lines) + (
            "\n" if node_lines else ""
        ),
        encoding="utf-8"
    )

    (PUBLIC_DIR / "youtube_ok.txt").write_text(
        "\n".join(youtube_lines) + (
            "\n" if youtube_lines else ""
        ),
        encoding="utf-8"
    )

    rows = []

    for index, node in enumerate(success_nodes, 1):

        address = (
            f'{node["protocol"]}://'
            f'{node["host"]}:{node["port"]}'
        )

        latency = node.get("responseTime")

        latency_text = (
            f"{latency} ms"
            if latency is not None
            else "未知"
        )

        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{html.escape(address)}</td>"
            f"<td>{html.escape(latency_text)}</td>"
            "<td style='color:green'>成功</td>"
            "</tr>"
        )

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YouTube代理检测</title>
<style>
body{{font-family:Arial;margin:25px;background:#f5f5f5}}
.box{{background:white;padding:20px;border-radius:8px}}
table{{width:100%;border-collapse:collapse}}
td,th{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}
</style>
</head>
<body>
<div class="box">
<h2>YouTube代理检测结果</h2>
<p>检测目标：www.youtube.com</p>
<p>实际检测数量：{len(results)}</p>
<p>成功数量：{len(success_nodes)}</p>
<p>更新时间：{html.escape(data["updated_at"])}</p>
<table>
<tr><th>序号</th><th>代理</th><th>Worker延迟</th><th>结果</th></tr>
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

    logging.info("输出完成")
    logging.info("成功代理：%s", len(success_nodes))


# =====================================
# 主程序
# =====================================

def main():

    start = time.time()

    logging.info("========== YouTube代理检测开始 ==========")

    logging.info(
        "Worker：%s",
        WORKER_BASE_URL
    )

    records = fetch_proxyscrape()

    candidates = normalize_candidates(records)

    logging.info(
        "可用协议候选：%s",
        len(candidates)
    )

    if not candidates:
        raise RuntimeError(
            "没有解析到 HTTP、HTTPS 或 SOCKS5 候选代理"
        )

    # 只取前100个
    candidates = candidates[:MAX_TEST_NODES]

    logging.info(
        "本轮最多测试：%s 个",
        len(candidates)
    )

    results, worker_errors = check_all(candidates)

    write_outputs(
        results,
        len(results),
        worker_errors
    )

    logging.info(
        "总耗时：%.1f 秒",
        time.time() - start
    )

    logging.info("========== 检测结束 ==========")


if __name__ == "__main__":
    main()
