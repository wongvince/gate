#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
从 ProxyScraper 获取 SOCKS5 公共代理，
再通过现有 Cloudflare Worker 检查是否能访问 YouTube。
只输出 Worker 实际检测成功的代理。

注意：
1. 公共免费代理不可信，不要用于登录账号或传输隐私数据。
2. Worker 检测成功只代表检测时能访问 YouTube，不代表 PUBG 一定可用。
3. v2rayn.txt 是 SOCKS5 URI 清单，不是 VLESS/VMess/Trojan 订阅。
"""

import json
import logging
import math
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests


# -------------------- 基本设置 --------------------

SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://api.proxyscraper.com/v1/socks5.json"
)

# 现有 Worker 的兼容入口，必须以 proxy= 结尾，或包含 {config}
WORKER_CHECK_URL = os.getenv(
    "WORKER_CHECK_URL",
    "https://wong.wong123.ccwu.cc/check?proxy="
)

SOURCE_MAX_LATENCY_MS = int(os.getenv("SOURCE_MAX_LATENCY_MS", "5000"))
WORKER_MAX_LATENCY = float(os.getenv("WORKER_MAX_LATENCY", "3000"))
CHECK_CONCURRENCY = max(1, int(os.getenv("CHECK_CONCURRENCY", "5")))
MAX_CHECK_NODES = max(1, int(os.getenv("MAX_CHECK_NODES", "100")))

HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "20"))
WORKER_TIMEOUT = int(os.getenv("WORKER_TIMEOUT", "40"))

# 留空表示不按国家过滤；例如只要日本和韩国可设置 JP,KR
COUNTRY_CODES = {
    item.strip().upper()
    for item in os.getenv("COUNTRY_CODES", "").split(",")
    if item.strip()
}

PUBLIC_DIR = os.getenv("PUBLIC_DIR", "public")
JSON_OUTPUT = os.path.join(PUBLIC_DIR, "tcp_candidates.json")
TEXT_OUTPUT = os.path.join(PUBLIC_DIR, "v2rayn.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("publicvpnlist")


# -------------------- 获取来源节点 --------------------

def fetch_source_nodes():
    """获取 ProxyScraper SOCKS5 JSON 数据并进行基础过滤。"""
    params = {
        "min_uptime": 50,
        "max_latency": SOURCE_MAX_LATENCY_MS,
    }
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 PublicVPNList-Checker/1.0",
    }

    log.info("正在获取 SOCKS5 来源：%s", SOURCE_URL)

    response = requests.get(
        SOURCE_URL,
        params=params,
        headers=headers,
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()

    try:
        payload = response.json()
    except ValueError as exc:
        preview = response.text[:200].replace("\n", " ")
        raise RuntimeError(
            f"来源没有返回有效 JSON；HTTP={response.status_code}；"
            f"Content-Type={response.headers.get('Content-Type', '')}；"
            f"响应开头={preview!r}"
        ) from exc

    if isinstance(payload, dict):
        raw_nodes = payload.get("proxies")
        snapshot = payload.get("snapshot") or payload.get("generation")
    elif isinstance(payload, list):
        # 兼容来源直接返回数组的情况
        raw_nodes = payload
        snapshot = None
    else:
        raise RuntimeError("来源 JSON 顶层格式不正确")

    if not isinstance(raw_nodes, list):
        keys = list(payload.keys()) if isinstance(payload, dict) else []
        raise RuntimeError(f"来源 JSON 中没有有效的 proxies 数组；顶层字段：{keys}")

    candidates = []
    seen = set()

    for item in raw_nodes:
        if not isinstance(item, dict):
            continue

        ip = str(item.get("ip") or "").strip()
        port_value = item.get("port")
        protocol = str(item.get("protocol") or "socks5").strip().lower()

        try:
            port = int(port_value)
        except (TypeError, ValueError):
            continue

        if not ip or not (1 <= port <= 65535):
            continue

        # 此脚本只处理 SOCKS5，不把其他协议伪装成 SOCKS5。
        if protocol not in ("socks5", "socks5h", "socks"):
            continue

        try:
            source_latency = float(item.get("latency_ms"))
        except (TypeError, ValueError):
            source_latency = None

        if source_latency is not None:
            if not math.isfinite(source_latency) or source_latency < 0:
                continue
            if source_latency > SOURCE_MAX_LATENCY_MS:
                continue

        country = str(item.get("country") or "").strip().upper()
        if COUNTRY_CODES and country not in COUNTRY_CODES:
            continue

        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)

        candidates.append({
            "ip": ip,
            "port": port,
            "protocol": "socks5",
            "country": country or None,
            "source_latency_ms": source_latency,
            "last_checked": item.get("last_checked"),
            "uptime_24h": item.get("uptime_24h"),
            "uptime_7d": item.get("uptime_7d"),
            "exit_ip": item.get("exit_ip"),
            "asn": item.get("asn"),
            "asn_name": item.get("asn_name"),
            "network_type": item.get("network_type"),
            "address": f"{ip}:{port}",
        })

    candidates.sort(
        key=lambda node: (
            node["source_latency_ms"] is None,
            node["source_latency_ms"] if node["source_latency_ms"] is not None else 999999,
        )
    )

    candidates = candidates[:MAX_CHECK_NODES]

    log.info("来源记录数：%s", len(raw_nodes))
    log.info("过滤去重后候选数：%s", len(candidates))
    log.info("来源快照：%s", snapshot or "未提供")

    return candidates, snapshot


# -------------------- Worker 检测 --------------------

def make_worker_url(proxy_uri):
    encoded = quote(proxy_uri, safe="")

    if "{config}" in WORKER_CHECK_URL:
        return WORKER_CHECK_URL.replace("{config}", encoded)

    if WORKER_CHECK_URL.endswith("="):
        return WORKER_CHECK_URL + encoded

    raise ValueError(
        "WORKER_CHECK_URL 必须以 proxy= 结尾，或包含 {config}"
    )


def check_one(node):
    """通过 Worker 检测一个 SOCKS5 代理。"""
    proxy_uri = f"socks5://{node['ip']}:{node['port']}"
    url = make_worker_url(proxy_uri)

    try:
        response = requests.get(
            url,
            headers={"Accept": "application/json"},
            timeout=WORKER_TIMEOUT,
        )

        if response.status_code != 200:
            return None, f"Worker HTTP {response.status_code}"

        try:
            result = response.json()
        except ValueError:
            return None, "Worker 返回的不是 JSON"

        if not isinstance(result, dict):
            return None, "Worker JSON 格式不正确"

        if result.get("success") is not True:
            return None, str(result.get("error") or "Worker 检测失败")[:160]

        try:
            response_time = float(result.get("responseTime"))
        except (TypeError, ValueError):
            return None, "Worker responseTime 缺失或无效"

        if not math.isfinite(response_time) or response_time < 0:
            return None, "Worker responseTime 数值无效"

        if response_time > WORKER_MAX_LATENCY:
            return None, f"Worker 延迟超过上限：{response_time:.0f}ms"

        saved = dict(node)
        saved.update({
            "proxy_uri": proxy_uri,
            "responseTime": response_time,
            "success": True,
            "worker_colo": result.get("colo"),
            "worker_exit": result.get("exit"),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })
        return saved, None

    except requests.Timeout:
        return None, "请求 Worker 超时"
    except requests.RequestException as exc:
        return None, f"请求异常：{type(exc).__name__}"
    except Exception as exc:
        return None, f"检测异常：{type(exc).__name__}"


def check_all(nodes):
    successful = []
    failures = {}

    if not nodes:
        return successful, failures

    log.info(
        "开始 Worker 检测：%s 个节点；并发数：%s",
        len(nodes),
        CHECK_CONCURRENCY,
    )

    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as pool:
        futures = [pool.submit(check_one, node) for node in nodes]

        for done, future in enumerate(as_completed(futures), start=1):
            try:
                result, error = future.result()

                if result:
                    successful.append(result)
                    log.info(
                        "[成功] %s，Worker 延迟 %.0f ms",
                        result["address"],
                        result["responseTime"],
                    )
                else:
                    reason = error or "未知失败"
                    failures[reason] = failures.get(reason, 0) + 1

            except Exception as exc:
                reason = f"任务异常：{type(exc).__name__}"
                failures[reason] = failures.get(reason, 0) + 1

            if done % 10 == 0 or done == len(nodes):
                log.info(
                    "检测进度：%s/%s，成功：%s",
                    done,
                    len(nodes),
                    len(successful),
                )

    successful.sort(key=lambda node: node["responseTime"])
    return successful, failures


# -------------------- 保存结果 --------------------

def write_outputs(nodes, snapshot, candidate_count, failures):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "ProxyScraper",
        "source_url": SOURCE_URL.split("?")[0],
        "source_snapshot": snapshot,
        "protocol": "socks5",
        "worker_target": "https://www.youtube.com/",
        "source_max_latency_ms": SOURCE_MAX_LATENCY_MS,
        "worker_max_latency_ms": WORKER_MAX_LATENCY,
        "candidate_count": candidate_count,
        "success_count": len(nodes),
        "failure_count": max(0, candidate_count - len(nodes)),
        "failure_reasons": failures,
        "nodes": nodes,
    }

    with open(JSON_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)

    # 这是 SOCKS5 URI 清单，不是标准 V2Ray 分享链接订阅。
    with open(TEXT_OUTPUT, "w", encoding="utf-8") as file:
        for node in nodes:
            file.write(node["proxy_uri"] + "\n")

    log.info("JSON 输出：%s", JSON_OUTPUT)
    log.info("SOCKS5 URI 清单输出：%s", TEXT_OUTPUT)


# -------------------- 主程序 --------------------

def main():
    log.info("========== SOCKS5 公共代理检测 ==========")
    log.info("节点来源：ProxyScraper")
    log.info("协议：SOCKS5")
    log.info("来源延迟上限：%s ms", SOURCE_MAX_LATENCY_MS)
    log.info("Worker 延迟上限：%s ms", WORKER_MAX_LATENCY)
    log.info("检测数量上限：%s", MAX_CHECK_NODES)
    log.info(
        "国家过滤：%s",
        ", ".join(sorted(COUNTRY_CODES)) if COUNTRY_CODES else "不限制",
    )

    if not WORKER_CHECK_URL:
        log.error("缺少 WORKER_CHECK_URL")
        sys.exit(1)

    if "{config}" not in WORKER_CHECK_URL and not WORKER_CHECK_URL.endswith("="):
        log.error("WORKER_CHECK_URL 必须以 = 结尾，或包含 {config}")
        sys.exit(1)

    try:
        candidates, snapshot = fetch_source_nodes()
    except Exception as exc:
        log.exception("获取 SOCKS5 来源失败：%s", type(exc).__name__)
        sys.exit(1)

    if not candidates:
        log.warning("没有找到符合条件的 SOCKS5 候选节点")
        write_outputs([], snapshot, 0, {})
        return

    successful, failures = check_all(candidates)
    write_outputs(successful, snapshot, len(candidates), failures)

    log.info("========== 检测完成 ==========")
    log.info(
        "候选节点：%s；成功节点：%s；失败节点：%s",
        len(candidates),
        len(successful),
        len(candidates) - len(successful),
    )

    if failures:
        log.info("失败原因统计：")
        for reason, count in sorted(
            failures.items(),
            key=lambda item: -item[1],
        )[:10]:
            log.info("  %s：%s", reason, count)

    if successful:
        log.info(
            "最低 Worker 延迟：%.0f ms",
            successful[0]["responseTime"],
        )
    else:
        log.warning("没有代理通过 Worker 检测；输出文件中的 nodes 将为空。")


if __name__ == "__main__":
    main()
