
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PublicVPNList TCP 节点筛选器

流程：
1. 从 PublicVPNList 获取 TCP 节点
2. 只筛选 VLESS / Trojan / VMess / Shadowsocks
3. 先按数据源延迟过滤
4. 获取每个节点的完整配置 URI
5. 把完整 URI 交给 Cloudflare Worker 检测
6. 只保留 Worker success=true 且 responseTime 有效的节点
7. 按 Worker responseTime 从低到高排序
8. 输出 public/tcp_candidates.json 和 public/v2rayn.txt

注意：
- 不会把 API Token 或节点配置打印到日志
- 不会把 API 原始延迟当成最终延迟
- 只保留 Worker 实际检测成功的节点
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urljoin

import requests


# ============================================================
# 配置
# ============================================================

API_BASE = "https://publicvpnlist.com/api/v1"
API_SERVERS = f"{API_BASE}/servers"

# GitHub Secrets 中设置 PUBLICVPNLIST_TOKEN
API_TOKEN = os.getenv("PUBLICVPNLIST_TOKEN", "").strip()

# Worker 地址必须以等号结尾，例如：
# https://你的域名/check?proxy=
#
# 也支持 {config} 模板：
# https://你的域名/check?proxy={config}
WORKER_CHECK_URL = os.getenv(
    "WORKER_CHECK_URL",
    ""
).strip()

# 数据源预筛选延迟上限
API_MAX_LATENCY = int(os.getenv("API_MAX_LATENCY", "300"))

# Worker 实测延迟上限
WORKER_MAX_LATENCY = int(os.getenv("WORKER_MAX_LATENCY", "300"))

# 只检查最近多少秒更新的节点
FRESH_WITHIN = int(os.getenv("FRESH_WITHIN", "86400"))

# 每种协议最多读取多少页
MAX_PAGES = int(os.getenv("MAX_PAGES", "10"))

# Worker 并发数
CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "8"))

# HTTP 超时
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "25"))
WORKER_TIMEOUT = int(os.getenv("WORKER_TIMEOUT", "40"))

# 每次运行最多检测多少个候选节点
MAX_CHECK_NODES = int(os.getenv("MAX_CHECK_NODES", "200"))

# 可选国家过滤，例如 JP,KR
# 留空表示不限制国家
COUNTRY_CODES = [
    x.strip().upper()
    for x in os.getenv("COUNTRY_CODES", "").split(",")
    if x.strip()
]

# TCP 协议白名单
PROTOCOLS = (
    "vless",
    "trojan",
    "vmess",
    "shadowsocks",
)

PUBLIC_DIR = os.getenv("PUBLIC_DIR", "public")

JSON_OUTPUT = os.path.join(PUBLIC_DIR, "tcp_candidates.json")
V2RAYN_OUTPUT = os.path.join(PUBLIC_DIR, "v2rayn.txt")

USER_AGENT = "PublicVPNList-TCP-Checker/1.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger("publicvpnlist")


# ============================================================
# HTTP 请求
# ============================================================

_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        _thread_local.session = session

    return _thread_local.session


def request_json(url, headers=None, params=None, timeout=None):
    """
    请求 JSON，遇到 429 或临时错误时自动重试。
    """
    session = get_session()

    for attempt in range(5):
        try:
            response = session.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout or HTTP_TIMEOUT,
            )

            if response.status_code == 429:
                wait_time = min(5 * (attempt + 1), 30)
                log.warning("API 请求频率受限，等待 %s 秒后重试", wait_time)
                time.sleep(wait_time)
                continue

            if response.status_code in (500, 502, 503, 504):
                time.sleep(min(3 * (attempt + 1), 15))
                continue

            response.raise_for_status()
            return response.json()

        except requests.RequestException as exc:
            if attempt == 4:
                log.warning("请求失败：%s", type(exc).__name__)
                return None

            time.sleep(min(2 * (attempt + 1), 10))

        except ValueError:
            log.warning("服务器返回的内容不是有效 JSON")
            return None

    return None


# ============================================================
# 获取 API 节点
# ============================================================

def api_headers():
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def fetch_protocol(protocol):
    """
    获取某一种协议的 TCP 节点。
    """
    all_records = []

    for page in range(1, MAX_PAGES + 1):
        params = {
            "protocol": protocol,
            "transport": "tcp",
            "status": "online",
            "max_latency": API_MAX_LATENCY,
            "fresh_within": FRESH_WITHIN,
            "sort": "latency",
            "order": "asc",
            "page": page,
            "per_page": 200,
        }

        if COUNTRY_CODES:
            # 单次 API 请求只传一个国家；
            # 多国家由外层逻辑分别请求。
            pass

        payload = request_json(
            API_SERVERS,
            headers=api_headers(),
            params=params,
        )

        if not payload:
            break

        records = payload.get("data", [])

        if not isinstance(records, list) or not records:
            break

        for item in records:
            if not isinstance(item, dict):
                continue

            item_protocol = str(item.get("protocol", "")).lower()
            item_transport = str(item.get("transport", "")).lower()

            if item_protocol != protocol:
                continue

            # 严格只保留 TCP
            if item_transport != "tcp":
                continue

            if COUNTRY_CODES:
                country = str(item.get("country_code") or "").upper()
                if country not in COUNTRY_CODES:
                    continue

            all_records.append(item)

        if len(records) < 200:
            break

    log.info("%s：获取到 %s 条 TCP 记录", protocol, len(all_records))
    return all_records


def fetch_all_candidates():
    candidates = []

    for protocol in PROTOCOLS:
        records = fetch_protocol(protocol)
        candidates.extend(records)

    # 按节点 ID 去重
    unique = {}
    for item in candidates:
        node_id = str(item.get("id") or "")
        if node_id:
            unique[node_id] = item

    result = list(unique.values())

    # 再按数据源延迟排序
    result.sort(
        key=lambda x: (
            float(x.get("latency_ms"))
            if x.get("latency_ms") is not None
            else 999999
        )
    )

    if MAX_CHECK_NODES > 0:
        result = result[:MAX_CHECK_NODES]

    log.info("TCP 候选节点总数：%s", len(result))
    return result


# ============================================================
# 获取完整配置 URI
# ============================================================

def extract_config_uri(payload):
    """
    从 connection_info_url 返回内容中提取真实配置 URI。
    兼容常见的 JSON 嵌套结构。
    """
    if not isinstance(payload, dict):
        return None

    possible_keys = (
        "config_uri",
        "uri",
        "v2rayng_url",
    )

    for key in possible_keys:
        value = payload.get(key)
        if isinstance(value, str) and "://" in value:
            return value.strip()

    for key in ("data", "connection", "config", "result"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            value = extract_config_uri(nested)
            if value:
                return value

    return None


def fetch_config_uri(node):
    """
    使用 API 返回的 connection_info_url 获取配置。
    不猜测 UUID、密码、TLS、SNI 等参数。
    """
    info_url = node.get("connection_info_url")

    if not info_url:
        return None

    info_url = urljoin(API_BASE + "/", str(info_url))

    payload = request_json(
        info_url,
        headers=api_headers(),
    )

    if not payload:
        return None

    uri = extract_config_uri(payload)

    if not uri:
        return None

    protocol = str(node.get("protocol", "")).lower()

    expected_schemes = {
        "vless": ("vless://",),
        "trojan": ("trojan://",),
        "vmess": ("vmess://",),
        "shadowsocks": ("ss://", "shadowsocks://"),
    }

    allowed = expected_schemes.get(protocol, ())

    if not uri.lower().startswith(allowed):
        return None

    return uri


# ============================================================
# Cloudflare Worker 检测
# ============================================================

def build_worker_url(config_uri):
    """
    将完整配置 URI 交给 Worker。

    支持两种配置方式：

    方式 A：
    WORKER_CHECK_URL=https://域名/check?proxy=

    方式 B：
    WORKER_CHECK_URL=https://域名/check?proxy={config}
    """
    encoded = quote(config_uri, safe="")

    if "{config}" in WORKER_CHECK_URL:
        return WORKER_CHECK_URL.replace("{config}", encoded)

    return WORKER_CHECK_URL + encoded


def check_one(node):
    """
    Worker 必须返回：
    {
        "success": true,
        "responseTime": 123
    }

    只有 success=true 且 responseTime 有效才算成功。
    """
    protocol = str(node.get("protocol", "")).lower()

    try:
        config_uri = fetch_config_uri(node)

        if not config_uri:
            return None

        check_url = build_worker_url(config_uri)

        response = get_session().get(
            check_url,
            timeout=WORKER_TIMEOUT,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )

        if response.status_code != 200:
            return None

        try:
            result = response.json()
        except ValueError:
            return None

        if not isinstance(result, dict):
            return None

        if result.get("success") is not True:
            return None

        response_time = result.get("responseTime")

        try:
            response_time = float(response_time)
        except (TypeError, ValueError):
            return None

        if response_time < 0:
            return None

        if response_time > WORKER_MAX_LATENCY:
            return None

        # 必须存在可导入的完整 URI
        if not config_uri or "://" not in config_uri:
            return None

        # 不把配置 URI 写入日志
        return {
            "id": node.get("id"),
            "protocol": protocol,
            "transport": "tcp",
            "country_code": node.get("country_code"),
            "country_name": node.get("country_name"),
            "city": node.get("city"),
            "hostname": node.get("hostname"),
            "ip": node.get("ip"),
            "port": node.get("port"),

            # 数据源检测延迟，仅供参考
            "source_latency_ms": node.get("latency_ms"),

            # Worker 实际检测延迟
            "responseTime": response_time,

            "success": True,
            "config_uri": config_uri,
            "server_page_url": node.get("server_page_url"),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    except requests.Timeout:
        return None

    except requests.RequestException:
        return None

    except Exception as exc:
        log.warning(
            "%s 节点检测异常：%s",
            protocol,
            type(exc).__name__,
        )
        return None


def check_all(nodes):
    successful = []

    if not nodes:
        return successful

    log.info("开始 Worker 检测，共 %s 个候选节点", len(nodes))

    with ThreadPoolExecutor(
        max_workers=CHECK_CONCURRENCY
    ) as executor:

        futures = {
            executor.submit(check_one, node): node
            for node in nodes
        }

        completed = 0

        for future in as_completed(futures):
            completed += 1

            try:
                result = future.result()

                if result:
                    successful.append(result)
                    log.info(
                        "[成功] %s %s:%s 延迟 %.0f ms",
                        result["protocol"],
                        result.get("hostname") or result.get("ip"),
                        result.get("port"),
                        result["responseTime"],
                    )

            except Exception:
                pass

            if completed % 10 == 0 or completed == len(futures):
                log.info(
                    "检测进度：%s/%s，成功：%s",
                    completed,
                    len(futures),
                    len(successful),
                )

    successful.sort(key=lambda x: x["responseTime"])
    return successful


# ============================================================
# 输出文件
# ============================================================

def write_outputs(nodes):
    os.makedirs(PUBLIC_DIR, exist_ok=True)

    # JSON 输出
    json_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "PublicVPNList",
        "transport": "tcp",
        "protocols": list(PROTOCOLS),
        "api_max_latency_ms": API_MAX_LATENCY,
        "worker_max_latency_ms": WORKER_MAX_LATENCY,
        "candidate_count": len(nodes),
        "nodes": nodes,
    }

    with open(JSON_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(
            json_data,
            file,
            ensure_ascii=False,
            indent=2,
        )

    # v2rayN URI 订阅
    with open(V2RAYN_OUTPUT, "w", encoding="utf-8") as file:
        for node in nodes:
            uri = node.get("config_uri")
            if uri:
                file.write(uri.strip() + "\n")

    log.info("JSON 输出：%s", JSON_OUTPUT)
    log.info("v2rayN 输出：%s", V2RAYN_OUTPUT)


# ============================================================
# 主程序
# ============================================================

def main():
    log.info("========== PublicVPNList TCP ==========")

    if not API_TOKEN:
        log.error("缺少 PUBLICVPNLIST_TOKEN")
        sys.exit(1)

    if not WORKER_CHECK_URL:
        log.error("缺少 WORKER_CHECK_URL")
        sys.exit(1)

    if (
        "{config}" not in WORKER_CHECK_URL
        and not WORKER_CHECK_URL.endswith("=")
    ):
        log.error(
            "WORKER_CHECK_URL 必须以 = 结尾，"
            "或者包含 {config} 占位符"
        )
        sys.exit(1)

    log.info("协议：%s", ", ".join(PROTOCOLS))
    log.info("传输：TCP")
    log.info("数据源延迟上限：%s ms", API_MAX_LATENCY)
    log.info("Worker 延迟上限：%s ms", WORKER_MAX_LATENCY)

    if COUNTRY_CODES:
        log.info("国家限制：%s", ", ".join(COUNTRY_CODES))
    else:
        log.info("国家限制：不限制")

    candidates = fetch_all_candidates()

    if not candidates:
        log.warning("没有找到符合条件的 TCP 候选节点")
        write_outputs([])
        return

    successful = check_all(candidates)

    write_outputs(successful)

    log.info("========== 检测完成 ==========")
    log.info("候选节点：%s", len(candidates))
    log.info("成功节点：%s", len(successful))
    log.info("失败节点：%s", len(candidates) - len(successful))

    if successful:
        log.info(
            "最低 Worker 延迟：%.0f ms",
            successful[0]["responseTime"],
        )
    else:
        log.warning("本次没有检测成功的节点")


if __name__ == "__main__":
    main()
