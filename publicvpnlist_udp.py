
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PublicVPNList UDP 候选节点采集器

输出：
    public/udp_candidates.json

注意：
    1. 本脚本只采集候选节点元数据。
    2. 不代表节点的 UDP 转发、代理连通性或 PUBG 游戏可用性已验证。
    3. 请在 GitHub Actions Secrets 中设置 PUBLICVPNLIST_TOKEN。
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


API = "https://publicvpnlist.com/api/v1/servers"

TOKEN = os.environ.get("PUBLICVPNLIST_TOKEN", "").strip()
OUT = Path(os.environ.get("PUBLIC_DIR", "public"))

TIMEOUT = 20
PER_PAGE = 100
MAX_PAGES = 20
FRESH_WITHIN = 86400

PROTOCOLS = ("hysteria2", "tuic")
COUNTRIES = ("JP", "KR")

USER_AGENT = "wongvince-gate-udp-checker/2.0"


def log(message):
    print(message, flush=True)


def get_first(row, *keys):
    """返回第一个非空字段。"""
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def extract_rows(payload):
    """
    从常见 JSON 响应结构提取记录。
    无法识别时抛错，避免把未知响应误认为零条数据。
    """
    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        raise RuntimeError(
            f"无法识别的 API 响应类型：{type(payload).__name__}"
        )

    # 常见格式：{"data": [...]}
    data = payload.get("data")
    if isinstance(data, list):
        return data

    # 常见格式：{"data": {"servers": [...]}}
    if isinstance(data, dict):
        for key in ("servers", "results", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return value

    # 其他常见格式
    for key in ("servers", "results", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return value

    raise RuntimeError(
        "无法识别 API 返回结构；"
        f"顶层字段：{list(payload.keys())}"
    )


def country_code_of(row):
    """兼容常见国家代码字段。"""
    value = get_first(
        row,
        "country_code",
        "countryCode",
        "country",
    )

    if isinstance(value, dict):
        value = get_first(value, "code", "country_code", "iso2")

    return str(value or "").strip().upper()


def protocol_of(row):
    return normalize_text(
        get_first(row, "protocol", "protocol_name", "type")
    )


def get_host(row):
    return get_first(
        row,
        "hostname",
        "host",
        "ip",
        "server",
    )


def get_port(row):
    value = get_first(row, "port", "server_port")

    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 1 <= port <= 65535:
        return port

    return None


def parse_candidate(row, expected_protocol, expected_country):
    """检查字段并生成标准化候选记录。"""
    if not isinstance(row, dict):
        return None, "记录不是 JSON 对象"

    actual_protocol = protocol_of(row)
    actual_country = country_code_of(row)

    # 只接受本次查询目标对应的协议和国家。
    if actual_protocol != expected_protocol:
        return None, "协议不匹配"

    if actual_country != expected_country:
        return None, "国家不匹配"

    host = get_host(row)
    port = get_port(row)
    public_id = get_first(row, "id", "server_id", "uuid")

    if not host:
        return None, "缺少主机名或 IP"

    if port is None:
        return None, "端口缺失或无效"

    # 不假定 API 一定提供 id；没有 id 时用主机和端口去重。
    candidate_id = (
        str(public_id)
        if public_id is not None
        else f"{host}:{port}"
    )

    candidate = {
        "id": candidate_id,
        "country_code": actual_country,
        "protocol": actual_protocol,
        "transport": get_first(row, "transport"),
        "hostname": str(host),
        "ip": get_first(row, "ip"),
        "port": port,
        "latency_ms": get_first(
            row, "latency_ms", "latency", "ping"
        ),
        "speed_mbps": get_first(
            row, "speed_mbps", "speed"
        ),
        "last_checked_at": get_first(
            row, "last_checked_at", "last_checked"
        ),
        "config_updated_at": get_first(
            row, "config_updated_at", "config_updated"
        ),
        "source": "PublicVPNList",
        "udp_tunnel_verified": False,
        "game_tested": False,
    }

    return candidate, None


def fetch_page(session, protocol, country, page):
    """请求一页数据，并输出诊断信息。"""
    params = {
        "protocol": protocol,
        "country": country,
        "status": "online",
        "fresh_within": FRESH_WITHIN,
        "page": page,
        "per_page": PER_PAGE,
        "sort": "last_checked",
        "order": "desc",
    }

    response = session.get(
        API,
        params=params,
        timeout=TIMEOUT,
    )

    log(
        f"[HTTP] {protocol}/{country}/page={page} "
        f"status={response.status_code}"
    )

    if response.status_code == 401:
        raise RuntimeError(
            "API Token 无效或已过期（HTTP 401）"
        )

    if response.status_code == 403:
        raise RuntimeError(
            "API 拒绝请求（HTTP 403），"
            "请检查 Token 权限和 API 使用限制"
        )

    if response.status_code == 429:
        raise RuntimeError(
            "API 请求限流（HTTP 429），"
            "请降低请求频率后重试"
        )

    response.raise_for_status()

    try:
        payload = response.json()
    except ValueError as exc:
        content_type = response.headers.get(
            "content-type", ""
        )
        preview = response.text[:200].replace("\n", " ")
        raise RuntimeError(
            f"API 未返回有效 JSON；"
            f"content-type={content_type!r}；"
            f"响应预览={preview!r}"
        ) from exc

    rows = extract_rows(payload)

    log(
        f"[DATA] {protocol}/{country}/page={page} "
        f"records={len(rows)}"
    )

    if rows and isinstance(rows[0], dict):
        log(
            "[FIELDS] "
            + ", ".join(str(key) for key in rows[0].keys())
        )

        summary_keys = (
            "id",
            "protocol",
            "country",
            "country_code",
            "transport",
            "hostname",
            "ip",
            "port",
        )
        summary = {
            key: rows[0].get(key)
            for key in summary_keys
            if key in rows[0]
        }
        log(
            "[FIRST_RECORD] "
            + json.dumps(summary, ensure_ascii=False)
        )

    return rows


def main():
    if not TOKEN:
        log("[FATAL] 缺少 PUBLICVPNLIST_TOKEN 环境变量")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    })

    candidates = {}
    errors = []
    stats = {
        "requests_ok": 0,
        "records_received": 0,
        "protocol_country_matches": 0,
        "candidates_added": 0,
        "records_rejected": {},
    }

    for protocol in PROTOCOLS:
        for country in COUNTRIES:
            for page in range(1, MAX_PAGES + 1):
                try:
                    rows = fetch_page(
                        session,
                        protocol,
                        country,
                        page,
                    )
                    stats["requests_ok"] += 1
                    stats["records_received"] += len(rows)

                    for row in rows:
                        candidate, reason = parse_candidate(
                            row,
                            protocol,
                            country,
                        )

                        if candidate is None:
                            stats["records_rejected"][reason] = (
                                stats["records_rejected"].get(
                                    reason, 0
                                ) + 1
                            )
                            continue

                        stats["protocol_country_matches"] += 1

                        key = (
                            f"{candidate['protocol']}:"
                            f"{candidate['country_code']}:"
                            f"{candidate['id']}"
                        )

                        if key not in candidates:
                            candidates[key] = candidate
                            stats["candidates_added"] += 1

                    # 返回记录少于每页上限，通常说明已到末页。
                    if len(rows) < PER_PAGE:
                        break

                    time.sleep(1)

                except Exception as exc:
                    message = (
                        f"{protocol}/{country}/page={page}: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    errors.append(message)
                    log("[ERROR] " + message)

                    # 当前查询失败，继续尝试其他协议和国家。
                    break

    OUT.mkdir(parents=True, exist_ok=True)
    output_file = OUT / "udp_candidates.json"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "PublicVPNList API v1",
        "description": (
            "UDP 协议候选节点清单；"
            "不代表 UDP 隧道、代理连通性或 PUBG 已验证可用"
        ),
        "candidate_count": len(candidates),
        "collection_errors": errors,
        "stats": stats,
        "candidates": list(candidates.values()),
    }

    output_file.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    log("=" * 50)
    log(f"请求成功数：{stats['requests_ok']}")
    log(f"API 返回记录总数：{stats['records_received']}")
    log(f"通过协议和国家检查：{stats['protocol_country_matches']}")
    log(f"最终候选数量：{len(candidates)}")
    log(f"采集错误数：{len(errors)}")
    log(f"输出文件：{output_file}")
    log("=" * 50)

    if stats["records_rejected"]:
        log(
            "[REJECTED] "
            + json.dumps(
                stats["records_rejected"],
                ensure_ascii=False,
            )
        )

    # 只有完全没有成功请求且所有请求都失败时才返回失败。
    # 成功请求但没有匹配节点时保留诊断 JSON，方便排查。
    if stats["requests_ok"] == 0 and errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
