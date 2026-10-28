
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PublicVPNList UDP 候选节点采集器

输出：
    public/udp_candidates.json

说明：
    - 采集 Hysteria2 和 TUIC 协议的候选记录。
    - 不预先按国家过滤，避免 API 国家字段缺失导致全部丢弃。
    - 国家未知的节点会标记为 unknown，不会冒充日本或韩国。
    - 采集成功不代表 UDP 隧道或 PUBG 游戏已经验证可用。
"""

import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests


API = "https://publicvpnlist.com/api/v1/servers"
TOKEN = os.environ.get("PUBLICVPNLIST_TOKEN", "").strip()
OUT = Path(os.environ.get("PUBLIC_DIR", "public"))

PROTOCOLS = ("hysteria2", "tuic")
TARGET_COUNTRIES = {"JP", "KR"}

PER_PAGE = 200
MAX_PAGES = 20
TIMEOUT = 25
USER_AGENT = "wongvince-gate-udp-collector/4.0"


def log(message):
    print(message, flush=True)


def first_value(row, *keys):
    """返回第一个存在且非空的字段。"""
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


def normalize_country(row):
    """
    返回国家代码。
    如果 API 没提供国家代码，尝试识别国家名称。
    无法确定时返回 None。
    """
    code = first_value(row, "country_code", "countryCode")

    if isinstance(code, str):
        code = code.strip().upper()
        if code:
            return code

    name = first_value(row, "country_name", "countryName")

    if isinstance(name, str):
        normalized = name.strip().lower()

        known_names = {
            "japan": "JP",
            "jp": "JP",
            "south korea": "KR",
            "republic of korea": "KR",
            "korea, republic of": "KR",
            "korea, republic of korea": "KR",
            "south korea (republic of korea)": "KR",
            "kr": "KR",
        }

        if normalized in known_names:
            return known_names[normalized]

    return None


def extract_rows(payload):
    """解析 API 的记录列表，并在结构异常时明确报错。"""
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"API 顶层不是 JSON 对象：{type(payload).__name__}"
        )

    rows = payload.get("data")

    if not isinstance(rows, list):
        raise RuntimeError(
            "API 没有返回列表型 data 字段；"
            f"顶层字段：{list(payload.keys())}"
        )

    return rows


def fetch_protocol(session, protocol):
    """获取一个协议的所有可访问分页。"""
    url = API
    params = {
        "protocol": protocol,
        "page": 1,
        "per_page": PER_PAGE,
        "sort": "last_checked",
        "order": "desc",
    }

    all_rows = []
    page = 0

    while url and page < MAX_PAGES:
        page += 1

        response = session.get(
            url,
            params=params if page == 1 else None,
            timeout=TIMEOUT,
        )

        log(
            f"[HTTP] protocol={protocol} page={page} "
            f"status={response.status_code}"
        )

        if response.status_code == 401:
            raise RuntimeError("HTTP 401：Token 无效或已过期")

        if response.status_code == 403:
            raise RuntimeError("HTTP 403：API 拒绝请求，请检查权限")

        if response.status_code == 429:
            raise RuntimeError("HTTP 429：API 请求限流")

        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"API 返回的不是有效 JSON：{response.text[:200]!r}"
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"API 响应类型异常：{type(payload).__name__}"
            )

        log(f"[TOP_KEYS] {list(payload.keys())}")

        meta = payload.get("meta")
        log(
            "[META] "
            + json.dumps(meta, ensure_ascii=False)
        )

        rows = extract_rows(payload)
        log(f"[ROWS] protocol={protocol} page={page} count={len(rows)}")

        if rows and isinstance(rows[0], dict):
            sample = rows[0]

            log(
                "[FIRST_ROW_FIELDS] "
                + json.dumps(list(sample.keys()), ensure_ascii=False)
            )

            sample_keys = (
                "id",
                "protocol",
                "country_code",
                "country_name",
                "city",
                "transport",
                "hostname",
                "ip",
                "port",
                "availability_status",
                "last_checked_at",
            )

            log(
                "[FIRST_ROW_SAMPLE] "
                + json.dumps(
                    {key: sample.get(key) for key in sample_keys},
                    ensure_ascii=False,
                )
            )

        all_rows.extend(rows)

        links = payload.get("links")
        next_link = (
            links.get("next")
            if isinstance(links, dict)
            else None
        )

        if not next_link:
            break

        url = urljoin(API, str(next_link))
        params = None
        time.sleep(0.5)

    return all_rows


def normalize_candidate(row, requested_protocol):
    """验证协议、主机和端口，转换为统一格式。"""
    if not isinstance(row, dict):
        return None, "invalid_record"

    protocol = str(
        first_value(row, "protocol") or requested_protocol
    ).strip().lower()

    if protocol != requested_protocol:
        return None, "protocol_mismatch"

    # Hysteria2/TUIC 是基于 UDP 的协议。
    # transport 是 API 的独立元数据，不用它作为唯一过滤依据。
    host = first_value(row, "hostname", "host", "ip")
    ip = first_value(row, "ip")
    hostname = first_value(row, "hostname", "host")
    port_value = first_value(row, "port", "server_port")

    if not host:
        return None, "missing_host"

    try:
        port = int(port_value)
    except (ValueError, TypeError):
        return None, "invalid_port"

    if not 1 <= port <= 65535:
        return None, "invalid_port"

    country_code = normalize_country(row)
    country_name = first_value(row, "country_name", "countryName")

    if country_code == "JP":
        region_status = "japan"
        target_match = True
    elif country_code == "KR":
        region_status = "south_korea"
        target_match = True
    elif country_code:
        region_status = "other_country"
        target_match = False
    else:
        region_status = "unknown"
        target_match = None

    public_id = first_value(row, "id", "server_id")
    candidate_id = (
        str(public_id)
        if public_id is not None
        else f"{protocol}:{host}:{port}"
    )

    candidate = {
        "id": candidate_id,
        "protocol": protocol,
        "transport": row.get("transport"),
        "transport_security": row.get("transport_security"),
        "country_code": country_code,
        "country_name": country_name,
        "city": row.get("city"),
        "region_status": region_status,
        "target_country_match": target_match,
        "hostname": hostname,
        "ip": ip,
        "port": port,
        "exit_ip": row.get("exit_ip"),
        "latency_ms": row.get("latency_ms"),
        "handshake_ms": row.get("handshake_ms"),
        "speed_mbps": row.get("speed_mbps"),
        "uptime_percent_7d": row.get("uptime_percent_7d"),
        "availability_status": row.get("availability_status"),
        "is_working": row.get("is_working"),
        "last_check_ok": row.get("last_check_ok"),
        "last_checked_at": row.get("last_checked_at"),
        "last_success_at": row.get("last_success_at"),
        "config_updated_at": row.get("config_updated_at"),
        "measurement_status": row.get("measurement_status"),
        "measurement_quality": row.get("measurement_quality"),
        "risk_flags": row.get("risk_flags"),
        "source": "PublicVPNList API v1",
        "udp_based_protocol": True,
        "udp_tunnel_verified": False,
        "game_tested": False,
    }

    return candidate, None


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
    rejection_counts = Counter()
    protocol_counts = Counter()
    country_counts = Counter()
    region_status_counts = Counter()

    successful_protocols = 0
    total_records = 0

    for protocol in PROTOCOLS:
        try:
            rows = fetch_protocol(session, protocol)
            successful_protocols += 1
            protocol_counts[protocol] = len(rows)
            total_records += len(rows)

            for row in rows:
                candidate, reason = normalize_candidate(row, protocol)

                if candidate is None:
                    rejection_counts[reason] += 1
                    continue

                country = candidate["country_code"] or "UNKNOWN"
                country_counts[country] += 1
                region_status_counts[candidate["region_status"]] += 1

                # 按协议、国家和节点 ID 去重。
                key = (
                    f"{candidate['protocol']}:"
                    f"{country}:"
                    f"{candidate['id']}"
                )
                candidates[key] = candidate

        except Exception as exc:
            message = f"{protocol}: {type(exc).__name__}: {exc}"
            errors.append(message)
            log("[ERROR] " + message)

    candidate_list = list(candidates.values())

    target_candidates = [
        item for item in candidate_list
        if item["target_country_match"] is True
    ]

    unknown_country_candidates = [
        item for item in candidate_list
        if item["target_country_match"] is None
    ]

    OUT.mkdir(parents=True, exist_ok=True)
    output_file = OUT / "udp_candidates.json"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "PublicVPNList API v1",
        "description": (
            "Hysteria2/TUIC UDP 候选节点。"
            "只有国家字段明确为 JP/KR 时才标记为目标地区；"
            "UNKNOWN 节点不代表日本或韩国节点。"
            "所有节点均未由本脚本验证 UDP 隧道或 PUBG 可用性。"
        ),
        "candidate_count": len(candidate_list),
        "target_country_candidate_count": len(target_candidates),
        "unknown_country_candidate_count": len(unknown_country_candidates),
        "collection_errors": errors,
        "stats": {
            "api_records_total": total_records,
            "successful_protocol_queries": successful_protocols,
            "protocol_counts": dict(protocol_counts),
            "country_counts": dict(country_counts),
            "region_status_counts": dict(region_status_counts),
            "rejected_records": dict(rejection_counts),
        },
        "candidates": candidate_list,
        "target_country_candidates": target_candidates,
        "unknown_country_candidates": unknown_country_candidates,
    }

    output_file.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    log("=" * 55)
    log(f"[SUMMARY] API 原始记录总数：{total_records}")
    log(f"[SUMMARY] 各协议记录：{dict(protocol_counts)}")
    log(f"[SUMMARY] 国家记录统计：{dict(country_counts)}")
    log(f"[SUMMARY] 区域分类统计：{dict(region_status_counts)}")
    log(f"[SUMMARY] 有效候选总数：{len(candidate_list)}")
    log(f"[SUMMARY] 明确日本/韩国候选：{len(target_candidates)}")
    log(f"[SUMMARY] 国家未知候选：{len(unknown_country_candidates)}")
    log(f"[SUMMARY] 无效记录统计：{dict(rejection_counts)}")
    log(f"[SUMMARY] 采集错误数：{len(errors)}")
    log(f"[OUTPUT] {output_file}")
    log("=" * 55)

    # 所有协议查询均失败时让 GitHub Actions 明确报错。
    if successful_protocols == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
