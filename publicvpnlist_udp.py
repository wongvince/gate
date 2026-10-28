
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PublicVPNList UDP 候选采集器。

输出 public/udp_candidates.json。

仅收集 Hysteria2/TUIC 元数据，不代表节点已连通、
UDP 转发已验证或 PUBG 游戏可用。
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests

API = "https://publicvpnlist.com/api/v1/servers"
TOKEN = os.environ.get("PUBLICVPNLIST_TOKEN", "").strip()
OUT = Path(os.environ.get("PUBLIC_DIR", "public"))

PROTOCOLS = ("hysteria2", "tuic")
COUNTRIES = {"JP", "KR"}
PER_PAGE = 200
TIMEOUT = 25
MAX_PAGES = 20


def log(message):
    print(message, flush=True)


def fetch_pages(session, protocol):
    """按官方分页链接获取数据；不预先限制国家和状态。"""
    url = API
    params = {
        "protocol": protocol,
        "page": 1,
        "per_page": PER_PAGE,
        "sort": "last_checked",
        "order": "desc",
    }
    all_rows = []
    page_count = 0

    while url and page_count < MAX_PAGES:
        page_count += 1

        response = session.get(
            url,
            params=params if url == API else None,
            timeout=TIMEOUT,
        )

        log(f"[HTTP] protocol={protocol} page={page_count} "
            f"status={response.status_code}")
        log(f"[URL] {response.url}")

        if response.status_code == 401:
            raise RuntimeError("HTTP 401：API Token 缺失或已过期")
        if response.status_code == 403:
            raise RuntimeError("HTTP 403：API 拒绝请求，请检查访问权限")
        if response.status_code == 429:
            raise RuntimeError("HTTP 429：请求过于频繁，请稍后重试")

        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"响应不是有效 JSON：{response.text[:200]!r}"
            ) from exc

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"响应顶层不是 JSON 对象：{type(payload).__name__}"
            )

        log(f"[TOP_KEYS] {list(payload.keys())}")

        rows = payload.get("data")
        if not isinstance(rows, list):
            raise RuntimeError(
                "响应缺少列表型 data 字段；"
                f"顶层字段={list(payload.keys())}"
            )

        meta = payload.get("meta")
        links = payload.get("links")

        log(f"[META] {json.dumps(meta, ensure_ascii=False)}")
        log(f"[LINKS] {json.dumps(links, ensure_ascii=False)}")
        log(f"[ROWS] {len(rows)}")

        if rows and isinstance(rows[0], dict):
            log("[FIRST_ROW_FIELDS] "
                + json.dumps(list(rows[0].keys()), ensure_ascii=False))
            safe_keys = (
                "id", "protocol", "country_code", "country_name",
                "transport", "hostname", "ip", "port",
                "availability_status", "last_checked_at",
            )
            log("[FIRST_ROW_SAMPLE] " + json.dumps(
                {k: rows[0].get(k) for k in safe_keys if k in rows[0]},
                ensure_ascii=False,
            ))

        all_rows.extend(rows)

        next_url = links.get("next") if isinstance(links, dict) else None
        if not next_url:
            break

        # 只跟随官方返回的下一页链接。
        url = urljoin(API, str(next_url))
        params = None
        time.sleep(0.5)

    return all_rows


def main():
    if not TOKEN:
        log("[FATAL] 缺少 PUBLICVPNLIST_TOKEN 环境变量")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
        "User-Agent": "wongvince-gate-udp-collector/3.0",
    })

    candidates = {}
    errors = []
    stats = {
        "protocol_records": {},
        "jp_kr_records": 0,
        "rejected": {},
    }

    for protocol in PROTOCOLS:
        try:
            rows = fetch_pages(session, protocol)
            stats["protocol_records"][protocol] = len(rows)

            for row in rows:
                if not isinstance(row, dict):
                    stats["rejected"]["not_object"] = (
                        stats["rejected"].get("not_object", 0) + 1
                    )
                    continue

                actual_protocol = str(row.get("protocol") or "").lower()
                country = str(row.get("country_code") or "").strip().upper()
                country_name = str(row.get("country_name") or "").strip().lower()
                if not country:
                    if country_name in ("japan", "jp", "日本"):
                        country = "JP"
                    elif country_name in ("south korea", "korea, republic of", "korea", "kr", "韩国", "대한민국"):
                        country = "KR"

                if actual_protocol != protocol:
                    stats["rejected"]["protocol_mismatch"] = (
                        stats["rejected"].get("protocol_mismatch", 0) + 1
                    )
                    continue

                if country not in COUNTRIES:
                    continue

                stats["jp_kr_records"] += 1

                host = row.get("hostname") or row.get("ip")
                port_value = row.get("port")
                public_id = row.get("id")

                try:
                    port = int(port_value)
                except (TypeError, ValueError):
                    port = None

                if not host or not port or not 1 <= port <= 65535:
                    stats["rejected"]["missing_host_or_port"] = (
                        stats["rejected"].get("missing_host_or_port", 0) + 1
                    )
                    continue

                candidate_id = (
                    str(public_id) if public_id is not None
                    else f"{host}:{port}"
                )
                key = f"{protocol}:{country}:{candidate_id}"

                candidates[key] = {
                    "id": candidate_id,
                    "country_code": country,
                    "country_name": row.get("country_name"),
                    "protocol": protocol,
                    "transport": row.get("transport"),
                    "hostname": host,
                    "ip": row.get("ip"),
                    "port": port,
                    "latency_ms": row.get("latency_ms"),
                    "speed_mbps": row.get("speed_mbps"),
                    "availability_status": row.get("availability_status"),
                    "last_checked_at": row.get("last_checked_at"),
                    "config_updated_at": row.get("config_updated_at"),
                    "source": "PublicVPNList API v1",
                    "udp_tunnel_verified": False,
                    "game_tested": False,
                }

        except Exception as exc:
            message = f"{protocol}: {type(exc).__name__}: {exc}"
            errors.append(message)
            log("[ERROR] " + message)

    OUT.mkdir(parents=True, exist_ok=True)
    output_file = OUT / "udp_candidates.json"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "PublicVPNList API v1",
        "description": (
            "日本/韩国 Hysteria2、TUIC 候选元数据；"
            "未验证实际 UDP 隧道或 PUBG 游戏可用性"
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
    log(f"协议记录数量：{stats['protocol_records']}")
    log(f"日本/韩国记录数：{stats['jp_kr_records']}")
    log(f"最终候选数：{len(candidates)}")
    log(f"采集错误数：{len(errors)}")
    log(f"输出文件：{output_file}")
    log("=" * 50)

    if not stats["protocol_records"] and errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
