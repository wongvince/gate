
#!/usr/bin/env python3
"""PublicVPNList UDP 候选节点采集器。

输出：
  public/udp_candidates.json

注意：
  只采集候选元数据，不代表 UDP 隧道或 PUBG 已验证可用。
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
PER_PAGE = 50
MAX_PAGES = 20
FRESH_WITHIN = 86400
PROTOCOLS = ("hysteria2", "tuic")
COUNTRIES = {"JP", "KR"}


def log(message):
    print(message, flush=True)


def main():
    if not TOKEN:
        raise RuntimeError("缺少 PUBLICVPNLIST_TOKEN 环境变量")

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json",
        "User-Agent": "wongvince-gate-udp-checker/1.0",
    })

    candidates = {}
    errors = []

    for protocol in PROTOCOLS:
        for country in sorted(COUNTRIES):
            for page in range(1, MAX_PAGES + 1):
                params = {
                    "protocol": protocol,
                    "transport": "udp",
                    "country": country,
                    "status": "online",
                    "fresh_within": FRESH_WITHIN,
                    "page": page,
                    "per_page": PER_PAGE,
                    "sort": "last_checked",
                    "order": "desc",
                }

                try:
                    response = session.get(
                        API, params=params, timeout=TIMEOUT
                    )

                    if response.status_code == 401:
                        raise RuntimeError(
                            "API 密钥无效或已过期（HTTP 401）"
                        )
                    if response.status_code == 429:
                        raise RuntimeError(
                            "API 请求限流（HTTP 429）"
                        )

                    response.raise_for_status()
                    payload = response.json()
                    rows = payload.get("data", [])

                    if not isinstance(rows, list):
                        raise RuntimeError("API data 字段不是列表")

                    log(
                        f"{protocol}/{country}/page={page}: "
                        f"{len(rows)} 条"
                    )

                    for row in rows:
                        if not isinstance(row, dict):
                            continue

                        # 二次校验返回数据，避免把其他协议混入。
                        if row.get("protocol") != protocol:
                            continue
                        if row.get("country_code") not in COUNTRIES:
                            continue
                        if row.get("country_code") != country:
                            continue
                        if row.get("transport") != "udp":
                            continue

                        public_id = row.get("id")
                        host = row.get("hostname") or row.get("ip")
                        port = row.get("port")

                        if public_id is None or not host or not port:
                            continue

                        try:
                            port = int(port)
                        except (ValueError, TypeError):
                            continue

                        if not 1 <= port <= 65535:
                            continue

                        key = f"{protocol}:{public_id}"
                        candidates[key] = {
                            "id": public_id,
                            "country_code": country,
                            "protocol": protocol,
                            "transport": row.get("transport"),
                            "hostname": host,
                            "ip": row.get("ip"),
                            "port": port,
                            "latency_ms": row.get("latency_ms"),
                            "speed_mbps": row.get("speed_mbps"),
                            "last_checked_at": row.get(
                                "last_checked_at"
                            ),
                            "config_updated_at": row.get(
                                "config_updated_at"
                            ),
                            "source": "PublicVPNList",
                            "udp_tunnel_verified": False,
                            "game_tested": False,
                        }

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
                    break

    OUT.mkdir(parents=True, exist_ok=True)
    output_file = OUT / "udp_candidates.json"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "PublicVPNList API v1",
        "description": (
            "候选节点清单；不代表 UDP 隧道或游戏已验证可用"
        ),
        "candidate_count": len(candidates),
        "collection_errors": errors,
        "candidates": list(candidates.values()),
    }

    output_file.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    log(f"候选数量：{len(candidates)}")
    log(f"采集错误：{len(errors)}")
    log(f"输出文件：{output_file}")

    # 所有查询都失败时让 GitHub Actions 明确报错。
    if errors and not candidates:
        sys.exit(1)


if __name__ == "__main__":
    main()
