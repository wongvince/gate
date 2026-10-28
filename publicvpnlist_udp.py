
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PublicVPNList UDP candidate collector.

Outputs:
  public/udp_candidates.json  - metadata only; no node credentials
  public/v2rayn.txt           - Base64-encoded v2rayN subscription

Required environment:
  PUBLICVPNLIST_TOKEN

Important:
  - Never invent credentials or TLS parameters.
  - Only export complete hysteria2:// or tuic:// share URIs
    returned by PublicVPNList.
  - A structurally valid URI does not guarantee PUBG connectivity.
"""

import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import requests


API_BASE = "https://publicvpnlist.com/api/v1"
PROTOCOLS = ("hysteria2", "tuic")
PUBLIC_DIR = Path(os.getenv("PUBLIC_DIR", "public"))
JSON_OUTPUT = PUBLIC_DIR / "udp_candidates.json"
SUB_OUTPUT = PUBLIC_DIR / "v2rayn.txt"

TOKEN = os.getenv("PUBLICVPNLIST_TOKEN", "").strip()
TIMEOUT = 20
REQUEST_PAUSE_SECONDS = 1.1
USER_AGENT = "wongvince-gate-udp-collector/2.0"

SESSION = requests.Session()
SESSION.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json",
    "User-Agent": USER_AGENT,
})


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_request(url, *, params=None, expect_json=False):
    """Request without logging credential-bearing URLs or response bodies."""
    try:
        response = SESSION.get(
            url,
            params=params,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "")
            try:
                wait = min(max(int(retry_after), 2), 60)
            except (TypeError, ValueError):
                wait = 10
            print(f"[WARN] API 限流，等待 {wait} 秒")
            time.sleep(wait)
            response = SESSION.get(
                url, params=params, timeout=TIMEOUT,
                allow_redirects=True,
            )

        response.raise_for_status()
        if expect_json:
            return response.json()
        return response

    except requests.RequestException as exc:
        # Do not print the complete URL; it might contain access tokens.
        print(f"[WARN] 请求失败：{type(exc).__name__}")
    except ValueError:
        print("[WARN] 响应不是有效 JSON")
    return None


def fetch_protocol(protocol):
    """Fetch all pages using the API's links.next field."""
    url = f"{API_BASE}/servers"
    params = {
        "protocol": protocol,
        "transport": "udp",
        "per_page": 200,
        "sort": "last_checked",
        "order": "desc",
    }
    rows = []
    seen_pages = set()

    while url:
        page_key = url
        if page_key in seen_pages:
            print(f"[WARN] {protocol}: 检测到重复分页链接，停止")
            break
        seen_pages.add(page_key)

        payload = safe_request(url, params=params, expect_json=True)
        params = None  # links.next already contains its own query
        if not isinstance(payload, dict):
            break

        data = payload.get("data", [])
        if isinstance(data, list):
            rows.extend(
                row for row in data
                if isinstance(row, dict)
            )

        links = payload.get("links") or {}
        url = links.get("next")
        if url:
            time.sleep(0.2)

    print(f"[INFO] {protocol}: 取得 {len(rows)} 条 API 记录")
    return rows


def normalize_country(row):
    code = str(row.get("country_code") or "").strip().upper()
    name = str(row.get("country_name") or "").strip().lower()

    aliases = {
        "japan": "JP",
        "south korea": "KR",
        "korea, republic of": "KR",
        "republic of korea": "KR",
    }
    if code in ("JP", "KR"):
        return code
    if name in aliases:
        return aliases[name]
    return None


def metadata_record(row):
    """Only non-secret metadata is written to JSON."""
    country = normalize_country(row)
    protocol = str(row.get("protocol") or "").lower()
    return {
        "id": row.get("id"),
        "protocol": protocol,
        "transport": row.get("transport"),
        "country_code": country,
        "country_name": row.get("country_name"),
        "city": row.get("city"),
        "hostname": row.get("hostname"),
        "ip": row.get("ip"),
        "port": row.get("port"),
        "latency_ms": row.get("latency_ms"),
        "speed_mbps": row.get("speed_mbps"),
        "uptime_percent_7d": row.get("uptime_percent_7d"),
        "availability_status": row.get("availability_status"),
        "last_checked_at": row.get("last_checked_at"),
        "last_check_ok": row.get("last_check_ok"),
        "is_working": row.get("is_working"),
        "freshness_status": row.get("freshness_status"),
        "config_available": False,
        "subscription_exported": False,
        "region_status": (
            "target_country"
            if country in ("JP", "KR")
            else "unknown_or_other"
        ),
        "source_name": row.get("source_name"),
        "server_page_url": row.get("server_page_url"),
        "config_download_available": bool(row.get("config_download_url")),
        "connection_info_available": bool(row.get("connection_info_url")),
    }


def extract_uris(value):
    """Extract only explicit standard share URIs from API-returned data."""
    found = []

    if isinstance(value, str):
        # Keep only URI strings; do not interpret host:port as a node.
        pattern = r"(?i)(?:hysteria2|hy2|tuic)://[^\s\"'<>]+"
        found.extend(re.findall(pattern, value))

    elif isinstance(value, dict):
        # Known fields may contain a share URI.
        for key in (
            "config_uri", "uri", "share_uri", "profile_uri",
            "config", "configuration", "qr_payload",
        ):
            item = value.get(key)
            if isinstance(item, str):
                found.extend(extract_uris(item))
            elif isinstance(item, (dict, list)):
                found.extend(extract_uris(item))

        # Search nested API objects, but do not print their contents.
        for key, item in value.items():
            if key not in (
                "config_uri", "uri", "share_uri", "profile_uri",
                "config", "configuration", "qr_payload",
            ) and isinstance(item, (dict, list)):
                found.extend(extract_uris(item))

    elif isinstance(value, list):
        for item in value:
            found.extend(extract_uris(item))

    # Remove common trailing punctuation from copied text.
    cleaned = []
    for uri in found:
        uri = uri.rstrip("),.;]")
        if uri not in cleaned:
            cleaned.append(uri)
    return cleaned


def valid_share_uri(uri, expected_protocol):
    """
    Conservative structural checks.
    Required values must exist in the actual URI; nothing is generated.
    """
    try:
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        allowed = {
            "hysteria2": {"hysteria2", "hy2"},
            "tuic": {"tuic"},
        }
        if scheme not in allowed.get(expected_protocol, set()):
            return False

        host = parsed.hostname
        port = parsed.port
        if not host or not port or not (1 <= port <= 65535):
            return False

        query = parse_qs(parsed.query, keep_blank_values=True)
        sni_values = query.get("sni") or query.get("server_name") or []
        sni = next((v for v in sni_values if v.strip()), "")

        # Hysteria2 requires a password and TLS server name for this
        # conservative export policy.
        if expected_protocol == "hysteria2":
            password = unquote(parsed.username or "")
            if not password or not sni:
                return False

        # TUIC needs UUID, password and TLS server name.
        elif expected_protocol == "tuic":
            user = unquote(parsed.username or "")
            password = unquote(parsed.password or "")
            if not user or not password or not sni:
                return False
            # Basic UUID shape check; do not manufacture one.
            if not re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{12}",
                user,
            ):
                return False

        return True
    except (ValueError, TypeError):
        return False


def get_real_config_uris(row):
    """
    Prefer connection_info_url, which returns current config_uri.
    Fall back to config_download_url if necessary.
    Do not cache config responses or print returned credentials.
    """
    protocol = str(row.get("protocol") or "").lower()
    urls = []

    info_url = row.get("connection_info_url")
    download_url = row.get("config_download_url")

    if isinstance(info_url, str) and info_url.startswith("https://"):
        urls.append(("info", info_url))
    if isinstance(download_url, str) and download_url.startswith("https://"):
        if download_url not in [item[1] for item in urls]:
            urls.append(("download", download_url))

    for kind, url in urls:
        time.sleep(REQUEST_PAUSE_SECONDS)
        response = safe_request(url, expect_json=(kind == "info"))
        if response is None:
            continue

        if kind == "info":
            uris = extract_uris(response)
        else:
            # Download may be plain text, URI, or JSON/YAML.
            content_type = response.headers.get("Content-Type", "").lower()
            text = response.text[:1_000_000]
            uris = extract_uris(text)
            if "json" in content_type:
                try:
                    uris.extend(extract_uris(response.json()))
                except ValueError:
                    pass

        for uri in uris:
            if valid_share_uri(uri, protocol):
                return uri

    return None


def make_unique_name(row, used_names):
    protocol = str(row.get("protocol") or "udp").lower()
    country = normalize_country(row) or "UNKNOWN"
    host = row.get("hostname") or row.get("ip") or "host-unknown"
    port = row.get("port") or "port-unknown"
    base = f"{country}-{protocol}-{host}-{port}"
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:80]
    name = base
    index = 2
    while name in used_names:
        name = f"{base}-{index}"
        index += 1
    used_names.add(name)
    return name


def add_uri_fragment(uri, name):
    """Set a readable node label without changing credentials or parameters."""
    from urllib.parse import urlsplit, urlunsplit, quote

    parts = urlsplit(uri)
    # Preserve scheme, credentials, host, port and query as returned.
    return urlunsplit((
        parts.scheme, parts.netloc, parts.path, parts.query,
        quote(name, safe="-._"),
    ))


def main():
    if not TOKEN:
        print("[ERROR] 缺少环境变量 PUBLICVPNLIST_TOKEN")
        sys.exit(2)

    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

    all_rows = []
    for protocol in PROTOCOLS:
        all_rows.extend(fetch_protocol(protocol))

    # De-duplicate records by stable API ID.
    unique_rows = []
    seen_ids = set()
    for row in all_rows:
        row_id = row.get("id")
        key = row_id or (
            row.get("protocol"), row.get("hostname"),
            row.get("ip"), row.get("port")
        )
        if key in seen_ids:
            continue
        seen_ids.add(key)
        unique_rows.append(row)

    metadata = [metadata_record(row) for row in unique_rows]
    metadata_by_key = {}
    for row, meta in zip(unique_rows, metadata):
        key = row.get("id") or (
            row.get("protocol"), row.get("hostname"),
            row.get("ip"), row.get("port")
        )
        metadata_by_key[key] = meta

    subscription_uris = []
    used_names = set()
    exported_keys = set()
    skipped = 0

    print(f"[INFO] 去重后候选记录：{len(unique_rows)}")
    print("[INFO] 正在逐条获取真实连接配置；不会输出配置内容或密码")

    for row in unique_rows:
        protocol = str(row.get("protocol") or "").lower()
        if protocol not in PROTOCOLS:
            continue
        if str(row.get("transport") or "").lower() != "udp":
            continue

        key = row.get("id") or (
            row.get("protocol"), row.get("hostname"),
            row.get("ip"), row.get("port")
        )
        meta = metadata_by_key.get(key)
        if not meta:
            continue

        uri = get_real_config_uris(row)
        if not uri:
            skipped += 1
            continue

        name = make_unique_name(row, used_names)
        labeled_uri = add_uri_fragment(uri, name)

        # Verify the final URI again after adding the label.
        if not valid_share_uri(labeled_uri, protocol):
            skipped += 1
            continue

        subscription_uris.append(labeled_uri)
        exported_keys.add(key)
        meta["config_available"] = True
        meta["subscription_exported"] = True

    # v2rayN supports a subscription containing share URIs, including
    # Base64-encoded line-separated protocol links.
    raw_subscription = (
        "\n".join(subscription_uris) + "\n"
        if subscription_uris else ""
    )
    encoded_subscription = (
        base64.b64encode(raw_subscription.encode("utf-8")).decode("ascii")
        if raw_subscription else ""
    )
    SUB_OUTPUT.write_text(encoded_subscription, encoding="ascii")

    target_rows = [
        item for item in metadata
        if item.get("country_code") in ("JP", "KR")
    ]
    unknown_rows = [
        item for item in metadata
        if not item.get("country_code")
    ]

    result = {
        "generated_at": utc_now(),
        "source": "PublicVPNList API v1",
        "protocols_requested": list(PROTOCOLS),
        "transport_filter": "udp",
        "candidate_count": len(metadata),
        "subscription_node_count": len(subscription_uris),
        "skipped_incomplete_or_unavailable_config_count": skipped,
        "target_country_candidate_count": len(target_rows),
        "unknown_country_candidate_count": len(unknown_rows),
        "subscription_format": "Base64-encoded newline-separated share URIs",
        "subscription_file": "v2rayn.txt",
        "notes": [
            "JSON does not contain node passwords or UUIDs.",
            "Only API-returned share URIs passing basic checks are exported.",
            "A valid URI does not guarantee current connectivity.",
            "Country metadata may be unknown or may describe an exit IP.",
            "PUBG compatibility and latency from your network are not tested.",
        ],
        "stats": {
            "protocols": {
                protocol: sum(
                    1 for row in metadata
                    if row.get("protocol") == protocol
                )
                for protocol in PROTOCOLS
            },
            "subscription_by_protocol": {
                protocol: sum(
                    1 for uri in subscription_uris
                    if urlparse(uri).scheme.lower()
                    in ({"hysteria2", "hy2"} if protocol == "hysteria2" else {"tuic"})
                )
                for protocol in PROTOCOLS
            },
        },
        "candidates": metadata,
        "target_country_candidates": target_rows,
        "unknown_country_candidates": unknown_rows,
    }

    JSON_OUTPUT.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[OUTPUT] {JSON_OUTPUT}")
    print(f"[OUTPUT] {SUB_OUTPUT}")
    print(f"[SUMMARY] 候选记录：{len(metadata)}")
    print(f"[SUMMARY] 导出订阅节点：{len(subscription_uris)}")
    print(f"[SUMMARY] 配置缺失/过期/格式不完整而跳过：{skipped}")
    print(f"[SUMMARY] 明确 JP/KR 元数据记录：{len(target_rows)}")
    print(f"[SUMMARY] 国家未知记录：{len(unknown_rows)}")
    print("[INFO] 不会把“已导出订阅”当作 PUBG 实测成功")


if __name__ == "__main__":
    main()
