
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

import requests

API_URL = "https://www.vpngate.net/api/iphone/"

UPLOAD_URL = os.environ["LXI_UPLOAD_URL"]
UPLOAD_TOKEN = os.environ["LXI_UPLOAD_TOKEN"]

TIMEOUT = 40
MAX_SERVERS = 10000

session = requests.Session()
session.headers.update({
    "User-Agent": "LXI-VPNGate-Directory/1.0"
})


def get_vpngate_data():

    print("正在获取 VPN Gate 全球服务器列表...")

    response = session.get(
        API_URL,
        timeout=TIMEOUT
    )

    response.raise_for_status()

    response.encoding = "utf-8"

    text = response.text

    if "*vpn_servers" not in text:
        raise RuntimeError(
            "官方 CSV 数据格式不正确"
        )

    # VPN Gate CSV 第一行是 *vpn_servers 标记
    lines = text.splitlines()

    csv_text = "\n".join(
        line for line in lines
        if line.strip() and not line.startswith("*")
    )

    reader = csv.DictReader(
        io.StringIO(csv_text)
    )

    servers = []
    seen = set()

    for row in reader:

        host = (row.get("#HostName") or "").strip()

        ip = (row.get("IP") or "").strip()

        country = (
            row.get("CountryLong") or ""
        ).strip()

        country_code = (
            row.get("CountryShort") or ""
        ).strip()

        if not host or not ip:
            continue

        # 去重
        key = (host, ip)

        if key in seen:
            continue

        seen.add(key)

        # 只接受有效 IPv4 地址
        parts = ip.split(".")

        if len(parts) != 4:
            continue

        try:
            if not all(
                0 <= int(part) <= 255
                for part in parts
            ):
                continue
        except ValueError:
            continue

        # OpenVPN 配置
        config_b64 = (
            row.get("OpenVPN_ConfigData_Base64")
            or ""
        ).strip()

        try:
            config = base64.b64decode(
                config_b64,
                validate=True
            ).decode("utf-8", errors="ignore")

        except Exception:
            config = ""

        server = {
            "id": len(servers),
            "hostname": host,
            "ip": ip,
            "country": country,
            "country_code": country_code,
            "ping_ms": number(row.get("Ping")),
            "speed_bps": number(row.get("Speed")),
            "sessions": number(
                row.get("NumVpnSessions")
            ),
            "uptime": number(
                row.get("Uptime")
            ),
            "score": number(row.get("Score")),
            "total_users": number(
                row.get("TotalUsers")
            ),
            "total_traffic": number(
                row.get("TotalTraffic")
            ),
            "openvpn_available": bool(config),
            "openvpn_config": config
        }

        servers.append(server)

        if len(servers) >= MAX_SERVERS:
            break

    if not servers:
        raise RuntimeError(
            "没有获取到有效服务器，停止发布"
        )

    return servers


def number(value):

    try:
        return int(float(value or 0))
    except Exception:
        return 0


def main():

    servers = get_vpngate_data()

    now = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )

    # 删除配置正文，避免列表 JSON 过大
    public_servers = []

    for server in servers:

        item = dict(server)

        item.pop("openvpn_config", None)

        public_servers.append(item)

    payload = {
        "generated_at": now,
        "source": "VPN Gate official CSV API",
        "source_url": API_URL,
        "server_count": len(public_servers),
        "servers": public_servers
    }

    configs = {}

    for server in servers:

        if server["openvpn_config"]:

            configs[str(server["id"])] = (
                server["openvpn_config"]
            )

    package = {
        "servers": payload,
        "configs": configs
    }

    content = json.dumps(
        package,
        ensure_ascii=False,
        separators=(",", ":")
    )

    print("全球服务器数量：", len(servers))
    print("有 OpenVPN 配置的服务器：", len(configs))

    if not configs:
        raise RuntimeError(
            "没有 OpenVPN 配置，拒绝发布"
        )

    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = session.post(
        UPLOAD_URL,
        headers=headers,
        files={
            "data": (
                "vpngate.json",
                json_bytes,
                "application/json"
            )
        },
        timeout=120
    )

    if response.status_code != 200:
        raise RuntimeError(
            "LXI 上传失败："
            + str(response.status_code)
            + " "
            + response.text[:500]
        )

    print("LXI 发布成功")
    print(response.text[:500])


if __name__ == "__main__":

    try:
        main()

    except Exception as error:
        print("Error:", error)
        sys.exit(1)
