
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多来源 VLESS / VMess / Trojan / Shadowsocks 节点收集器

功能：
1. 从多个订阅地址获取节点
2. 支持明文订阅和 Base64 订阅
3. 只接受 VLESS、VMess、Trojan、Shadowsocks
4. 去重
5. 检查服务器 TCP 端口是否可连接
6. 生成 tcp_candidates.json 和 v2rayn.txt
7. 上传到 LXI PHP 接口
8. 不生成、不覆盖、不上传 udp_candidates.json

注意：
TCP 端口连接成功不代表协议握手成功，也不代表 UDP 可用。
"""

import base64
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests


# -------------------- 基本配置 --------------------

ALLOWED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
}

PUBLIC_DIR = Path(os.getenv("PUBLIC_DIR", "public"))

CONNECT_TIMEOUT = float(
    os.getenv("CONNECT_TIMEOUT", "4")
)

CHECK_CONCURRENCY = int(
    os.getenv("CHECK_CONCURRENCY", "30")
)

MAX_NODES = int(
    os.getenv("MAX_NODES", "500")
)

MAX_SOURCE_SIZE = 5 * 1024 * 1024

MAX_WORKERS = max(1, min(CHECK_CONCURRENCY, 100))
MAX_NODES = max(1, min(MAX_NODES, 5000))

SOURCE_TEXT = os.getenv(
    "SOURCE_SUBSCRIPTION_URLS", ""
)

SOURCE_URLS = [
    x.strip()
    for x in re.split(r"[;\r\n]+", SOURCE_TEXT)
    if x.strip()
]

LXI_UPLOAD_URL = os.getenv("LXI_UPLOAD_URL", "").strip()
LXI_UPLOAD_TOKEN = os.getenv("LXI_UPLOAD_TOKEN", "").strip()

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "NodeCollector/1.0"
})


# -------------------- Base64 解码 --------------------

def decode_base64(text):

    text = text.strip()

    if not text:
        return ""

    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)

    try:
        return base64.b64decode(
            text,
            validate=False
        ).decode("utf-8", errors="ignore")

    except Exception:
        return ""


def decode_subscription(text):

    text = text.lstrip("\ufeff").strip()

    if not text:
        return ""

    if re.search(
        r"(?im)^\s*(vless|vmess|trojan|ss)://",
        text
    ):
        return text

    decoded = decode_base64(
        re.sub(r"\s+", "", text)
    )

    if re.search(
        r"(?im)^\s*(vless|vmess|trojan|ss)://",
        decoded
    ):
        return decoded

    return text


# -------------------- 获取节点服务器地址 --------------------

def get_node_address(link):

    scheme = link.split("://", 1)[0].lower()

    if scheme not in ALLOWED_PROTOCOLS:
        return None

    body = link.split("://", 1)[1].strip()

    # VMess
    if scheme == "vmess":

        encoded = body.split("#", 1)[0]

        decoded = decode_base64(encoded)

        if not decoded:
            return None

        config = json.loads(decoded)

        host = str(config.get("add", "")).strip()
        port = int(config.get("port", 0))

    # Shadowsocks
    elif scheme == "ss":

        body = body.split("#", 1)[0]

        # 兼容旧式 Base64 格式
        if "@" not in body:

            decoded = decode_base64(body)

            if "@" not in decoded:
                return None

            body = decoded

        parsed = urlsplit("ss://" + body)

        host = parsed.hostname or ""
        port = parsed.port or 0

    # VLESS / Trojan
    else:

        parsed = urlsplit(
            scheme + "://" + body
        )

        host = parsed.hostname or ""
        port = parsed.port or 0

    if not host:
        return None

    if not (1 <= int(port) <= 65535):
        return None

    return host, int(port)


# -------------------- 节点格式检查 --------------------

def validate_link(link):

    link = link.strip()

    if "://" not in link:
        return None

    scheme = link.split("://", 1)[0].lower()

    if scheme not in ALLOWED_PROTOCOLS:
        return None

    try:

        address = get_node_address(link)

        if not address:
            return None

        host, port = address

        return {
            "protocol": scheme,
            "host": host,
            "port": port,
        }

    except Exception:
        return None


# -------------------- 获取公开订阅 --------------------

def fetch_subscription(url):

    try:

        response = SESSION.get(
            url,
            timeout=20,
            stream=True
        )

        response.raise_for_status()

        content = bytearray()

        for chunk in response.iter_content(65536):

            content.extend(chunk)

            if len(content) > MAX_SOURCE_SIZE:
                raise ValueError(
                    "订阅文件超过 5 MiB"
                )

        text = bytes(content).decode(
            "utf-8-sig",
            errors="ignore"
        )

        return decode_subscription(text), None

    except Exception as exc:

        return "", str(exc)


# -------------------- TCP 连通性检测 --------------------

def tcp_check(item):

    link, info = item

    host = info["host"]
    port = info["port"]

    start = time.perf_counter()

    try:

        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            raise RuntimeError("DNS 没有返回地址")

        last_error = "没有可连接的公网地址"

        for family, socktype, proto, _, sockaddr in addresses:

            # 防止订阅源让 GitHub Runner 连接本机或内网地址
            ip = ipaddress.ip_address(sockaddr[0])

            if not ip.is_global:
                continue

            try:

                with socket.socket(
                    family,
                    socktype,
                    proto
                ) as sock:

                    sock.settimeout(CONNECT_TIMEOUT)
                    sock.connect(sockaddr)

                elapsed = round(
                    (time.perf_counter() - start) * 1000,
                    1
                )

                return {
                    "link": link,
                    "protocol": info["protocol"],
                    "server": host,
                    "port": port,
                    "tcp_connect": True,
                    "tcp_latency_ms": elapsed,
                }

            except Exception as exc:

                last_error = str(exc)

        raise RuntimeError(last_error)

    except Exception as exc:

        return {
            "link": link,
            "protocol": info["protocol"],
            "server": host,
            "port": port,
            "tcp_connect": False,
            "error": str(exc)[:180],
        }


# -------------------- 写入文件 --------------------

def atomic_write(path, content):

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp_path.write_text(
        content,
        encoding="utf-8"
    )

    temp_path.replace(path)


# -------------------- 上传 LXI --------------------

def upload_to_lxi(json_path, txt_path):

    if not LXI_UPLOAD_URL:
        raise RuntimeError("缺少 LXI_UPLOAD_URL")

    if len(LXI_UPLOAD_TOKEN) < 32:
        raise RuntimeError("LXI_UPLOAD_TOKEN 长度不足")

    headers = {
        "Authorization": "Bearer " + LXI_UPLOAD_TOKEN
    }

    with open(json_path, "rb") as json_file, \
         open(txt_path, "rb") as txt_file:

        response = requests.post(
            LXI_UPLOAD_URL,
            headers=headers,
            files={
                "tcp_candidates": (
                    "tcp_candidates.json",
                    json_file,
                    "application/json"
                ),
                "v2rayn": (
                    "v2rayn.txt",
                    txt_file,
                    "text/plain"
                ),
            },
            timeout=60
        )

    if response.status_code != 200:

        raise RuntimeError(
            "LXI 上传失败："
            + str(response.status_code)
            + " "
            + response.text[:300]
        )

    print("LXI 上传成功：", response.text[:300])


# -------------------- 主程序 --------------------

def main():

    PUBLIC_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not SOURCE_URLS:

        raise SystemExit(
            "Error：没有配置 SOURCE_SUBSCRIPTION_URLS"
        )

    print("========== 多来源节点采集 ==========")

    print("来源数量：", len(SOURCE_URLS))

    all_links = []
    source_errors = []

    # 获取多个来源
    for index, url in enumerate(SOURCE_URLS, 1):

        print(f"正在获取来源 {index}/{len(SOURCE_URLS)}")

        content, error = fetch_subscription(url)

        if error:

            source_errors.append(error)

            print("来源获取失败：", error[:200])

            continue

        links = [
            line.strip()
            for line in content.splitlines()
            if line.strip().lower().startswith(
                tuple(x + "://" for x in ALLOWED_PROTOCOLS)
            )
        ]

        print("获取节点：", len(links))

        all_links.extend(links)

    if not all_links:

        raise SystemExit(
            "Error：所有来源均未取得有效节点，旧数据不会被覆盖"
        )

    # 去重
    unique_links = list(dict.fromkeys(all_links))

    print("去重后节点：", len(unique_links))

    candidates = []

    for link in unique_links:

        info = validate_link(link)

        if info:

            candidates.append((link, info))

    candidates = candidates[:MAX_NODES]

    print("格式完整节点：", len(candidates))

    if not candidates:

        raise SystemExit(
            "Error：没有格式完整的节点，旧数据不会被覆盖"
        )

    # TCP 检测
    print("========== 开始 TCP 检测 ==========")

    results = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        for result in executor.map(
            tcp_check,
            candidates
        ):

            results.append(result)

    good = [
        item
        for item in results
        if item["tcp_connect"]
    ]

    good.sort(
        key=lambda x: x["tcp_latency_ms"]
    )

    print("TCP 检测总数：", len(results))
    print("TCP 成功数量：", len(good))

    if not good:

        raise SystemExit(
            "Error：TCP 成功节点为 0，旧数据不会被覆盖"
        )

    # 生成数据
    now = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )

    output = {
        "generated_at": now,
        "source_count": len(SOURCE_URLS),
        "protocols": sorted(ALLOWED_PROTOCOLS),
        "test_type": "TCP host:port connect only",
        "udp_tested": False,
        "protocol_handshake_tested": False,
        "warning": (
            "TCP connect success does not prove protocol handshake, "
            "proxy traffic, UDP, or PUBG compatibility."
        ),
        "candidate_count": len(good),
        "nodes": good,
        "source_errors": source_errors[:20],
    }

    json_path = PUBLIC_DIR / "tcp_candidates.json"
    txt_path = PUBLIC_DIR / "v2rayn.txt"

    json_content = json.dumps(
        output,
        ensure_ascii=False,
        indent=2
    ) + "\n"

    txt_content = "\n".join(
        item["link"] for item in good
    ) + "\n"

    atomic_write(json_path, json_content)
    atomic_write(txt_path, txt_content)

    # 特别注意：
    # 不创建、不覆盖、不删除 udp_candidates.json
    print("UDP 文件保持原样，不进行任何操作")

    # 上传 LXI
    print("========== 上传 LXI ==========")

    upload_to_lxi(
        json_path,
        txt_path
    )

    print("========== 全部完成 ==========")


if __name__ == "__main__":

    try:
        main()

    except Exception as exc:

        print("Error：", str(exc))

        raise
