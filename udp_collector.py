#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect PublicVPNList Hysteria2/TUIC UDP candidates; never invent configs."""
import base64, json, os, re, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote, urlsplit, urlunsplit, quote
import requests

API = "https://publicvpnlist.com/api/v1"
PROTOCOLS = ("hysteria2", "tuic")  # Only protocols exposed by the existing collector/API workflow.
OUT = Path(os.getenv("PUBLIC_DIR", "public"))
TOKEN = os.getenv("PUBLICVPNLIST_TOKEN", "").strip()
TIMEOUT = 20
S = requests.Session()
S.headers.update({"Authorization": f"Bearer {TOKEN}", "Accept": "application/json", "User-Agent": "wongvince-gate-udp-v1"})


def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def request(url, params=None, json_expected=False):
    try:
        r = S.get(url, params=params, timeout=TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        return r.json() if json_expected else r
    except (requests.RequestException, ValueError) as e:
        print(f"[WARN] 请求失败：{type(e).__name__}")
        return None

def fetch(proto):
    url, params, rows, visited = f"{API}/servers", {"protocol": proto, "transport": "udp", "per_page": 200, "sort": "last_checked", "order": "desc"}, [], set()
    while url and url not in visited:
        visited.add(url)
        data = request(url, params, True); params = None
        if not isinstance(data, dict): break
        rows += [x for x in data.get("data", []) if isinstance(x, dict)]
        url = (data.get("links") or {}).get("next")
        if url: time.sleep(.2)
    print(f"[INFO] {proto}: API 记录 {len(rows)}")
    return rows

def country(row):
    code = str(row.get("country_code") or "").upper()
    name = str(row.get("country_name") or "").lower()
    if code in ("JP", "KR"): return code
    if name == "japan": return "JP"
    if name in ("south korea", "korea, republic of", "republic of korea"): return "KR"
    return None

def find_uris(obj):
    out=[]
    if isinstance(obj, str): out += re.findall(r"(?i)(?:hysteria2|hy2|tuic)://[^\s\"'<>]+", obj)
    elif isinstance(obj, dict):
        for v in obj.values(): out += find_uris(v)
    elif isinstance(obj, list):
        for v in obj: out += find_uris(v)
    return list(dict.fromkeys(x.rstrip("),.;]") for x in out))

def valid(uri, proto):
    try:
        p=urlparse(uri); q=parse_qs(p.query); sni=next((x for x in (q.get("sni",[])+q.get("server_name",[])) if x.strip()), "")
        if not p.hostname or not p.port or not sni: return False
        if proto == "hysteria2": return p.scheme.lower() in ("hysteria2","hy2") and bool(unquote(p.username or ""))
        if proto == "tuic":
            u, pw = unquote(p.username or ""), unquote(p.password or "")
            return p.scheme.lower()=="tuic" and bool(pw) and bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",u))
    except (ValueError, TypeError): pass
    return False

def config_for(row):
    proto=str(row.get("protocol") or "").lower()
    urls=[]
    for k in ("connection_info_url","config_download_url"):
        u=row.get(k)
        if isinstance(u,str) and u.startswith("https://") and u not in urls: urls.append(u)
    for u in urls:
        time.sleep(.8)
        is_info=(u==row.get("connection_info_url"))
        r=request(u, json_expected=is_info)
        if r is None: continue
        if is_info: uris=find_uris(r)
        else:
            uris=find_uris(r.text[:1000000])
            if "json" in r.headers.get("content-type","").lower():
                try: uris += find_uris(r.json())
                except ValueError: pass
        for uri in uris:
            if valid(uri,proto): return uri
    return None

def label(uri, name):
    p=urlsplit(uri)
    return urlunsplit((p.scheme,p.netloc,p.path,p.query,quote(name,safe="-._")))

def main():
    if not TOKEN:
        print("[ERROR] GitHub 仓库必须设置 Secrets: PUBLICVPNLIST_TOKEN")
        sys.exit(2)
    OUT.mkdir(parents=True,exist_ok=True)
    rows=[]
    for proto in PROTOCOLS: rows.extend(fetch(proto))
    unique=[]; seen=set()
    for x in rows:
        k=x.get("id") or (x.get("protocol"),x.get("hostname"),x.get("ip"),x.get("port"))
        if k not in seen: seen.add(k); unique.append(x)
    candidates=[]; uris=[]; used=set(); skipped=0
    for row in unique:
        proto=str(row.get("protocol") or "").lower()
        if proto not in PROTOCOLS or str(row.get("transport") or "").lower()!="udp": continue
        uri=config_for(row)
        name=re.sub(r"[^A-Za-z0-9._-]+","_",f"{country(row) or 'UNKNOWN'}-{proto}-{row.get('hostname') or row.get('ip') or 'host'}-{row.get('port') or 'port'}")[:80]
        base=name; n=2
        while name in used: name=f"{base}-{n}"; n+=1
        used.add(name)
        if uri:
            uris.append(label(uri,name)); exported=True
        else: skipped+=1; exported=False
        candidates.append({"id":row.get("id"),"protocol":proto,"transport":row.get("transport"),"country_code":country(row),"country_name":row.get("country_name"),"city":row.get("city"),"hostname":row.get("hostname"),"ip":row.get("ip"),"port":row.get("port"),"api_latency_ms":row.get("latency_ms"),"api_is_working":row.get("is_working"),"last_checked_at":row.get("last_checked_at"),"config_exported":exported,"test_level":"L0_structure_only","http_test":"not_tested","udp_tunnel_test":"not_tested","pubg_test":"not_tested"})
    # Do not destroy a previously published subscription if today's source/API gives zero usable links.
    sub=OUT/"v2rayn.txt"
    if uris:
        raw="\n".join(uris)+"\n"
        sub.write_text(base64.b64encode(raw.encode()).decode("ascii"),encoding="ascii")
    else:
        print("[WARN] 本次没有提取到有效分享链接；保留旧 v2rayn.txt（如果存在）")
    report={"generated_at":now(),"source":"PublicVPNList API v1","protocols_requested":list(PROTOCOLS),"transport_filter":"udp","candidate_count":len(candidates),"exported_uri_count":len(uris),"skipped_config_count":skipped,"verification_scope":"GitHub Actions runner only; no China user or PUBG test","levels":{"L0":"URI/config structural checks only","L1":"not implemented in v1","L2_http":"not tested in v1","L3_udp_echo":"not tested in v1","PUBG":"not tested"},"warning":"Exported does not mean online, UDP relay verified, safe, or PUBG playable. Never use public nodes for sensitive accounts.","candidates":candidates}
    (OUT/"udp_candidates.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(f"[DONE] API去重记录 {len(unique)}；配置导出 {len(uris)}；配置缺失/无效 {skipped}")
    print("[NOTE] v1 只做配置结构筛选；没有宣称 HTTP/UDP/PUBG 实测成功。")

if __name__=="__main__": main()
