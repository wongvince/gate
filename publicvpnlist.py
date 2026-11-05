










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
            "proxy_uri": f"socks5://{node['ip']}:{node['port']}",
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

    log.info("开始 Worker 检测：%s 个节点；并发数：%s", len(nodes), CHECK_CONCURRENCY)
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as pool:
        futures = [pool.submit(check_one, node) for node in nodes]
        for done, future in enumerate(as_completed(futures), start=1):
            try:
                result, error = future.result()
                if result:
                    successful.append(result)
                    log.info("[成功] %s 延迟 %.0f ms", result["address"], result["responseTime"])
                else:
                    reason = error or "未知失败"
                    failures[reason] = failures.get(reason, 0) + 1
            except Exception as exc:
                reason = f"任务异常：{type(exc).__name__}"
                failures[reason] = failures.get(reason, 0) + 1
            if done % 10 == 0 or done == len(nodes):
                log.info("检测进度：%s/%s，成功：%s", done, len(nodes), len(successful))

    successful.sort(key=lambda n: n["responseTime"])
    return successful, failures


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
    with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    # 保留原文件名；内容为 SOCKS5 URI 清单，不保证是 v2rayN 可导入订阅格式。
    with open(TEXT_OUTPUT, "w", encoding="utf-8") as f:
        for node in nodes:
            f.write(node["proxy_uri"] + "\n")
    log.info("JSON 输出：%s", JSON_OUTPUT)
    log.info("SOCKS5 URI 清单输出：%s", TEXT_OUTPUT)


def main():
    log.info("========== SOCKS5 公共代理检测 ==========")
    log.info("节点来源：ProxyScraper；协议：SOCKS5")
    log.info("数据源延迟上限：%s ms", SOURCE_MAX_LATENCY_MS)
    log.info("Worker 延迟上限：%s ms", WORKER_MAX_LATENCY)
    if not WORKER_CHECK_URL:
        log.error("缺少 WORKER_CHECK_URL")
        sys.exit(1)
    if "{config}" not in WORKER_CHECK_URL and not WORKER_CHECK_URL.endswith("="):
        log.error("WORKER_CHECK_URL 必须以 = 结尾，或包含 {config}")
        sys.exit(1)
    log.info("国家过滤：%s", ", ".join(sorted(COUNTRY_CODES)) if COUNTRY_CODES else "不限制")

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
    log.info("候选节点：%s；成功节点：%s；失败节点：%s", len(candidates), len(successful), len(candidates) - len(successful))
    if failures:
        log.info("失败原因统计：")
        for reason, count in sorted(failures.items(), key=lambda x: -x[1])[:8]:
            log.info("  %s：%s", reason, count)
    if successful:
        log.info("最低 Worker 延迟：%.0f ms", successful[0]["responseTime"])
    else:



