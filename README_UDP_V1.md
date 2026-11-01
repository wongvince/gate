# gate UDP v1（候选采集版）

## 本版范围
- 数据来源：PublicVPNList API v1。
- 当前仅请求该项目原采集器已使用的 `hysteria2`、`tuic`，并要求 API 记录的 `transport=udp`。
- 只导出 API 实际返回且通过基础字段检查的分享链接；不生成密码、UUID、SNI 或混淆参数。
- 不将 Shadowsocks/VLESS/VMess/Trojan 等协议仅凭名称推断为 UDP 可用。

## 输出
- `public/udp_candidates.json`：候选元数据，不含 URI 凭据。
- `public/v2rayn.txt`：Base64 编码的分享链接订阅。若本次没有可用链接，保留上次订阅，避免空文件覆盖。

## 重要限制
本版只完成 L0（配置结构检查）。尚未实现 HTTP 代理测试、真实 UDP echo 隧道测试、PUBG 测试。因此：
- `config_exported=true` 不代表节点在线。
- API 的 UDP 标记不代表服务端 UDP 转发已实测。
- GitHub Actions 的网络测试即使后续加入，也只代表 runner 到节点的结果，不代表用户所在地网络。
- 公共节点存在隐私与账号风险，不要用于游戏主账号、支付或敏感登录。

## GitHub 配置
1. 在仓库 Settings → Secrets and variables → Actions → New repository secret。
2. Name 填 `PUBLICVPNLIST_TOKEN`，Value 填你的 PublicVPNList API Token。
3. 确认仓库 Settings → Pages → Build and deployment 的 Source 为 `GitHub Actions`。
4. 在 Actions 运行 `UDP Proxy Candidate Collector` → Run workflow。
5. 成功后检查 Pages 的 `udp_candidates.json` 与 `v2rayn.txt`。

## 安全升级方式
将本压缩包中的文件复制到你已创建的备份分支 `backup-before-udp-upgrade` 以外的工作分支（建议新建 `udp-upgrade-v1`）。不要删除旧 `vpngate.py`、旧 workflow、旧 Worker 文件或旧输出。新 workflow 名称为 `udp-check.yml`，不会自动运行。

## 下一版才做
L2 HTTP 代理验证、L3 受控 UDP echo 双向验证、节点失败分类与保留上次成功报告。不能用 `nc -u` 单向发包或 IP 风险评分代替真实隧道 UDP 测试。
