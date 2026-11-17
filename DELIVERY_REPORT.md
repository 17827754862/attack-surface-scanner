# Attack Surface Scanner 交付说明

## 项目定位

本项目是面向授权资产的本地优先攻击面侦察与漏洞定位系统。它使用 LangGraph
编排资产发现、端口识别、Web 扫描、API 检查、密钥扫描、Kubernetes 基线检查和
主机漏洞扫描，并把不同工具输出归一化为统一 Finding。

项目边界是防御侧评估，不包含漏洞利用、口令爆破、持久化或横向移动。

## 交付内容

- React 前端控制台
- FastAPI + JWT API
- Celery Worker + Redis
- PostgreSQL 任务、审计和检查点
- ZAP 独立扫描服务
- 可选 OpenVAS full profile
- 13 个扫描适配器
- Scope Guard、证据存储、报告和处置剧本
- 风险组语义聚合、资产历史快照和新增/持续/消失变化
- 可选的 OpenAI 兼容/DeepSeek 分析层与加密 API Key 配置
- 中英双语风险类型、严重度、节点状态和报告展示
- 3×3 消融实验
- Docker 一键启动
- AMD64 离线镜像包

## 13 个适配器

| 工具 | 主要职责 |
|---|---|
| Subfinder | 被动子域发现 |
| dnsx | DNS 解析 |
| httpx | HTTP 存活、标题和技术指纹 |
| Nmap | `-sT -sV -sC` 服务识别 |
| Nuclei | 固定版本模板和已知 CVE 匹配 |
| ZAP | 登录态 Spider + Active Scan |
| OpenVAS/GVM | 主机和网络层 CVE |
| Schemathesis | OpenAPI 契约检查 |
| Kubescape | Kubernetes 配置基线 |
| Subjack | 子域接管指纹 |
| Gitleaks | JavaScript 资源密钥检查 |
| Nikto | Web 服务器配置检查 |
| Wapiti | SQLi、XSS、文件、上传、CSRF 等参数检查 |

ZAP 和 OpenVAS 都不安装进 Worker 服务。OpenVAS 的 GPL `gvm-cli` 只以子进程运行，
应用代码不 import GPL/AGPL 库。

## 编排与状态

工作流包含 19 个节点：

```text
auth_gate
recon
dns_resolve
takeover_check
http_probe
port_scan
credential_session_analysis
router
web_scan
nuclei_scan
js_secret_scan
api_fuzz
k8s_audit
server_baseline
active_validation
host_vuln_scan
merge_and_score
llm_summarize
report
```

路由根据目标条件、扫描模式和 `tool_profile` 选择节点。未选节点会明确标记
`skipped`，不会调用对应工具。Worker 并发为 1，图内使用确定性串行阶段，保证取消、
恢复和汇合行为稳定。

## 真实验收

完整验收结果：`passed`

| 项目 | 结果 |
|---|---|
| 自动化测试 | 61 passed |
| Mock 全链路（历史基线） | completed，17 节点终态，10 Finding |
| DVWA 全链路 | completed，104 Finding |
| DVWA 登录后页面 | 10 |
| ZAP 未登录/登录后 URL | 11 / 42 |
| 报告、JSON、证据、PNG | 全部生成 |
| 取消后恢复（历史基线） | completed，17 节点，0 failed，9 Finding |
| 风险组与历史记忆 smoke | 2 次 completed；各 2 风险组；第二次读取历史快照 |
| AI 配置安全 smoke | Key 不回显；错误端点返回 502；失败不阻塞扫描 |

最终验收任务：

- Mock：`e4cbb4f6-c10a-4664-989b-670651f46005`
- DVWA：`366adec6-7b6b-45c2-9596-d6f48746c5ce`
- 取消/恢复：`22bf6e39-5da9-4fd3-a945-01fdb3fe4f09`

详细证据见 `ACCEPTANCE_REPORT.md` 和 `acceptance-results-final/`。

## 最新认证覆盖复验

使用 full Compose profile、DVWA 重置数据库和真实登录 Cookie 完成最终复验：

- Task ID：`1e269b9b-b426-4139-ae73-e0b001480fad`
- 状态：`completed`，错误列表为空
- Finding：88
- 风险组：20
- 严重度：critical 1、high 2、medium 40、low 42、info 3
- 工具来源：ZAP 84、Wapiti 3、Nmap 1
- ZAP 登录后覆盖：48 个 URL
- Wapiti：认证成功，检出 critical 文件包含
- OpenVAS：`done`，本次 0 条主机层 Finding
- 扫描结束后 `admin/password` 仍可登录

按现有 12 个归一化 ground-truth 类别复算，Recall 为 0.500、Precision 为 0.588、
Coverage 为 0.500；逐行证据见 `evaluation/results-final.csv`。仍未稳定覆盖的类别
及原因写在 `docs/evaluation.md`，没有使用 DVWA 专用硬编码检测冒充通用扫描能力。

## 通用认证、时间预算与深度验证

- 认证档案由 YAML 配置驱动，支持 form、cookie、Bearer 和 Basic；DVWA 只保留为
  `samples/auth.example.yaml` 示例，扫描器不再读取 DVWA 专用代码配置。
- 任务支持 `quick`、`standard`、`deep` 三档和自定义总预算，并支持
  `authentication / discovery / web_scan / host_scan / reporting` 阶段预算。
- 所有 CLI 子进程、ZAP 轮询和 OpenVAS 轮询共享任务 deadline；超时返回
  `partial`，保留已完成 Finding、证据和部分报告。
- 通用验证器在认证会话上执行 SQL 错误差分、低影响命令回显、无载荷危险扩展名
  上传检查；静态 SQL 文本和 XSS 反射造成的命令标记误报会被抑制。
- 认证分析支持配置化弱口令字典、低量失败登录限速探测、会话熵和会话固定检查。
- 独立 OAST 服务提供一次性回调 token 和命中记录；只有 `deep` 验证并显式开启
  `oast_enabled` 时才用于盲 SSRF、XXE 和命令执行确认。
- AI 摘要按 risk group 分批请求，单批失败只降级该批，其他批次和确定性扫描结果
  继续生成；不再因一次长 JSON 响应截断而跳过全部 AI 分析。

本轮有效验证任务 `a1ac45e1-d0f4-489b-ad99-854429ef3e83` 产出 6 条 Finding：
SQL 注入、命令注入、文件上传、默认口令、会话固定和开放端口。短预算任务
`d4fdbb0d-04a5-4df6-944c-dfa5e1a984df` 返回 `partial` 且生成部分报告。OAST
回调服务已通过真实 `/api/tokens → /cb/{token} → hit` 流程验证。机器可读结果见
`evaluation/active-validation-final.json`。

最终端到端验收 `scripts/acceptance.py` 返回 `status=passed`：

- Mock：`dccde6af-082e-4e55-9282-ef274ca1c963`
- DVWA：`509f8d6b-3c88-4b34-a044-9d86357c2e41`，completed，91 Finding
- 取消恢复：`b22b65bf-c7d5-4216-a5b4-d847218e3aac`，completed
- 深度验证：`82d15b48-1889-4c15-b11b-ce8ac6595dec`，7 类型 Finding
- 验收产物：`acceptance-results-current/`

## 新增分析层说明

`merge_and_score` 后先生成确定性风险组，再进入可选的 `llm_summarize`。AI 只做
同一 `host + port + vuln_type` 范围内的语义合并和叙述增强，服务端会拒绝跨类型、
跨端口或跨主机合并。原始 Finding、证据和确定性组始终保留。

AI 设置保存在数据库中，API Key 使用由 `JWT_SECRET` 派生的密钥加密。前端只显示
“已配置”状态，不读取明文。默认 `LLM_ENABLED=false`，因此 DVWA、Mock、离线包和
验收不依赖公网模型。

## 漏洞数据

DVWA 验收结果：

| 严重度 | 数量 |
|---|---:|
| High | 1 |
| Medium | 42 |
| Low | 50 |
| Info | 11 |

工具贡献：ZAP 101、Wapiti 2、Nmap 1。

Finding 包含标准化类型、严重度、confidence、证据、证据 SHA-256、来源合并信息和
情景化处置剧本。

## 3×3 消融实验

| 组别 | Mean Recall | Mean Precision | Mean FP Rate | Mean Seconds |
|---|---:|---:|---:|---:|
| 单 Nuclei | 0.000 | 0.000 | 0.000 | 35.30 |
| ZAP + Wapiti + Nuclei | 0.417 | 0.527 | 0.473 | 647.57 |
| 完整 Agent | 0.417 | 0.527 | 0.473 | 647.62 |

所有 9 次任务均完成。原始任务 ID 和逐行结果见：

- `evaluation/results.csv`
- `docs/evaluation.md`

严格 Precision/FP 指标只以固定 DVWA ground truth 为匹配集合，因此其他真实配置问题
会被计作“未匹配”。文档没有把该指标包装成人工复核后的业务误报率。

## 安全边界

- 未授权目标在 API 和 Worker 双层被拦截
- 重定向、OpenAPI server URL 和扫描器返回外链逐跳检查
- 私网授权支持 CIDR 和 DNS rebinding 基础防护
- 子进程支持超时、取消和进程组终止
- 密码、Cookie、Token、Authorization 和 URL 用户信息脱敏
- API 除登录和健康检查外均要求 JWT
- 审计日志记录用户、动作、目标和时间

## 离线部署

已有离线文件：

```text
offline-bundle/images.tar
offline-bundle/images.txt
offline-bundle/VERSION
offline-bundle/SHA256SUMS
```

本次重新生成包含认证 Cookie 注入、状态安全排除、通用认证档案、预算、深度验证、
OAST、历史记忆、风险组、双语界面和 AI 分批代码。`images.tar` 为 6,310,728,192
bytes（约 5.88 GiB），9 个镜像；SHA-256 已逐项校验通过。
包内不含 OpenVAS，支持 Linux AMD64；ARM64 未验证。Windows 可执行
`scripts/make_offline_bundle.ps1` 与 `scripts/load_offline_bundle.ps1`。

## 启动与演示

```powershell
cd D:\桌面\传智杯\attack-surface-scanner
.\start.bat
```

- 前端：`http://127.0.0.1:3000`
- API：`http://127.0.0.1:8000/docs`
- DVWA：`http://127.0.0.1:8081`

任务填写：

```text
目标：http://dvwa
授权引用：local-dvwa
max_rps：5
模式：active
```

## OpenVAS 实测

full profile 已使用任务 `e96f67ab-d36b-4134-a028-a75b58a05965` 完成一次真实
DVWA 扫描：

- 最终状态：`completed`
- `host_vuln_scan`：`done`
- OpenVAS Finding：0
- 其他引擎 Finding：124
- 错误：0
- GMP 版本：22.7

OpenVAS 0 条结果表示本次 DVWA 未命中主机层 NVT/CVE，不代表 Web 或业务逻辑无风险。

## 已知限制

- OpenVAS full profile 已完成镜像启动、GMP TLS 连通、客户端兼容和真实主机扫描验证；
  当前使用镜像内置的 NVT 基线 feed，尚未完成在线 feed 全量同步。
- 当前未实现公网 HTTPS、RBAC、多租户和分布式限流。
- SSE 公网部署前需要更换 JWT query 参数方案。
- 业务逻辑漏洞需要人工建模。
- ZAP 复杂目标可能触发 20 分钟整次上限，此时保留已生成告警并停止剩余规则。
- 本机未配置真实 DeepSeek Key；AI 配置接口、加密、mocked OpenAI 兼容调用和失败
  降级已验证，但真实模型输出质量仍需使用用户自己的 Key 抽样复核。
- 最近一次真实模型摘要因响应 JSON 不完整而自动降级为 `skipped`，不影响确定性扫描
  和报告。后续可将大风险组拆批请求以进一步降低长响应截断概率。

正式对外部署前必须修改 `.env` 默认密码和 JWT 密钥，并阅读
`SECURITY_BOUNDARIES.md`。
