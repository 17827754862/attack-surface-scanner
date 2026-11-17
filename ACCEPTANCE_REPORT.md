# 本地产品验收报告

验收日期：2026-10-29  
项目目录：`D:\桌面\传智杯\attack-surface-scanner`  
平台：Windows 11 + Docker Desktop，Linux AMD64 容器

## 1. 部署结果

Docker Compose 成功构建并启动：

- 前端：`http://127.0.0.1:3000`
- API：`http://127.0.0.1:8000`
- DVWA：`http://127.0.0.1:8081`
- Mock HTTP：`http://127.0.0.1:18000`
- Mock 6443：`127.0.0.1:16443`
- PostgreSQL 16.6、Redis 7.4.1、Celery Worker：健康运行
- ZAP 2.17.0：独立容器，健康运行
- Worker：只读根文件系统、`cap_drop: ALL`、无宿主机端口

当前本地管理员为 `admin / changeme`，仅用于本机验收，必须在使用前修改。

## 2. 自动化测试

```text
docker compose --profile test run --rm tests
61 passed, 2 warnings
```

通过项包括：

- JWT 登录、受保护 API、取消接口
- 13 个适配器代码路径和解析测试
- ZAP 表单认证生命周期
- OpenVAS `gvm-cli` 生命周期和 mock GMP XML
- Scope Guard 通配符、重定向、OpenAPI 伪造地址、DNS rebinding
- 多引擎别名、去重、置信度和来源合并
- 证据哈希、索引和下载校验
- 报告、11 类处置剧本、可选 LLM 降级
- 条件路由、取消、失败和断点恢复
- SSE 格式和 Worker 失败状态
- 风险组 URL 实例聚合、历史资产快照和风险变化
- AI API Key 加密与非回显、历史 API、双语报告、AI 失败降级

告警来自 Starlette TestClient 与 LangGraph 上游弃用提示，不影响验收结果。

静态/配置校验：

```text
docker compose config --quiet
docker compose -f docker-compose.yml -f docker-compose.full.yml --profile full config --quiet
frontend Docker build
npm audit --omit=dev: 0 vulnerabilities
placeholder scan: clean
shell syntax: OK
```

## 3. 最终总验收

执行：

```powershell
python scripts/acceptance.py --output acceptance-results-final
```

结果：`status=passed`

### Mock 全链路

- 任务：`e4cbb4f6-c10a-4664-989b-670651f46005`
- 状态：`completed`
- 历史基线终态节点：17 个，无 pending
- `api_fuzz`：done
- `k8s_audit`：skipped，原因是没有 kubeconfig
- Finding：10 条
- `findings.json`、`report.html`、`workflow.png` 均存在

### DVWA 全链路

- 任务：`366adec6-7b6b-45c2-9596-d6f48746c5ce`
- 状态：`completed`
- Finding：104 条
- 严重度：high 1、medium 42、low 50、info 11
- 工具贡献：ZAP 101、Wapiti 2、Nmap 1
- 报告、JSON、证据索引和工作流 PNG 均已生成
- 工作流节点含工具名、摘要和状态颜色

### 认证扫描

DVWA 表单登录后访问验证：

- 登录成功
- 覆盖 10 个后台页面
- 包含 SQLi、反射/存储 XSS、命令执行、文件包含、上传、CSRF、Brute Force 页面

ZAP 登录前后 URL 对比：

- 未登录 URL：11
- 登录后 URL：42
- `passed=true`

### 浏览器展示检查

- 新建任务页加载工具能力卡片；默认 profile 不启动 OpenVAS，full profile 下实测 available
- 历史基线 DVWA 任务页显示 17 个节点，终态与后端一致
- Findings 区域实际渲染 104 条，展示 confidence、severity、source 和证据哈希
- 报告页成功加载工作流 PNG
- 报告内嵌节点状态、Finding 表、情景化处置和覆盖范围说明
- 当前代码生成的 `c5cb9227-111e-4ba4-90ac-5125c61b9e89` 报告已复测，
  PNG、iframe 和串行工作流边关系均正常；鉴权 GET 使用 `cache: no-store`，
  避免旧的“报告未生成”响应被缓存

### 取消与断点恢复

- 任务：`22bf6e39-5da9-4fd3-a945-01fdb3fe4f09`
- 审计记录：`task.create`、`task.cancel`、`task.resume`
- 取消状态：`cancelled`
- 恢复后终态：`completed`
- 恢复后 Finding：9
- 历史基线恢复后 17 个节点均有终态，failed 节点为 0
- 错误列表为空

取消期间使用 Redis 取消标记并终止适配器子进程组；恢复任务从 Postgres/LangGraph
检查点中的最早失败节点开始。本次取消发生在 `http_probe` 阶段，恢复从
`http_probe` 继续，保留已经完成的 recon 和 DNS 结果，再依次完成端口、扫描和报告节点。
验收脚本还会拒绝“终态为 completed 但仍有 failed 节点或 Finding 为 0”的假完成。

## 4. 报告与证据

- 报告按 confidence 从高到低排序
- 同一风险保留 `also_reported_by`
- 每条 Finding 包含 `evidence_hash`
- 证据文件：`/output/{task_id}/evidence/{sha256}.json`
- 索引文件：`/output/{task_id}/evidence/evidence_index.json`
- 下载 API 重新计算 SHA-256 后写入 `X-Evidence-SHA256`
- 报告内嵌情景化处置剧本和覆盖范围说明
- PNG 优先；失败时保留 `.mmd` 并由本地 npm Mermaid 渲染

验收产物位于：

```text
acceptance-results-final/
```

## 5. 3×3 消融实验

实验共执行 9 个真实 DVWA 任务，全部 `completed`：

| 组别 | 平均 Findings | Recall | Precision | FP Rate | 平均耗时 |
|---|---:|---:|---:|---:|---:|
| 单 Nuclei | 0.0 | 0.000 | 0.000 | 0.000 | 35.30 秒 |
| ZAP + Wapiti + Nuclei | 103.0 | 0.417 | 0.527 | 0.473 | 647.57 秒 |
| 完整 Agent | 104.0 | 0.417 | 0.527 | 0.473 | 647.62 秒 |

三轮结果在组内完全一致。单 Nuclei 的固定模板没有命中当前 DVWA ground truth；
ZAP 是主要检出引擎。严格 FP Rate 会把 Cookie、版本泄露和服务器配置等未列入固定
ground truth 的真实问题计为未匹配，因此不是人工复核后的真实误报率。

完整结果和 9 个任务 ID 见 `evaluation/results.csv` 与 `docs/evaluation.md`。

## 6. 工具能力

`GET /api/capabilities` 当前显示：

- Subfinder、dnsx、httpx、Nmap、Nuclei、Nikto、Wapiti、Schemathesis、
  Kubescape、Subjack、Gitleaks、ZAP：available
- OpenVAS：默认 profile 不启动；full profile 实测 available，GMP 版本 22.7

所有 CLI 版本固定；ZAP 和 OpenVAS 服务使用独立容器。OpenVAS 的 GPL
`gvm-cli` 只在 Worker 子进程中执行，不 import `gvm`。

## 7. 离线包

脚本：

- `scripts/make_offline_bundle.sh`
- `scripts/load_offline_bundle.sh`

离线包包含前后端、Worker、ZAP、PostgreSQL、Redis、DVWA 和 Mock，生成
`SHA256SUMS` 和 `VERSION`。OpenVAS 不进入默认离线包。

本机已实际生成：

```text
offline-bundle/images.tar    6,310,728,192 bytes
offline-bundle/images.txt
offline-bundle/VERSION
offline-bundle/SHA256SUMS
```

`images.tar` 可被 `tar -tf` 读取；`sha256sum -c SHA256SUMS` 对三个文件全部校验通过。
离线包标记为 `architecture=amd64`、`openvas_included=false`，并包含
`features=memory,ai-analysis,bilingual-ui,risk-groups`。Windows 可使用
`scripts/make_offline_bundle.ps1` 和 `scripts/load_offline_bundle.ps1`。

## 8. 当前限制

- 当前面向本机授权靶场，不是公网生产部署。
- 未实现 HTTPS 终止、多租户 RBAC、组织级配额和分布式限速。
- SSE 当前通过 JWT query 参数鉴权，公网部署前必须改为安全 Header/Cookie 方案。
- ARM64 未验证；当前 Worker 固定为 Linux AMD64。
- OpenVAS 已完成镜像启动、GMP TLS 连通、客户端兼容和 full 模式 DVWA 扫描验证；
  当前使用镜像内置的 NVT 基线 feed（`OPENVAS_SKIP_SYNC=true`），尚未完成在线
  feed 全量同步。DVWA 的 OpenVAS 结果为 0 条 Finding，表示目标未命中主机 CVE，
  不代表不存在 Web 或业务逻辑漏洞。
- 业务逻辑漏洞仍需要人工建模；自动化结果不等于完整渗透测试结论。
- ZAP 当前默认限制整次主动扫描 20 分钟、单规则 5 分钟，复杂目标可能因上限停止剩余规则，
  已产生的告警仍会保留。

## 9. 复现入口

```powershell
cd D:\桌面\传智杯\attack-surface-scanner
.\start.bat
```

浏览器打开 `http://127.0.0.1:3000`，使用 `http://dvwa` 和授权引用
`local-dvwa` 提交任务。

## 10. 历史记忆与 AI 增量复验

本轮在原有扫描链路上完成以下增量复验：

| 项目 | 结果 |
|---|---|
| 单元/API 测试 | `61 passed, 2 warnings` |
| 前端生产构建 | passed |
| Docker Compose 默认配置 | passed |
| Docker Compose full profile 配置 | passed |
| Mock 历史 smoke 第一次 | `d11c1513-fa9f-4395-9703-3b9b4a638427`，completed，2 Finding，2 风险组 |
| Mock 历史 smoke 第二次 | `5a2aaf14-08cf-4e45-8f66-c78772e33f33`，completed，2 Finding，2 风险组 |
| 第二次任务历史上下文 | `scan_count=10`，新增风险 0，报告包含相同历史上下文 |
| 历史 API | 返回 Mock/DVWA 资产和任务记录 |
| AI Key 保存 | 响应与读取接口均不回显测试 Key |
| AI 错误降级 | 错误兼容端点在测试接口返回 502，不写入 Finding、不阻塞扫描 |
| 浏览器检查 | 新建、历史、AI 设置、任务详情、风险组展开、报告 iframe 和 PNG 均可渲染 |

风险组在 UI 和报告中按资产、端口和漏洞类型聚合，实例、受影响 URL、来源和证据
仍可展开查看。第二次同目标扫描会读取历史快照，并在任务页和报告页显示风险变化。

AI 默认为关闭状态。本机没有可用于质量评估的真实 DeepSeek Key，因此没有把 mocked
OpenAI 兼容调用的结果表述为真实模型成功；DeepSeek/任意 OpenAI 兼容服务的生产
验收需要用户填写有效 API Key 后再运行 `/settings/ai` 的“测试连接”。

## 11. OpenVAS full profile 实测

- 任务：`e96f67ab-d36b-4134-a028-a75b58a05965`
- 目标：`http://dvwa`
- 模式：`full`
- 扫描组合：`full_agent`
- 最终状态：`completed`
- `host_vuln_scan`：`done`
- OpenVAS Finding：0
- 任务错误：0
- 其他引擎 Finding：124
- GMP 版本：22.7
- NVT 基线版本：`202607241713`

本次任务验证了 `create_target -> create_task -> start_task -> get_tasks 轮询 ->
get_report -> cleanup` 完整生命周期。OpenVAS 返回 0 条 Finding 是本次 DVWA
主机层检查的真实结果，不表示扫描器整体没有发现风险。

## 12. 通用认证、预算、验证器、OAST 与 AI 分批复验

本轮新增能力已并入当前产品，而不是作为比赛专用开关：

| 能力 | 验收结果 |
|---|---|
| 通用认证档案 | form/cookie/Bearer/Basic 契约；DVWA 示例通过 `auth_ref` 读取 |
| 任务时间预算 | `quick/standard/deep` + 自定义秒数 + 5 个阶段预算；standard Web 阶段为 1500 秒 |
| 超时部分报告 | 任务 `d4fdbb0d-04a5-4df6-944c-dfa5e1a984df` 返回 `partial`，报告成功生成 |
| SQLi 差分 | 有效任务 `a1ac45e1-d0f4-489b-ad99-854429ef3e83` 检出 SQL 注入 |
| 命令注入 | 同一任务检出低影响命令回显，并抑制 XSS 反射造成的假标记 |
| 文件上传 | 同一任务以非执行探针检出危险扩展名接受 |
| 默认口令/会话 | 同一任务检出默认口令和会话固定 |
| OAST | `/api/tokens → /cb/{token} → hit` 真实回调流程通过 |
| AI 分批 | 单元测试覆盖 5 个风险组分 3 批生成摘要和逐批缓存 |
| 自动化测试 | `61 passed, 2 warnings` |
| 完整 `scripts/acceptance.py` | `status=passed` |
| Mock/DVWA/断点恢复 | `dccde6af-082e-4e55-9282-ef274ca1c963` / `509f8d6b-3c88-4b34-a044-9d86357c2e41` / `b22b65bf-c7d5-4216-a5b4-d847218e3aac` |
| 深度验证任务 | `82d15b48-1889-4c15-b11b-ce8ac6595dec`，7 类型 Finding |

短预算任务 `d4fdbb0d-04a5-4df6-944c-dfa5e1a984df` 使用 60 秒总预算，ZAP 到达
deadline 后节点转为 `skipped`/`deadline_exceeded`，任务保留已有 Finding 并生成
`partial` 报告，而不是默默丢弃结果或继续长时间运行。

## 13. 认证覆盖与多引擎融合历史复验

2026-10-29 使用 full Compose profile 和重置后的 DVWA Low 再执行一次完整任务：

- 任务：`1e269b9b-b426-4139-ae73-e0b001480fad`
- 状态：`completed`
- Finding：88
- 风险组：20
- 严重度：critical 1、high 2、medium 40、low 42、info 3
- 工具来源：ZAP 84、Wapiti 3、Nmap 1
- `web_scan`、`server_baseline`、`host_vuln_scan`、`merge_and_score`、`report`：全部 `done`
- 错误列表：空
- 阻塞目标：空

认证链路：

- Worker 通过真实 `user_token` 完成 DVWA 登录
- ZAP 使用 Replacer 注入会话 Cookie，登录后覆盖 48 个 URL
- Wapiti 复用同一认证会话，节点记录 `wapiti_authenticated=true`
- 扫描结束后再次使用 `admin/password` 登录成功，确认扫描未修改管理员密码
- `logout.php`、`setup.php` 和 DVWA 改密页面被排除；User-Agent Fuzzer 和不可靠
  LDAP 主动模块已移除

关键检出：

- Wapiti：`/vulnerabilities/fi/?page=/etc/passwd`，critical 文件包含
- ZAP：2 条 high DOM XSS
- ZAP/Wapiti/Nmap 合并后形成 20 个风险组，88 条 URL 级 Finding

OpenVAS：

- GMP `22.7 available=true`
- `host_vuln_scan=done`
- 本次主机层 0 条 Finding
- 未出现 GMP/TLS/feed 错误

Ground Truth 复算：

| 指标 | 结果 |
|---|---:|
| Recall | 0.500 |
| Precision | 0.588 |
| Strict FP Rate | 0.412 |
| Coverage | 0.500 |

相较旧版完整 Agent 的 0.417 Recall 和 0.527 Precision，认证扫描提高了覆盖和严格
匹配精度。未命中类别在 `docs/evaluation.md` 中逐项列明，没有用 DVWA 专用硬编码
规则虚增结果。

本轮 LLM 摘要节点遇到不完整 JSON 响应，节点按设计降级为 `skipped`，错误为
`llm_degraded`。确定性 Finding、风险组、证据、HTML 报告和 workflow PNG 均正常生成。
