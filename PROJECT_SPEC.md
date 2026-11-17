# PROJECT_SPEC.md

# 攻击面侦察与漏洞定位系统 - 工程规格书

## 1. 项目目标

构建一个基于 LangGraph 编排的本地攻击面侦察与漏洞定位系统。

- 输入：任意已获授权的域名或 IP、可选认证引用、速率上限。
- 输出：JSON/HTML 报告、工作流 Mermaid 源和可用时的 PNG。
- 覆盖范围：已知 CVE、常见 Web 配置缺陷、暴露服务、API 契约异常、K8s 基线问题。
- 不承诺发现业务逻辑漏洞。
- 部署形态：单机 Docker Compose，控制面与扫描执行面隔离。

## 2. 硬性约束

1. 扫描、编排和报告默认不依赖在线大模型。
2. GPL/AGPL 工具只能通过独立服务或子进程调用，不 import 其源码库。
3. 每个主动任务必须提交 `authorization_confirmed=true`，并通过目标解析、
   per-task scope 和 `max_rps <= 5` 门禁。
4. Worker 不映射宿主机端口，根文件系统只读，`cap_drop: ALL`，临时目录使用 tmpfs。
5. 工具调用节点为确定性函数；可选 AI 只负责在已通过门禁的候选节点中选择下一个，不能生成命令。
6. 扫描器和基础设施镜像均使用固定版本；实验室靶场镜像除外。
7. Windows 下只使用 named volume 或项目相对路径。

## 3. 技术栈

| 层 | 技术 |
|---|---|
| 前端 | React 18、Vite、Tailwind CSS |
| API | FastAPI、Pydantic v2 |
| 编排 | LangGraph StateGraph、PostgresSaver |
| 队列 | Celery、Redis |
| 数据库 | PostgreSQL 16 |
| 身份 | JWT、bcrypt |
| 工作流图 | mermaidx 后端渲染，浏览器 mermaid.js 兜底 |
| 报告 | Jinja2、JSON、HTML |

## 4. 执行架构

### 4.1 控制面

- `frontend`：登录、提交、节点卡片、SSE、Findings、报告。
- `backend`：JWT 鉴权、授权校验、任务入库、队列投递、查询接口。
- `postgres`：用户、任务、归一化结果和报告索引。
- `redis`：Celery broker/backend 与 SSE 发布订阅。

### 4.2 执行面

- `worker`：只运行编排与轻量 CLI，不对宿主机暴露端口。
- `zap`：独立 JVM 服务，通过 REST API 调用。
- `openvas`：`full` profile 下独立 GVM 服务，通过 GMP 调用。

### 4.3 实验室 profile

- `dvwa`：本地 Web 靶场，宿主机端口 `8081`。
- `mock`：本地条件边测试目标，容器内 `http://mock:8000`，同时监听 `6443`。

## 5. 状态与节点

### 5.1 State

`PentestState` 包含目标、授权、速率、资产、各类 Finding、执行轨迹、节点状态、错误和取消标记。

并行节点必须使用 reducer：

- `execution_trace`、`errors`、各类 Finding 列表使用追加 reducer。
- `node_status` 使用字典合并 reducer。
- `current_node` 使用最后写入 reducer。

### 5.2 十六个节点

1. `auth_gate`：授权门禁。
2. `recon`：subfinder。
3. `dns_resolve`：dnsx。
4. `takeover_check`：subjack。
5. `http_probe`：httpx 与 OpenAPI 路径发现。
6. `port_scan`：nmap `-sT -sV -sC`。
7. `router`：确定性条件路由。
8. `web_scan`：ZAP。
9. `nuclei_scan`：Nuclei。
10. `js_secret_scan`：Gitleaks。
11. `api_fuzz`：Schemathesis。
12. `k8s_audit`：Kubescape。
13. `server_baseline`：Nikto 与 Wapiti。
14. `host_vuln_scan`：OpenVAS/GVM。
15. `merge_and_score`：去重、交叉印证和评分。
16. `report`：HTML、JSON、Mermaid、PNG。

`http_probe`、`port_scan`、`takeover_check` 从 `dns_resolve` 并行执行。

条件分支：

- 无 HTTP 端点时不进入 Web 扫描。
- 发现 Swagger/OpenAPI 时进入 API 扫描。
- 发现 `.js` 资源时进入密钥扫描。
- 发现 `6443` 时进入 K8s 路由；没有 `KUBECONFIG` 时优雅跳过。
- `full` 模式才启用 OpenVAS。

## 6. 适配器契约

所有适配器继承 `BaseAdapter`，实现：

```python
def run(self, target_or_input, options: dict) -> list[Finding]: ...
```

每个适配器必须：

1. 从 `options["max_rps"]` 约束速率或并发。
2. 捕获异常并允许节点把错误写入 State。
3. 输出统一 `Finding`。
4. 不在模块导入阶段执行扫描。
5. 对缺失工具返回空结果并由节点标记 `skipped`。

Worker 启动时生成 `/output/capabilities.json`，API 通过 `GET /api/capabilities` 返回工具能力。

## 7. API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/login` | 登录并返回 JWT |
| POST | `/api/tasks` | 登录后提交任务 |
| GET | `/api/tasks/{id}` | 查询任务 |
| GET | `/api/tasks/{id}/events` | 带 token 的 SSE |
| GET | `/api/tasks/{id}/findings` | 查询 Finding |
| POST | `/api/tasks/{id}/cancel` | 请求取消 |
| GET | `/api/tasks/{id}/report` | HTML 或 JSON |
| GET | `/api/tasks/{id}/workflow.png` | PNG，渲染失败时 404 |
| GET | `/api/tasks/{id}/graph.mmd` | Mermaid 源 |
| GET | `/api/capabilities` | 工具能力 |
| GET | `/health` | 无鉴权健康检查 |

除 `/health` 和 `/api/auth/login` 外，所有 API 都要求 JWT。

## 8. 前端

- `/login`：JWT 登录。
- `/`：展示扫描风险提示与授权确认；支持任意目标，提交可选认证引用、速率和模式。
- `/tasks/{id}`：16 个节点卡片、SSE、Findings、鉴权下载。
- `/tasks/{id}/report`：报告 HTML、PNG 或浏览器 Mermaid 兜底、JSON 下载。

节点状态：

- `pending`：灰色。
- `running`：蓝色。
- `done`：绿色。
- `failed`：红色并展示错误。
- `skipped`：浅灰并展示原因。

## 9. 工作流图片

1. 后端把执行轨迹转换为 Mermaid。
2. 先写 `/output/{task_id}/workflow.mmd`。
3. 尝试使用 mermaidx 渲染 `/output/{task_id}/workflow.png`。
4. 渲染失败时返回空 PNG 路径，前端加载 `.mmd` 并用本地 npm `mermaid` 包渲染。
5. 不调用在线渲染服务，不依赖 Graphviz。

## 10. Docker

基础 Compose：

- `postgres`
- `redis`
- `zap`
- `backend`
- `worker`
- `frontend`

完整 Compose 叠加：

- `openvas`
- Worker `OPENVAS_ENABLED=true`

实验室 profile：

- `dvwa`
- `mock`

数据库和输出目录使用 named volume。授权 YAML 使用项目内相对只读挂载。

## 11. 验收

### V1 一键启动

`start.sh` 或 `start.bat` 创建 `.env`、启动基础服务与实验室 profile，等待健康检查后打印地址。

### V2 本地闭环

登录 `admin`，提交 `http://dvwa`，观察 16 个节点实时变化，得到 Findings 和报告。

### V3 条件边

提交 `http://mock:8000`，确认 OpenAPI 发现触发 `api_fuzz`，6443 路由触发后因缺少 `KUBECONFIG` 跳过 `k8s_audit`。

### V4 授权门禁

- 未勾选授权确认 / `authorization_confirmed=false`：403。
- 已确认的公网目标：允许进入队列，并按目标主机生成 per-task scope。
- 公开网站使用 `auth_ref=none`：允许进入队列。
- `max_rps=100`：403。
- 未知 `auth_ref`：403。

### V5 离线能力

镜像构建完成后，不依赖在线模型或在线 Mermaid 服务。扫描器的模板/指纹必须在构建阶段固化。

## 12. 已知边界

- 默认只授权 `dvwa`、`mock`、`127.0.0.1`、`localhost`。
- DVWA 第一次使用时需在页面执行 Create/Reset Database。
- OpenVAS 首次启用需要同步漏洞库，启动时间和资源占用显著高于基础服务。
- Kubescape 没有可用的 kubeconfig 时不会扫描外部 6443 服务。
- 本系统不执行口令爆破、漏洞利用或横向移动。
