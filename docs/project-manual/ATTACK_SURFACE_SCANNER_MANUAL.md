# Attack Surface Scanner 完整项目说明书

面向授权资产的多引擎攻击面侦察与漏洞定位系统

版本：2.0（深度设计版）

编制日期：2026-11-05

适用对象：项目使用者、运维人员、开发人员、答辩与评审人员

## 阅读说明

这份说明书回答四个问题：系统是什么，系统为什么这样设计，系统如何从底层运行到今天这个完整形态，以及使用者应该如何安装、配置、操作、验证、排错和继续开发。

全文以当前工作区中的实际代码、Compose 配置、测试和实际运行结果为依据。第一章到第三十一章提供完整使用视角；第三十二章以后进入深度设计篇，逐层解释设计框架、技术选型、源码调用链、外部工具执行方式、数据融合、有效性与替代人工验证方案。系统中已经实现的能力会直接描述；需要显式开启的能力会标明配置条件；未实现或尚未完成独立验证的生产能力会单独列入限制与实验计划。

建议阅读顺序如下。

1. 第一次接触项目时，先读第一章到第四章，建立整体认识。
2. 准备运行系统时，重点阅读第六章到第八章。
3. 需要理解设计原因和源码实现时，从第三十二章连续阅读到第四十九章。
4. 需要演示、答辩或面试时，重点阅读第十一章到第十五章、第二十五章、第五十三章和第五十六章。
5. 需要维护和二次开发时，重点阅读第十六章到第二十四章、第四十二章、第四十三章和第五十五章。

## 第一章 项目全景

### 1.1 一句话定义

Attack Surface Scanner 是一个本地优先、面向明确授权资产的多引擎攻击面侦察与漏洞定位系统。它把资产发现、DNS 解析、HTTP 指纹、端口服务识别、Web 动态扫描、模板漏洞扫描、API 契约检查、前端密钥扫描、Kubernetes 配置审计、服务器基线和主机漏洞扫描统一编排成一条可观察、可恢复、可评估的工作流。

系统的最终输出不是一段无法复核的自然语言，而是四类可以相互印证的结果：统一 Finding、风险组、证据文件、HTML/JSON/Markdown 报告及工作流图。

### 1.2 项目要解决的核心问题

传统扫描工具通常各自输出自己的格式。用户需要在多个工具之间切换，人工判断重复结果，手工拼接报告，也很难解释一次扫描到底执行了哪些步骤、哪些步骤没有执行、为什么没有执行。

本项目解决以下问题。

1. 工具碎片化。把多个扫描器封装为统一适配器，并将结果归一化为同一种 Finding。
2. 流程不可见。通过 LangGraph 状态机记录 19 个节点，通过 SSE 和任务详情页展示执行轨迹。
3. 风险排序粗糙。使用严重度、置信度、来源印证和暴露信息组织风险组，不只看单个工具的原始等级。
4. 结果不可复核。把证据规范化保存为 JSON，并计算 SHA-256，下载时重新校验。
5. 长任务不可控。引入总预算和阶段预算，支持取消、部分完成和断点恢复。
6. 工具能力不一致。通过 capabilities 接口探测工具是否可用，并在节点卡片中显示真实能力。
7. AI 不可靠时阻塞主链路。AI 可在授权和工具候选集合内动态选择下一个扫描器；关闭、超时或返回异常时，自动回退固定顺序，确定性扫描与报告仍然可用。

### 1.3 项目目标

系统的工程目标如下。

| 目标 | 说明 |
|---|---|
| 完整闭环 | 从授权目标输入到报告生成形成闭环 |
| 多引擎协同 | 不同工具分别覆盖网络层、Web 层、模板层、API 层和主机层 |
| 防御侧安全 | 不包含漏洞利用、口令爆破、持久化和横向移动 |
| 可观察 | 19 个节点、SSE 事件流、状态卡片和执行轨迹 |
| 可恢复 | LangGraph checkpoint、PostgreSQL 持久化和任务恢复 |
| 可评估 | Ground Truth、Recall、Precision、F1 和消融实验 |
| 可离线 | 本地 Docker 部署，基础扫描和报告不依赖在线模型 |
| 可扩展 | 新扫描器通过适配器接入，新能力通过节点或工具层接入 |

### 1.4 明确不做什么

以下能力不属于本项目。

1. 不执行漏洞利用。
2. 不进行口令爆破。
3. 不建立持久化后门。
4. 不进行横向移动。
5. 不上传恶意文件。
6. 不尝试破坏目标可用性。
7. 不承诺发现业务逻辑漏洞。
8. 不把 AI 输出当作扫描命令的来源。
9. 不默认面向公网暴露。
10. 不提供多租户 SaaS、企业 SSO 或完整生产级审计平台。

### 1.5 典型使用场景

| 场景 | 用法 |
|---|---|
| 本地功能演示 | 扫描 Docker 内的 DVWA 或 Mock 靶场 |
| 授权 Web 评估 | 对一个明确授权的域名执行主动 Web 扫描 |
| 认证站点检查 | 配置表单、Cookie、Bearer 或 Basic 认证后复测 |
| API 安全检查 | 目标暴露 Swagger/OpenAPI 时启用契约检查 |
| 主机层扫描 | 使用 full profile 启用 OpenVAS |
| 项目验收 | 执行 3×3 消融实验和完整验收脚本 |
| 课堂答辩 | 展示状态图、SSE、证据链、多引擎融合和失效降级 |

## 第二章 核心概念与术语

| 术语 | 含义 |
|---|---|
| Asset | 被授权的域名、主机或 URL |
| Task | 一次扫描任务，拥有唯一 task_id |
| Finding | 单个扫描器报告的标准化漏洞或风险实例 |
| Risk Group | 按 host、port、vuln_type 等维度聚合后的风险组 |
| Adapter | 外部扫描器与内部 Finding Schema 之间的适配层 |
| Node | LangGraph 工作流中的一个执行节点 |
| Trace | 节点执行轨迹，记录开始、结束、状态、摘要和错误 |
| Capability | 某个工具或服务当前是否可用，以及版本和模式 |
| Scope | 一次任务允许访问的目标范围 |
| Ground Truth | 人工标注的标准答案，用于计算检出指标 |
| SSE | Server-Sent Events，用于把工作流事件实时推送到前端 |
| Checkpoint | LangGraph 持久化状态快照，用于恢复任务 |
| Evidence | 能证明 Finding 来源和内容的证据数据 |
| Playbook | 按漏洞类型生成的情景化处置建议 |
| OAST | 带外应用安全测试，用于盲 SSRF、XXE 和命令执行确认 |
| GVM | Greenbone Vulnerability Management，OpenVAS 的管理协议 |

## 第三章 底层运行框架

### 3.1 运行基线

项目以 Windows 11 + Docker Desktop 为主要演示环境，同时提供 Linux/macOS 启动脚本。容器镜像以 Linux AMD64 为当前验证目标。

| 项目 | 当前基线 |
|---|---|
| 控制面 | Windows 11 或 Linux/macOS |
| 容器 | Docker Engine + Docker Compose v2 |
| Backend Python | 3.12.8 |
| Frontend Node | 22.12.0 |
| 数据库 | PostgreSQL 16.6 |
| 队列 | Redis 7.4.1 |
| Worker | Celery 5.4.0 |
| 编排 | LangGraph 0.2.62 |
| Web API | FastAPI 0.115.6 |
| 前端 | React 18.3.1 + Vite 6.0.5 |

### 3.2 为什么采用分层容器架构

系统把控制面和扫描执行面拆开。

控制面包括 frontend、backend、postgres 和 redis，负责登录、任务入库、API、状态查询、事件分发和报告访问。

执行面包括 worker，负责执行 LangGraph 和扫描适配器。Worker 不映射宿主机端口，根文件系统只读，丢弃 Linux capabilities，并使用 tmpfs 保存临时数据。

重型或许可证不同的工具放在独立容器中。ZAP 通过 REST API 调用，OpenVAS 通过 GMP 和 gvm-cli 调用。这样既便于资源隔离，也避免把 GPL/AGPL 工具链接进应用代码。

### 3.3 服务拓扑

| 服务 | 角色 | 默认端口 | 是否默认启动 |
|---|---|---:|---|
| frontend | React 控制台 | 3000 | 是 |
| backend | FastAPI API | 8000 | 是 |
| worker | Celery 扫描执行器 | 无宿主机端口 | 是 |
| postgres | 任务、用户、审计、快照 | 内部 5432 | 是 |
| redis | Celery broker 和 SSE Pub/Sub | 内部 6379 | 是 |
| zap | Web 主动扫描服务 | 内部 8090 | 是 |
| oast | OAST 回调服务 | 18001 | 是 |
| dvwa | Web 靶场 | 8081 | 实验室 profile |
| mock | 条件边测试服务 | 18000、16443 | 实验室 profile |
| openvas | 主机漏洞扫描 | 内部 9390 | full profile |

### 3.4 数据卷

| Volume | 用途 |
|---|---|
| postgres_data | PostgreSQL 数据 |
| redis_data | Redis AOF 数据 |
| output_data | 任务输出、证据、报告、工作流、能力文件 |
| zap_data | ZAP 工作目录 |
| oast_data | OAST token 与命中记录 |
| openvas_data | OpenVAS 数据库、证书和 feed |

### 3.5 启动流程

Windows 普通启动流程如下。

1. `start.bat` 检查 Docker 命令。
2. 检查 Docker Compose v2。
3. 调用 `scripts/ensure-docker.ps1`，必要时启动 Docker Desktop。
4. 如果没有 `.env`，从 `.env.example` 复制。
5. 读取端口、OpenVAS 和 VAS 启动器配置。
6. 如果 `OPENVAS_ENABLED=true`，叠加 full Compose profile，否则使用基础 profile。
7. 启动 backend、worker、frontend、postgres、redis、zap、oast、dvwa、mock。
8. 等待 `/health` 返回 200。
9. 输出前端、API、DVWA、Mock 和 OpenVAS 地址。
10. 如果配置了 `VAS_LAUNCHER`，调用 `scripts/vas-control.ps1` 启动外部 VAS 启动器。

### 3.6 停止流程

`stop.bat` 会读取 `.env` 中的 `VAS_LAUNCHER` 和 `VAS_STOPPER`，优先停止外部 VAS 启动器，然后执行 full Compose 的 down。数据卷默认保留，便于下次继续使用。

### 3.7 VAS 启动器

该功能用于把独立于本项目的 VAS 程序纳入统一启停。

配置示例：

```dotenv
VAS_LAUNCHER=C:\path\to\VAS-Launcher.exe
VAS_STOPPER=
```

`VAS_LAUNCHER` 支持 `.exe`、`.cmd`、`.bat`、`.ps1` 和 HTTP(S) URL。启动成功后会记录 PID。停止时如果配置了 `VAS_STOPPER` 就执行停止器，否则停止启动脚本记录的进程。

## 第四章 代码目录与模块地图

### 4.1 顶层目录

| 路径 | 作用 |
|---|---|
| backend/app | FastAPI、数据库、编排、适配器、报告 |
| backend/worker | Celery 任务入口和 Worker 镜像依赖 |
| frontend | React/Vite 控制台 |
| mock | 条件边测试目标 |
| oast | 独立回调服务 |
| config | 漏洞别名、缓存、弱口令字典 |
| docs | 使用、认证、预算、评估和项目文档 |
| evaluation | 消融实验与 ground truth |
| samples | 授权档案和任务示例 |
| scripts | 启动、验收、离线包、报告重建 |
| tests | 自动化测试 |
| report/playbooks | 漏洞处置知识库 |

### 4.2 Backend 模块

| 模块 | 关键职责 |
|---|---|
| main.py | 创建 FastAPI 应用，挂载路由 |
| config.py | Pydantic Settings 环境配置 |
| db.py | SQLAlchemy 模型、迁移和 Session |
| security.py | JWT、bcrypt、当前用户鉴权 |
| guard.py | 授权确认、Scope Guard、DNS 检查 |
| auth_session.py | form/cookie/Bearer/Basic 认证 |
| api/ | 任务、历史、AI、报告、SSE、审计 API |
| graph/ | LangGraph 状态、节点、边和事件包装 |
| adapters/ | 14 个扫描或验证适配器 |
| dedup.py | 归一化、去重和置信度 |
| risk_groups.py | 确定性风险组聚合 |
| memory.py | 资产快照和历史变化 |
| evidence.py | 证据写入、索引和哈希校验 |
| report.py | HTML/JSON/Markdown 报告 |
| workflow_image.py | Mermaid 和深色 PNG 工作流 |
| ai_*.py | 可选 OpenAI 兼容分析层 |
| oast_client.py | OAST token 创建和命中查询 |
| redaction.py | 密码、Token、Cookie、API Key 脱敏 |

### 4.3 Frontend 模块

| 路径 | 页面或职责 |
|---|---|
| pages/Login.jsx | 登录 |
| pages/Dashboard.jsx | 安全态势总览、实时流、引擎矩阵 |
| pages/Submit.jsx | 新建扫描、认证、模式、预算、风险确认 |
| pages/TaskDetail.jsx | 19 节点、SSE、风险组、Finding、恢复与下载 |
| pages/Report.jsx | 工作流图、完整 HTML 报告 |
| pages/History.jsx | 历史任务和资产变化 |
| pages/AISettings.jsx | OpenAI 兼容服务配置 |
| components/AppShell.jsx | 侧栏和全局框架 |
| components/NodeGrid.jsx | 19 节点网格 |
| components/RiskGroupList.jsx | 风险组展开视图 |
| components/FindingList.jsx | Finding 实例展开视图 |
| components/TraceView.jsx | 执行事件终端 |
| lib/api.js | JWT API 请求、下载和 SSE URL |

## 第五章 技术栈

| 层 | 技术 | 用途 |
|---|---|---|
| 容器 | Docker Compose | 服务隔离和本地部署 |
| 前端 | React 18 | 控制台 |
| 前端构建 | Vite 6 | 开发和生产构建 |
| 样式 | Tailwind CSS 3 | 页面样式 |
| 图标 | lucide-react | 统一图标 |
| 工作流前端 | Mermaid 12 | PNG 失败时浏览器兜底 |
| API | FastAPI | REST API |
| 数据校验 | Pydantic v2 | 请求、响应和 Finding Schema |
| ORM | SQLAlchemy 2 | PostgreSQL 持久化 |
| 认证 | JWT + bcrypt | 用户登录与密码校验 |
| 编排 | LangGraph | 状态图、条件边、checkpoint |
| 异步任务 | Celery | Worker 执行扫描 |
| Broker | Redis | 队列和事件发布订阅 |
| 数据库 | PostgreSQL | 任务、用户、历史、AI 配置 |
| 报告 | Jinja2 + JSON + Mermaid | 结果交付 |
| 扫描器 | 14 个适配器 | 发现、探测、验证 |

## 第六章 配置系统

### 6.1 `.env` 配置分组

数据库与认证：

| 变量 | 默认值 | 说明 |
|---|---|---|
| POSTGRES_PASSWORD | changeme | 本地数据库密码 |
| JWT_SECRET | change-this... | JWT 和 AI Key 加密派生密钥 |
| ADMIN_USERNAME | admin | 本地管理员用户名 |
| ADMIN_PASSWORD | changeme | 本地管理员密码 |
| API_PORT | 8000 | Backend 宿主机端口 |
| FRONTEND_PORT | 3000 | Frontend 宿主机端口 |

实验室和扫描：

| 变量 | 默认值 | 说明 |
|---|---|---|
| DVWA_PORT | 8081 | DVWA 宿主机端口 |
| MOCK_HTTP_PORT | 18000 | Mock HTTP 宿主机端口 |
| MOCK_K8S_PORT | 16443 | Mock 6443 映射 |
| AUTHORIZED_SCOPE | dvwa,... | 默认示例范围 |
| AUTHORIZATION_FILE | auth.example.yaml | 授权与认证 YAML |
| MAX_RPS | 5 | 每主机请求速率上限 |
| MAX_TASK_SECONDS | 7200 | 自定义任务预算上限 |

引擎：

| 变量 | 默认值 | 说明 |
|---|---|---|
| ZAP_IMAGE | zaproxy 2.17.0 | ZAP 镜像 |
| ZAP_API_KEY | local-zap-key | ZAP API Key |
| ZAP_MAX_SCAN_MINUTES | 20 | ZAP 整次上限 |
| OPENVAS_ENABLED | false | 是否启用 OpenVAS |
| OPENVAS_IMAGE | immauss/openvas | OpenVAS 镜像 |
| OPENVAS_SKIP_SYNC | false | 是否跳过 feed 同步 |
| NUCLEI_SEVERITY | medium,high,critical | 模板严重度 |

AI 与 OAST：

| 变量 | 默认值 | 说明 |
|---|---|---|
| LLM_ENABLED | false | 是否启用 AI 分析 |
| LLM_BASE_URL | 空 | OpenAI 兼容地址 |
| LLM_API_KEY | 空 | 模型 Key |
| LLM_MODEL | deepseek-chat | 模型名称 |
| LLM_BATCH_SIZE | 6 | 每批风险组数量 |
| LLM_MAX_TOKENS | 4096 | 单次输出上限 |
| OAST_PORT | 18001 | OAST 宿主端口 |
| OAST_SECRET | local-oast-secret | OAST 管理密钥 |
| OAST_PUBLIC_BASE_URL | http://oast:8001 | 目标可访问地址 |

### 6.2 授权档案

授权文件顶层为 `auth_refs`。每个 auth_ref 包含 scope、allowed_cidrs 和 authentication。

```yaml
auth_refs:
  portal:
    scope: [portal.example.com]
    allowed_cidrs: [203.0.113.10/32]
    authentication:
      type: form
      target_hint: https://portal.example.com
      target_hosts: [portal.example.com]
      login_url: https://portal.example.com/login
      verification_url: https://portal.example.com/home
      username_env: PORTAL_USERNAME
      password_env: PORTAL_PASSWORD
      username_field: username
      password_field: password
      csrf_field: csrf_token
      submit_field: submit
      submit_value: Login
      logged_in_indicator: Logout
```

### 6.3 认证类型

| 类型 | 必填信息 | 行为 |
|---|---|---|
| none | 无 | 不注入认证，适合公开网站 |
| form | login_url、字段、凭据环境变量 | 获取 CSRF、提交登录、验证登录态 |
| cookie | cookie_env | 从环境变量读取 Cookie Header |
| bearer | token_env | 注入 Authorization: Bearer |
| basic | 用户名和密码环境变量 | 使用 HTTP Basic |

敏感凭据不写入前端和 API 返回值。认证档案接口只返回 auth_ref、类型、目标提示和验证地址等非敏感元数据。

## 第七章 数据模型与持久化

### 7.1 PostgreSQL 表

| 表 | 关键字段 | 用途 |
|---|---|---|
| users | username、password_hash | 登录用户 |
| tasks | target、mode、profile、预算、状态、结果 | 任务主记录 |
| audit_logs | username、action、target、task_id | 审计 |
| asset_snapshots | asset_key、目标、风险类型、严重度 | 资产历史 |
| ai_config | enabled、base_url、model、密文 Key | AI 设置 |
| ai_analysis_cache | cache_key、模型、分析结果 | AI 批量缓存 |

### 7.2 Task 关键字段

`tasks` 表同时保存执行配置和执行结果。

配置字段包括 target、auth_ref、max_rps、mode、tool_profile、time_profile、time_budget_seconds、stage_budgets、deadline_at、validation_level、oast_enabled。

状态字段包括 status、node_status、errors、blocked_targets、deadline_exceeded。

结果字段包括 findings、risk_groups、memory_context、llm_summary、report_html、report_json、workflow_png、workflow_mmd。

恢复字段包括 resume_state、celery_task_id。

### 7.3 Finding Schema

| 字段 | 说明 |
|---|---|
| source | 扫描器来源 |
| host | 主机 |
| url | 受影响 URL |
| port | 端口 |
| vuln_type | 统一漏洞类型 |
| severity | info/low/medium/high/critical |
| evidence | 结构化证据 |
| raw | 原始工具数据 |
| also_reported_by | 其他佐证来源 |
| fingerprint | 稳定去重指纹 |
| confidence | 0 到 100 的置信度 |
| evidence_hash | 证据 SHA-256 |
| playbook | 对应处置剧本 |

### 7.4 输出目录

每个任务在 `/output/{task_id}/` 下生成：

```text
report.html
report.json
workflow.mmd
workflow.png
evidence/
  <sha256>.json
  evidence_index.json
```

## 第八章 安全模型

### 8.1 身份与访问

除 `/health` 和 `/api/auth/login` 外，API 默认要求 JWT。SSE 使用带 token 的查询参数，当前适用于本地和可信网络，公网部署前必须调整。

密码使用 bcrypt 哈希。JWT 默认有效期为 720 分钟。

### 8.2 授权门禁

任务必须满足以下条件。

1. `authorization_confirmed=true`。
2. `max_rps` 在 1 到 5 之间。
3. 目标可解析。
4. 模式属于 passive、active、full。
5. auth_ref 可解析或为 none。
6. 时间预算合法。
7. OAST 只在 deep 验证时允许。

### 8.3 Scope Guard

Scope Guard 负责：

1. 拒绝通配符目标。
2. 拒绝未授权的 CIDR 目标。
3. 解析初始目标。
4. 校验 redirect、OpenAPI server URL 和扫描器返回外链。
5. 拒绝元数据地址 169.254.169.254。
6. 在配置 allowed_cidrs 时检查 DNS 重绑定。

### 8.4 容器安全

Worker 不暴露端口，根文件系统只读，`cap_drop: [ALL]`，使用 tmpfs，并启用 `no-new-privileges`。

ZAP 和 OpenVAS 独立运行，不把重型 JVM 或 GVM 组件安装进应用层代码。

### 8.5 敏感信息处理

事件和错误进入前端前会递归脱敏。密码、passwd、token、cookie、authorization、api_key、secret 等字段统一替换为 `***`。URL 用户信息和 Bearer Header 也会被处理。

### 8.6 证据完整性

Finding 的 evidence 使用规范 JSON 计算 SHA-256。证据文件下载前重新计算并校验，响应头 `X-Evidence-SHA256` 返回验证后的哈希。

## 第九章 一次任务的完整生命周期

1. 用户登录并获取 JWT。
2. 前端读取能力矩阵、认证档案和历史记录。
3. 用户选择目标、认证、模式、工具组合、时间和验证级别。
4. 用户勾选授权声明。
5. Backend 调用 Guard 校验。
6. 创建 Task 记录，状态为 queued。
7. 写入审计日志。
8. Celery 投递 run_task。
9. Worker 读取任务和权限配置。
10. LangGraph 开始执行。
11. auth_gate 再次执行授权和 DNS 校验。
12. 执行 recon、DNS、接管、HTTP 和端口发现。
13. 认证分析节点按 auth_ref 决定是否执行。
14. router 根据端点、端口、模式和 tool_profile 选择分支。
15. 扫描节点执行，并把 Finding 写入状态。
16. merge_and_score 归一化、去重、评分并生成风险组。
17. 可选 llm_summarize 增强风险组描述。
18. report 生成 JSON、HTML、Mermaid 和 PNG。
19. Worker 把结果写回 Task 和资产快照。
20. 前端通过轮询和 SSE 更新节点、事件、风险组和 Finding。

## 第十章 LangGraph 编排

### 10.1 状态结构

`PentestState` 是 TypedDict，包含目标、授权、速率、时间预算、资产、各类 Finding、节点状态、轨迹、错误、取消和恢复字段。

并行或跨节点写入使用 reducer：

| 字段 | reducer |
|---|---|
| execution_trace | 追加 |
| errors | 追加 |
| blocked_targets | 追加 |
| live_endpoints | 追加 |
| port_findings | 追加 |
| vuln_findings | 追加 |
| api_findings | 追加 |
| k8s_findings | 追加 |
| secret_findings | 追加 |
| takeover_findings | 追加 |
| node_status | 字典合并 |
| current_node | 后写覆盖 |
| status | 按状态优先级合并 |

### 10.2 19 个节点

| 序号 | 节点 | 主要职责 | 工具 |
|---:|---|---|---|
| 1 | auth_gate | 授权、目标和 DNS 校验 | guard |
| 2 | recon | 被动子域发现 | subfinder |
| 3 | dns_resolve | DNS 解析 | dnsx |
| 4 | takeover_check | 子域接管检查 | subjack |
| 5 | http_probe | HTTP 存活、标题、技术栈 | httpx |
| 6 | port_scan | 端口和服务识别 | nmap |
| 7 | credential_session_analysis | 登录、会话强度、弱口令探测 | auth_analyzer |
| 8 | router | 条件路由 | 确定性规则 |
| 9 | web_scan | Web 主动扫描 | ZAP |
| 10 | nuclei_scan | 模板漏洞扫描 | Nuclei |
| 11 | js_secret_scan | JS 资源密钥扫描 | Gitleaks |
| 12 | api_fuzz | OpenAPI 契约检查 | Schemathesis |
| 13 | k8s_audit | K8s 配置基线 | Kubescape |
| 14 | server_baseline | Web 服务器基线 | Nikto + Wapiti |
| 15 | active_validation | 通用主动验证 | safe validators |
| 16 | host_vuln_scan | 主机漏洞扫描 | OpenVAS/GVM |
| 17 | merge_and_score | 归一化、去重、评分 | dedup |
| 18 | llm_summarize | AI 风险解读 | 可选 LLM |
| 19 | report | 报告和工作流 | Jinja2 + Mermaid |

### 10.3 路由逻辑

router 会根据以下条件生成 routes。

| 条件 | 启用节点 |
|---|---|
| live_endpoints 非空 | web_scan、nuclei_scan、server_baseline |
| validation_level 不是 off | active_validation |
| 发现 swagger 或 openapi | api_fuzz |
| 发现 .js URL | js_secret_scan |
| Nmap 发现 6443 | k8s_audit |
| mode=full | host_vuln_scan |

`tool_profile` 会进一步限制 routes。

| profile | 允许的扫描节点 |
|---|---|
| full_agent | 全部扫描节点 |
| nuclei | 仅 nuclei_scan |
| zap_wapiti_nuclei | web_scan、nuclei_scan、server_baseline |
| validation_only | active_validation |

### 10.4 跳过与失败的区别

`skipped` 表示条件不满足、工具不可用、分支未选中或预算耗尽。

`failed` 表示节点已尝试执行但出现未处理异常。

`blocked` 表示授权或范围校验拒绝。

`partial` 表示任务因总预算或阶段预算结束，已有结果仍然保留。

### 10.5 时间预算

| 阶段 | quick | standard | deep |
|---|---:|---:|---:|
| authentication | 30s | 90s | 180s |
| discovery | 90s | 300s | 600s |
| web_scan | 150s | 1500s | 2100s |
| host_scan | 0s | 420s | 900s |
| reporting | 30s | 90s | 180s |

### 10.6 取消与恢复

取消通过 Redis `cancel:{task_id}` 标记和 Celery revoke 共同实现。适配器应响应 cancel checker，子进程使用独立进程组，以便取消时终止整组进程。

失败或取消的任务可以恢复。恢复时重新计算 deadline，并从最早失败节点或失败节点之前的 pending 节点继续。已成功节点通过 checkpoint 复用，避免重复 Finding。

### 10.7 SSE

Worker 通过 Redis 发布 `task:{task_id}:events`。Backend 订阅该频道并以 SSE 推送给前端。事件包含节点名、工具、状态、摘要和错误。

前端会合并数据库中的 node_status 和 SSE 中的 live status。实时事件过期或断线时，任务轮询仍然能恢复最终状态。

## 第十一章 19 个节点逐项说明

### 11.1 auth_gate

对任务再次执行 `validate_task`。成功时写入 scope、allowed_cidrs 和 resolved_ips。失败时返回 blocked，并跳过后续扫描。

### 11.2 recon

对域名运行 Subfinder。本地主机和单标签主机不进行公共子域枚举，直接把主机作为 subdomains。工具缺失时节点 skipped，但不会阻塞后续。

### 11.3 dns_resolve

使用 dnsx 解析 A/AAAA 等记录。即使解析结果为空，也会保留原始 subdomains 供后续节点判断。

### 11.4 takeover_check

使用 Subjack 检查子域接管指纹。对 localhost、IP 和单标签本地主机直接 skipped，因为这类目标不具备公共 CNAME 接管语义。

### 11.5 http_probe

使用 httpx 获取状态码、标题、技术栈、Web Server 和 URL，并探测 `/swagger.json`、`/openapi.json`、`/v3/api-docs`。

### 11.6 port_scan

使用 Nmap `-sT -sV -sC` 识别端口、服务和版本。目标带显式端口时扫描该端口，否则扫描配置的 top ports。

### 11.7 credential_session_analysis

读取 auth_ref。仅当认证类型为 form 时执行登录、会话分析、弱会话检查、默认口令和登录限速相关检查。none、cookie、Bearer、Basic 不具备表单探测条件时会按规则跳过。

### 11.8 router

根据前序资产信息和任务配置生成 routes。它不调用外部工具，是确定性的分支选择器。

### 11.9 web_scan

调用独立 ZAP 服务。ZAP 可用于 Spider、Active Scan 和认证 Cookie 注入。达到时间上限时停止剩余扫描并保留已有告警。

### 11.10 nuclei_scan

运行固定版本模板。模板路径和严重度来自配置。没有 HTTP 端点时 skipped。

### 11.11 js_secret_scan

只扫描 live_endpoints 中以 `.js` 结尾的资源。它不负责发现所有静态资源，因此是否触发取决于 httpx 和路由是否已经发现 JS URL。

### 11.12 api_fuzz

只对包含 swagger 或 openapi 的 URL 运行 Schemathesis。没有 OpenAPI 契约时 skipped，不会盲目生成请求。

### 11.13 k8s_audit

只有 Nmap 发现 6443 时才进入路由。没有可用的 KUBECONFIG 时 skipped，不会把远程 6443 当作本地集群凭据。

### 11.14 server_baseline

对唯一 origin 执行 Nikto 和 Wapiti。full_agent 下 Nikto 和 Wapiti 都可参与。两个工具都失败时 failed，部分成功时 done 并记录错误。

### 11.15 active_validation

对唯一 origin 执行安全主动验证。它可检查 SQL 错误差分、低影响命令回显、危险扩展名上传和 OAST。validation_level=off 时 skipped。

### 11.16 host_vuln_scan

mode=full 且 OpenVAS available 时创建 GVM 目标、任务，轮询状态，获取报告并清理。OpenVAS 不可用时 skipped，不伪造主机漏洞。

### 11.17 merge_and_score

收集各类 Finding，按别名映射统一 vuln_type，去重，合并 also_reported_by，计算 confidence 和 score，排序，生成 evidence 和 risk groups。

### 11.18 llm_summarize

可选。AI 读取脱敏后的前序扫描摘要和证据样本，在系统给出的候选节点中选择下一个扫描器；失败时节点 skipped，确定性扫描和报告继续。AI 不能生成命令、增加目标、调用候选外工具，也不能删除、修改或伪造原始 Finding。

### 11.19 report

生成 HTML、JSON、Mermaid 源和深色 PNG 工作流。报告包含摘要、风险组、Finding、证据、修复建议、覆盖范围、历史和 AI 内容。

## 第十二章 扫描引擎手册

### 12.1 Subfinder

层级：被动 DNS 和资产发现。

用途：通过证书透明日志等公共来源发现子域。

输出：subdomain Findings。

失败模式：工具缺失、超时、网络不可达。节点可 skipped 或 done with local host only。

### 12.2 dnsx

层级：DNS 解析。

用途：把域名解析为 IP，过滤无效主机。

输出：解析结果。

### 12.3 httpx

层级：HTTP 探测。

用途：存活、状态码、标题、技术栈、Web Server 和基础 URL 发现。

输出：live_endpoints。

### 12.4 Nmap

层级：网络和端口。

用途：`-sT -sV -sC` 进行 TCP 连接扫描、服务识别和默认脚本检查。

输出：开放端口、服务、产品、版本。

### 12.5 Subjack

层级：DNS 和子域接管。

用途：匹配 CNAME 和托管服务接管指纹。

输出：subdomain_takeover Finding。

### 12.6 ZAP

层级：Web 动态扫描。

用途：Spider、Active Scan、认证会话 Cookie 注入。

输出：SQLi、XSS、路径遍历、CSRF、安全头、Cookie 属性等。

边界：独立容器，整次扫描和单规则均有时限。

### 12.7 Nuclei

层级：模板漏洞扫描。

用途：按固定模板检测已知 CVE、暴露配置和错误配置。

输出：known_cve 和模板类 Finding。

边界：覆盖率取决于模板集合和目标重合度。

### 12.8 Gitleaks

层级：前端静态资源。

用途：在已发现的 JavaScript URL 中扫描密钥和凭据特征。

边界：不主动发现所有 JS 文件，不验证泄露 Token 的真实权限。

### 12.9 Schemathesis

层级：API 契约。

用途：读取 OpenAPI，生成属性检查和契约异常。

边界：必须有可访问的 OpenAPI 文档。

### 12.10 Kubescape

层级：Kubernetes 基线。

用途：检查本地 K8s 配置和基线风险。

边界：没有 KUBECONFIG 时 skipped，不把外部 6443 自动视为本地集群。

### 12.11 Nikto

层级：Web 服务器基线。

用途：检查服务器配置、危险文件、默认页面和错误配置。

### 12.12 Wapiti

层级：Web 参数与常见漏洞。

用途：SQLi、XSS、命令注入、文件包含、上传、CSRF 等参数级检查。

边界：需要认证时复用统一会话对象。

### 12.13 OpenVAS/GVM

层级：主机和网络漏洞。

用途：通过 gvm-cli 与 OpenVAS GMP 通信，执行 create_target、create_task、start_task、poll、get_report 和 cleanup。

运行条件：full profile、OPENVAS_ENABLED=true、mode=full、GMP 可用、feed 状态可读。

### 12.14 OAST

层级：带外回调验证。

用途：为盲 SSRF、XXE 和命令执行创建一次性回调 token，并查询命中记录。

运行条件：validation_level=deep、oast_enabled=true，目标可以访问 OAST_PUBLIC_BASE_URL。

### 12.15 认证分析器与通用验证器

认证分析器负责表单登录、会话熵、会话固定、默认口令和登录限速检查。

通用验证器负责安全参数差分、低影响命令回显、非执行扩展名上传检查和 OAST，不生成破坏性利用载荷。

## 第十三章 Finding、风险组与评分

### 13.1 归一化

每个扫描器输出先转换为统一 Finding。不同工具的别名映射由 `config/vuln_alias.json` 维护，例如 SQL Injection、sqli 等统一为 `sql_injection`。

### 13.2 去重指纹

Finding 指纹由 host、port、url 和 vuln_type 的规范 JSON 计算 SHA-256 并截断得到。

### 13.3 置信度

置信度由四部分加权：

```text
confidence = source_score * 0.30
           + evidence_score * 0.30
           + severity_score * 0.25
           + exposure_score * 0.15
```

来源越多、证据字段越完整、严重度越高、暴露越直接，置信度越高。最终值限制在 0 到 100。

### 13.4 风险组

风险组默认按 host、port、vuln_type 聚合。信息泄露和敏感文件类别还会加入详情键，避免把不同根因混为一组。

风险组保留所有实例、URL、来源、证据和指纹。AI 只能在同一 host、port、vuln_type 内合并，不能跨类型。

## 第十四章 历史记忆与资产变化

每次成功结束的任务会生成 AssetSnapshot，记录 finding_count、risk_group_count、severity_counts 和 risk_types。

下一次扫描同一资产时读取最近 10 次快照，计算：

| 指标 | 含义 |
|---|---|
| scan_count | 历史快照数量 |
| new_risk_types | 本次新出现 |
| persistent_risk_types | 持续存在 |
| resolved_risk_types | 上次存在、本次消失 |

资产历史帮助判断修复是否生效，也避免每次扫描都从零开始理解目标。

## 第十五章 AI 增强层

### 15.1 定位

AI 具有两个受控位置：`router` 可在候选工具中选择下一扫描器，`llm_summarize` 位于 `merge_and_score` 之后生成解释。AI 不能执行任意命令、不能增加目标、不能修改原始 Finding，也不能删除风险组。

### 15.2 支持接口

支持任意 OpenAI 兼容 `/chat/completions` 服务，例如 DeepSeek、本地兼容服务或企业代理。

### 15.3 输入

AI 接收：

1. 同一风险组的类型、主机、端口、严重度、置信度。
2. 来源列表。
3. 受影响 URL 样本。
4. 证据样本。
5. 已脱敏的历史记忆。

AI 不接收：

1. 登录密码。
2. Cookie 明文。
3. Authorization Header。
4. API Key。

### 15.4 输出

输出中英双语标题、描述、影响、低影响复验步骤、误报检查、修复建议、复测建议和 AI 置信度。

### 15.5 分批与缓存

风险组按 LLM_BATCH_SIZE 分批请求。单个批次失败只降级该批，不阻塞其他批次。结果写入 AIAnalysisCache。

全部批次都失败时 `llm_summarize` 标记 skipped，任务仍进入 report。

## 第十六章 报告、证据和工作流图

### 16.1 报告结构

HTML 报告包含：

1. 任务基本信息。
2. 严重度统计。
3. 时间预算。
4. 历史记忆。
5. AI 辅助研判。
6. 风险组表。
7. 风险组详情。
8. Finding 实例表。
9. 节点状态。
10. 覆盖范围说明。
11. 处置剧本。

### 16.2 证据

证据以规范 JSON 保存。同一 Finding 的证据哈希稳定，下载时重新校验。证据索引用于从 fingerprint 定位 evidence_hash。

### 16.3 工作流图

后端根据 trace 和 node_status 生成 Mermaid，再尝试渲染 PNG。PNG 保存失败时，前端读取 `.mmd` 并使用本地 Mermaid 渲染。

当前工作流图使用深色画布，只绘制实际进入执行链的节点，按 trace 的真实顺序连成数据流。状态颜色如下。

| 状态 | 颜色语义 |
|---|---|
| done | 深绿底、绿色边框 |
| running | 深蓝底、蓝色边框 |
| failed | 深红底、红色边框 |
| skipped | 深灰底、虚线边框 |
| pending | 深棕底、琥珀色边框 |

### 16.4 深色报告

报告 HTML、iframe 外框、工作流容器和滚动条均使用深色方案，避免切换页面时出现白色闪烁和白色滚动条。

## 第十七章 前端使用手册

### 17.1 登录

访问 `http://127.0.0.1:3000`。默认本地账号为 admin / changeme，正式使用前必须修改。

### 17.2 总览页

总览显示：

| 区域 | 内容 |
|---|---|
| 指标卡 | 资产、风险实例、高危、任务数 |
| 实时数据流 | 最近执行轨迹和当前 SSE 事件 |
| 扫描引擎 | 所有引擎的版本和在线状态 |
| 最近任务 | 任务目标、状态、模式、数量和时间 |
| 高频风险 | 资产快照中的风险类型排行 |

### 17.3 新建扫描页

新建扫描分为四个配置区。

1. 目标与认证：URL、auth_ref。
2. 扫描策略：passive、active、full；full_agent、validation_only、zap_wapiti_nuclei、nuclei。
3. 时间与请求预算：quick、standard、deep 或自定义分钟数；max_rps。
4. 主动验证：off、safe、deep；deep 时可启用 OAST。

风险声明位于开始按钮上方，必须勾选授权确认。

### 17.4 任务详情页

任务详情不再预先排列全部 19 个节点，而是按照真实执行顺序显示已经进入数据流的工具。每个工具卡片显示状态、数据摘要和 AI/固定规则选择理由；未进入候选或条件不满足的工具只显示数量，不占据主流程。运行中任务每 2 秒轮询，并同时接收 SSE。失败或取消后可以恢复。

### 17.5 风险组与 Finding

风险组用于阅读和修复，Finding 用于查看单条证据。风险组展开后显示来源、实例数、URL 数、复验步骤、误报检查、修复和复测建议。

### 17.6 报告页

报告页显示深色工作流图和完整 HTML 报告。支持下载 PNG 和 JSON。

### 17.7 历史与资产

历史页支持按目标和状态筛选，展示资产快照、任务记录和风险变化。

### 17.8 AI 设置

AI 设置页支持配置 Base URL、模型、API Key、启用状态和连接测试。读取接口只显示是否已配置 Key，不回显明文。

## 第十八章 API 手册

所有示例默认携带 `Authorization: Bearer <token>`。

### 18.1 登录

`POST /api/auth/login`

```json
{"username":"admin","password":"changeme"}
```

响应：

```json
{"access_token":"...","token_type":"bearer"}
```

### 18.2 健康检查

`GET /health`

无需 JWT，返回 `{"status":"ok"}`。

### 18.3 能力

`GET /api/capabilities`

返回所有扫描工具和外部服务的 available、version、mode、error。

### 18.4 认证档案

`GET /api/auth-profiles`

返回非敏感的 auth_ref、类型、目标提示和验证地址。

### 18.5 创建任务

`POST /api/tasks`

```json
{
  "target": "http://dvwa",
  "auth_ref": "local-dvwa",
  "authorization_confirmed": true,
  "max_rps": 5,
  "mode": "active",
  "tool_profile": "full_agent",
  "time_profile": "standard",
  "time_budget_seconds": 1800,
  "validation_level": "safe",
  "oast_enabled": false
}
```

成功返回 202 和 task_id。

### 18.6 查询任务

`GET /api/tasks/{task_id}`

### 18.7 取消

`POST /api/tasks/{task_id}/cancel`

### 18.8 恢复

`POST /api/tasks/{task_id}/resume`

仅 failed 或 cancelled 任务可以恢复。

### 18.9 事件流

`GET /api/tasks/{task_id}/events?token=<jwt>`

返回 `text/event-stream`。

### 18.10 Finding

`GET /api/tasks/{task_id}/findings`

### 18.11 报告

`GET /api/tasks/{task_id}/report`

`format=html` 返回 HTML，`format=json` 返回 JSON。

### 18.12 工作流

`GET /api/tasks/{task_id}/workflow.png`

`GET /api/tasks/{task_id}/graph.mmd`

### 18.13 证据

`GET /api/tasks/{task_id}/evidence/{fingerprint}`

返回证据 JSON，并校验 SHA-256。

### 18.14 历史

`GET /api/history/tasks`

`GET /api/history/assets`

`GET /api/history/assets/{asset_key}`

### 18.15 AI

`GET /api/ai/config`

`PUT /api/ai/config`

`POST /api/ai/test`

### 18.16 审计

`GET /api/audit`

返回用户、动作、目标、任务和时间。

## 第十九章 安装与部署手册

### 19.1 首次安装

1. 安装 Docker Desktop。
2. 确认 Docker Compose v2 可用。
3. 进入项目目录。
4. 执行 `start.bat` 或 `./start.sh`。
5. 等待 API 健康。
6. 打开前端。
7. 修改默认密码和 JWT Secret。

### 19.2 基础 profile

基础 profile 适合日常演示，包含 frontend、backend、worker、postgres、redis、ZAP、OAST、DVWA、Mock，不启动 OpenVAS。

### 19.3 full profile

full profile 额外启动 OpenVAS，并把 Worker 和 Backend 的 OPENVAS_ENABLED 设置为 true。

### 19.4 离线包

在联网 AMD64 主机生成：

```powershell
.\scripts\make_offline_bundle.ps1 -BundleDir offline-bundle
```

在离线主机加载：

```powershell
.\scripts\load_offline_bundle.ps1 -BundleDir offline-bundle
```

### 19.5 停止

```powershell
.\stop.bat
```

### 19.6 清理

默认 down 保留数据。清空数据前必须确认报告、证据和数据库不再需要。

## 第二十章 运维与故障排查

### 20.1 服务未启动

先执行：

```powershell
docker compose ps
docker compose logs --tail=200 backend worker frontend
```

### 20.2 API 健康但页面无数据

检查 JWT 是否过期、网络请求是否 401、`/api/capabilities` 是否可访问。

### 20.3 工具显示 unavailable

检查 Worker 或 Backend 的 capability 文件、Docker 镜像、命令 PATH 和外部服务健康状态。

### 20.4 OpenVAS 不显示

依次检查：

1. 是否使用 full Compose。
2. `OPENVAS_ENABLED` 是否为 true。
3. OpenVAS 容器是否 healthy。
4. `gvm-cli` 是否可用。
5. GMP 9390 是否连通。
6. feed 是否处于同步状态。
7. Worker 是否已重写 capabilities 文件。

### 20.5 报告或工作流缺失

检查 `/output/{task_id}/` 下的 report、workflow 和 evidence 文件。使用重建脚本：

```powershell
docker compose exec -T worker python /app/scripts/regenerate_reports.py --task-id <task_id>
docker compose exec -T worker python /app/scripts/regenerate_workflows.py --task-id <task_id>
```

### 20.6 任务长时间运行

检查 time_profile、阶段预算、ZAP 上限、OpenVAS 状态和当前节点。阶段预算耗尽会生成 partial 报告。

### 20.7 大量 skipped

按错误码判断：

| 原因 | 解释 |
|---|---|
| condition_not_met | 缺少触发条件 |
| route_not_selected | 当前 profile 或 mode 未选中 |
| tool_profile_excluded | 工具组合主动排除 |
| no_http_endpoints | 没有 HTTP 端点 |
| no_javascript_assets | 未发现 JS URL |
| no_openapi_contract | 未发现 OpenAPI |
| k8s_route_not_selected | 未发现 6443 |
| kubescape_requires_kubeconfig | 缺 KUBECONFIG |
| deadline_exceeded | 时间预算耗尽 |
| tool_not_installed | 工具缺失 |

## 第二十一章 测试与验收

### 21.1 当前自动化测试

当前完整测试结果：

```text
66 passed, 2 warnings
```

告警来自 Starlette TestClient 的 anyio 弃用提示和 LangGraph 上游弃用提示，不影响结果。

### 21.2 测试覆盖

| 类别 | 覆盖内容 |
|---|---|
| 安全 | JWT、授权确认、Scope、DNS rebinding |
| 图 | 全链路、条件路由、恢复、状态优先级 |
| 适配器 | 13 个扫描工具和解析器 |
| 认证 | form、Cookie、Bearer、Basic、CSRF |
| 预算 | quick/standard/deep、阶段预算 |
| 证据 | 哈希、索引、下载验证 |
| 报告 | HTML、风险组、处置剧本、深色工作流 |
| AI | 关闭、超时、失败、分批、缓存 |
| 历史 | 资产快照、新增、持续、消失 |
| 前端 | 生产构建 |

### 21.3 验收基线

历史验收包括 Mock、DVWA、认证扫描、OpenVAS full、取消恢复、OAST、AI 降级和离线包。

Mock 验收任务：`e4cbb4f6-c10a-4664-989b-670651f46005`。

DVWA 验收任务：`366adec6-7b6b-45c2-9596-d6f48746c5ce`。

取消恢复任务：`22bf6e39-5da9-4fd3-a945-01fdb3fe4f09`。

OpenVAS 验收任务：`e96f67ab-d36b-4134-a028-a75b58a05965`。

### 21.4 3×3 消融

| 组别 | Mean Recall | Mean Precision | Mean FP Rate | Mean Seconds |
|---|---:|---:|---:|---:|
| 单 Nuclei | 0.000 | 0.000 | 0.000 | 35.30 |
| ZAP + Wapiti + Nuclei | 0.417 | 0.527 | 0.473 | 647.57 |
| 完整 Agent | 0.417 | 0.527 | 0.473 | 647.62 |

严格 Precision 只以固定 Ground Truth 为匹配集合，不能直接等同于人工复核后的真实误报率。

## 第二十二章 已知限制

1. 当前面向本地和可信网络，不适合直接公网暴露。
2. 未实现 HTTPS 终止和证书管理。
3. 未实现多租户 RBAC、组织级配额和分布式限流。
4. SSE 当前使用 JWT query 参数，公网部署前必须调整。
5. ARM64 未验证，当前 Worker 以 Linux AMD64 为主。
6. OpenVAS 首次同步资源占用大，当前示例使用基线 feed。
7. 业务逻辑漏洞需要人工建模。
8. Nuclei 覆盖率取决于模板集合。
9. ZAP 可能因时间上限停止剩余规则。
10. JavaScript 密钥扫描只覆盖已发现的 JS URL。
11. K8s 审计需要 KUBECONFIG。
12. AI 质量取决于外部模型，当前只完成接口、加密、降级和 mock 验证。

## 第二十三章 生产化建议

正式部署前至少完成：

1. 反向代理和 HTTPS。
2. 修改所有默认密码和密钥。
3. 使用密钥管理系统。
4. 增加 OIDC/SSO 和 RBAC。
5. 将 SSE 改为安全 Cookie 或代理 Header。
6. 增加租户隔离和资产归属。
7. 增加集中式日志、审计归档和告警。
8. 为扫描网络建立独立安全域。
9. 设置组织级速率和并发配额。
10. 建立证据保留和删除制度。
11. 在 AMD64 以外的架构完成独立验收。
12. 建立工具许可证清单和合规审查。

## 第二十四章 二次开发指南

### 24.1 新增扫描器

1. 在 `backend/app/adapters/` 新建适配器。
2. 继承 `BaseAdapter`。
3. 实现 `run()`。
4. 将原始结果转换为 `Finding`。
5. 在 `adapters/__init__.py` 导出。
6. 在 `graph/nodes.py` 增加节点函数。
7. 在 `graph/build.py` 注册节点和边。
8. 在 `NodeGrid.jsx` 和 `i18n.js` 增加显示。
9. 更新 capability 探测。
10. 增加单元测试和靶场验收。

### 24.2 新增风险类型

1. 在 `backend/app/i18n.py` 增加中英文标签。
2. 在 `config/vuln_alias.json` 增加别名。
3. 在 `frontend/src/i18n.js` 增加前端标签。
4. 需要时增加 playbook。
5. 增加 ground truth 和测试。

### 24.3 新增节点

1. 在 `NODE_NAMES` 和 `SCAN_NODES` 或流程列表中增加名称。
2. 在 `NODE_TOOL` 中绑定工具。
3. 在 `NODE_STAGE` 中绑定时间预算。
4. 在 `build_graph` 注册节点。
5. 更新前置节点和汇合边。
6. 更新前端 NodeGrid 和 nodeLabels。
7. 增加状态 reducer 和恢复测试。

### 24.4 新增 API

1. 在 `backend/app/api/` 新建路由。
2. 使用 `get_current_user`。
3. 添加 Pydantic 请求和响应。
4. 添加审计日志。
5. 在 `main.py` 注册 router。
6. 增加 API 测试和前端调用。

## 第二十五章 项目问答

### 25.1 这个项目和普通扫描器有什么区别

普通扫描器负责单点检测；本项目负责多引擎编排、统一数据模型、状态可见、历史记忆、证据链、评估和报告。

### 25.2 为什么用 LangGraph

因为任务存在条件边、状态持久化、取消、恢复和阶段状态。普通函数调用可以做流程，但不适合表达长期运行的图状态。

### 25.3 为什么 Worker 不直接调用浏览器

扫描执行面需要隔离。ZAP 和 OpenVAS 是独立服务，通过 API 或 GMP 调用，避免重型依赖进入 Worker。

### 25.4 为什么不是多 Agent

当前项目是单任务工作流，主要不确定性来自工具条件、预算和资产状态，而不是多个自主角色协作。单图结构更容易审计、恢复和测试。

### 25.5 什么是条件边

根据中间结果选择下一节点。例如发现 OpenAPI 才进入 api_fuzz，发现 6443 才进入 k8s_audit。

### 25.6 为什么未选节点显示 skipped

这是工作流语义。skipped 表示不适用、未选中、缺工具或预算耗尽，不等同于 failed。

### 25.7 Finding 和风险组有什么区别

Finding 是单条工具输出实例，风险组是按资产、端口、类型聚合后的可读风险。

### 25.8 为什么要去重

不同工具会对同一风险重复报告。去重保留证据和来源，避免风险数量被重复放大。

### 25.9 为什么需要置信度

单工具结果可能误报。多来源印证、证据完整度和暴露条件会影响可信程度。

### 25.10 为什么需要证据哈希

证据哈希用于完整性验证，确保下载和报告引用的数据没有被意外修改。

### 25.11 为什么 AI 不能控制扫描

扫描命令需要确定性和授权边界。当前实现允许 AI 在已经通过授权、scope、mode 和 tool_profile 过滤的候选节点中选择下一个，但 AI 不能生成命令或增加候选工具；模型不可用时回退固定安全顺序。

### 25.12 AI 失败会怎样

llm_summarize 标记 skipped，扫描、风险组、证据和报告继续。

### 25.13 为什么要时间预算

扫描目标复杂度不可预测。阶段预算防止单个工具无限占用资源，并保证已有结果可以交付。

### 25.14 partial 是什么意思

任务未完整执行全部节点，但已完成节点、Finding、证据和报告仍然有效。

### 25.15 如何恢复任务

对 failed 或 cancelled 任务调用 resume。系统重算 deadline，并从失败或中断节点继续。

### 25.16 为什么 OpenVAS 默认关闭

资源占用高、镜像大、首次 feed 同步慢，不适合作为所有本地演示的默认依赖。

### 25.17 为什么 K8s 审计常常 skipped

它需要 6443 入口和本地 KUBECONFIG。只发现端口不代表有集群凭据。

### 25.18 为什么 JS 扫描常常 skipped

当前路由只对已发现的 `.js` URL 触发，httpx 不是完整前端爬虫。

### 25.19 为什么 API 扫描常常 skipped

必须发现 Swagger/OpenAPI。没有契约时进行盲目 fuzz 会偏离项目边界。

### 25.20 为什么不进行口令爆破

项目定位是防御侧授权评估。认证分析只做低量、受控、配置化的安全检查。

### 25.21 为什么使用 PostgreSQL

任务、审计、资产快照和 LangGraph checkpoint 都需要可靠持久化。

### 25.22 Redis 用来做什么

Celery broker、结果后端和 SSE Pub/Sub。

### 25.23 SSE 和轮询为什么同时存在

SSE 提供实时性，轮询提供最终一致性。断线后仍能通过任务 API 恢复状态。

### 25.24 为什么报告要有 Markdown、HTML、JSON

JSON 用于机器处理，HTML 用于阅读，Markdown/Mermaid 用于工作流源和二次编辑。

### 25.25 如何判断扫描是否有效

使用 Ground Truth 计算 Recall、Precision、F1、Top-10 真高危占比，并用消融实验比较基线。

### 25.26 多引擎一定比单引擎强吗

不一定。多引擎提升覆盖，但也增加耗时、重复和噪声。因此需要去重、交叉印证和消融实验。

### 25.27 当前最需要继续补强什么

认证覆盖、业务逻辑验证、OpenVAS feed、更多 ground truth、AI 输出质量、公网部署安全和多租户能力。

## 第二十六章 命令速查

启动：

```powershell
.\start.bat
```

完整 profile：

```powershell
.\start-full.bat
```

停止：

```powershell
.\stop.bat
```

查看服务：

```powershell
docker compose ps
```

查看日志：

```powershell
docker compose logs -f backend worker zap
```

运行测试：

```powershell
docker compose --profile test run --rm tests
```

验收：

```powershell
python scripts/acceptance.py
```

重建报告：

```powershell
docker compose exec -T worker python /app/scripts/regenerate_reports.py --task-id <task_id>
```

重建工作流：

```powershell
docker compose exec -T worker python /app/scripts/regenerate_workflows.py --task-id <task_id>
```

## 第二十七章 文件索引

| 文件 | 用途 |
|---|---|
| README.md | 快速入口 |
| PROJECT_SPEC.md | 工程规格 |
| ACCEPTANCE_REPORT.md | 验收证据 |
| DELIVERY_REPORT.md | 交付摘要 |
| SECURITY_BOUNDARIES.md | 安全边界 |
| AUTHORIZATION.md | 授权说明 |
| docs/auth-profiles.md | 认证档案 |
| docs/time-budgets.md | 时间预算 |
| docs/oast.md | OAST |
| docs/openvas.md | OpenVAS |
| docs/evaluation.md | 消融实验 |
| samples/sample_task.json | 任务示例 |
| samples/auth.example.yaml | 通用认证示例 |
| samples/auth.local.yaml | 本机授权与靶场示例 |

## 第二十八章 完整环境变量参考

### 28.1 基础与数据库

| 变量 | 说明 |
|---|---|
| POSTGRES_PASSWORD | PostgreSQL 账号密码 |
| JWT_SECRET | JWT 签名和 AI Key 派生密钥 |
| ADMIN_USERNAME | 初始化管理员用户名 |
| ADMIN_PASSWORD | 初始化管理员密码 |
| API_PORT | Backend 对外端口 |
| FRONTEND_PORT | Frontend 对外端口 |
| DATABASE_URL | SQLAlchemy 数据库连接 |
| REDIS_URL | Celery 和 SSE 使用的 Redis 地址 |

### 28.2 授权、范围和任务

| 变量 | 说明 |
|---|---|
| AUTHORIZATION_FILE | 授权与认证 YAML 路径 |
| AUTHORIZED_SCOPE | 默认示例 scope |
| AUTHORIZATION_FILE | 本机授权配置 |
| MAX_RPS | 请求速率上限 |
| DEFAULT_TIME_PROFILE | 默认时间策略 |
| MAX_TASK_SECONDS | 自定义任务时间上限 |

### 28.3 输出与证据

| 变量 | 说明 |
|---|---|
| OUTPUT_DIR | 任务输出根目录 |
| EVIDENCE_RETENTION_DAYS | 证据建议保留天数 |
| CAPABILITIES_PATH | 工具能力文件路径 |
| VULN_ALIAS_FILE | 漏洞别名文件 |
| PLAYBOOK_DIR | 处置剧本目录 |
| WEAK_CREDENTIALS_FILE | 弱口令字典 |

### 28.4 Web 与网络工具

| 变量 | 说明 |
|---|---|
| ZAP_URL | ZAP REST 地址 |
| ZAP_HOST | ZAP 主机名 |
| ZAP_PORT | ZAP REST 端口 |
| ZAP_API_KEY | ZAP API Key |
| ZAP_MAX_SCAN_MINUTES | ZAP 整次扫描时限 |
| NUCLEI_TAGS | 模板标签过滤 |
| NUCLEI_SEVERITY | Nuclei 严重度过滤 |
| SUBFINDER_TIMEOUT_SECONDS | 子域发现超时 |
| DNSX_TIMEOUT_SECONDS | DNS 解析超时 |
| HTTPX_TIMEOUT_SECONDS | HTTP 探测超时 |
| NMAP_TIMEOUT_SECONDS | Nmap 超时 |
| NIKTO_TIMEOUT_SECONDS | Nikto 超时 |
| WAPITI_TIMEOUT_SECONDS | Wapiti 超时 |
| SCHEMATHESIS_TIMEOUT_SECONDS | API 检查超时 |
| KUBESCAPE_TIMEOUT_SECONDS | K8s 审计超时 |
| GITLEAKS_TIMEOUT_SECONDS | 密钥扫描超时 |
| SUBJACK_TIMEOUT_SECONDS | 接管检查超时 |

### 28.5 OpenVAS

| 变量 | 说明 |
|---|---|
| OPENVAS_ENABLED | 是否启用 OpenVAS |
| OPENVAS_HOST | GMP 主机 |
| OPENVAS_PORT | GMP 端口，默认 9390 |
| OPENVAS_USERNAME | GMP 用户名 |
| OPENVAS_PASSWORD | GMP 密码 |
| OPENVAS_CAFILE | GMP TLS CA 文件 |
| OPENVAS_IMAGE | OpenVAS 镜像 |
| OPENVAS_SKIP_SYNC | 是否跳过 feed 同步 |
| OPENVAS_TIMEOUT_SECONDS | 主机扫描超时 |

### 28.6 验证和 OAST

| 变量 | 说明 |
|---|---|
| OAST_URL | Worker 访问 OAST 的内部地址 |
| OAST_PORT | OAST 宿主机端口 |
| OAST_SECRET | OAST 管理密钥 |
| OAST_PUBLIC_BASE_URL | 目标可访问的回调地址 |
| VALIDATION_MAX_PAGES | 主动验证最大页面数 |
| VALIDATION_MAX_PARAMETERS | 最大参数数 |
| VALIDATION_MAX_REQUESTS | 最大请求数 |

### 28.7 AI

| 变量 | 说明 |
|---|---|
| LLM_ENABLED | 是否默认启用 |
| LLM_BASE_URL | OpenAI 兼容接口 |
| LLM_API_KEY | 初始 API Key |
| LLM_MODEL | 模型名 |
| LLM_BATCH_SIZE | 批量大小 |
| LLM_MAX_TOKENS | 单批最大 Token |

### 28.8 VAS 启动器

| 变量 | 说明 |
|---|---|
| VAS_LAUNCHER | 外部 VAS 启动器路径或 URL |
| VAS_STOPPER | 可选停止器路径 |

## 第二十九章 源码阅读路线

第一次阅读源码时，建议按以下顺序进行。

### 29.1 先看启动入口

1. `docker-compose.yml`
2. `docker-compose.full.yml`
3. `start.bat`
4. `backend/app/main.py`
5. `backend/app/config.py`

这一组文件回答：系统包含哪些服务、端口是什么、环境变量如何注入、API 如何启动。

### 29.2 再看任务入口

1. `backend/app/api/tasks.py`
2. `backend/app/guard.py`
3. `backend/app/db.py`
4. `backend/worker/tasks.py`

这一组文件回答：任务如何创建、授权如何校验、任务如何入队和执行。

### 29.3 再看编排

1. `backend/app/graph/state.py`
2. `backend/app/graph/build.py`
3. `backend/app/graph/nodes.py`
4. `backend/app/budget.py`

这一组文件回答：状态如何合并、19 个节点如何连接、预算如何生效、节点如何跳过和恢复。

### 29.4 再看扫描器

1. `backend/app/adapters/base.py`
2. `backend/app/adapters/factory.py`
3. 各扫描器适配器
4. `backend/app/schemas/finding.py`

这一组文件回答：工具命令如何执行、原始输出如何转换、统一 Finding 如何形成。

### 29.5 最后看数据与展示

1. `backend/app/dedup.py`
2. `backend/app/risk_groups.py`
3. `backend/app/memory.py`
4. `backend/app/report.py`
5. `frontend/src/pages/TaskDetail.jsx`
6. `frontend/src/pages/Report.jsx`

这一组文件回答：风险如何聚合、报告如何生成、前端如何展示执行过程。

## 第三十章 完整演示手册

### 30.1 演示准备

1. 启动系统。
2. 打开总览页。
3. 确认扫描引擎矩阵显示主要工具在线。
4. 准备 DVWA 和 Mock 两个靶场。
5. 准备一个认证档案和一个无认证档案。

### 30.2 演示流程

1. 展示登录和 JWT。
2. 展示总览指标、实时数据流和引擎矩阵。
3. 新建 DVWA 扫描。
4. 展示风险声明和授权确认。
5. 选择 full_agent、standard、safe。
6. 启动任务。
7. 在任务详情中讲解 19 个节点。
8. 展示 SSE 状态变化。
9. 解释 skipped 和 failed 的区别。
10. 展示风险组聚合。
11. 展开 Finding 证据和哈希。
12. 展示历史变化。
13. 展示 AI 自动降级。
14. 打开报告页。
15. 展示深色工作流图和 HTML 报告。
16. 展示下载按钮。

### 30.3 条件边演示

目标使用 `http://mock:8000`，auth_ref 使用 `local-mock`。

该目标用于演示：

1. OpenAPI 文档发现。
2. API 契约检查。
3. 6443 端口发现。
4. 无 KUBECONFIG 时 K8s 节点 skipped。
5. 多类型 Finding 和风险组。

### 30.4 取消与恢复演示

1. 启动一个较长任务。
2. 在任务详情点击取消。
3. 观察 Worker 取消标记和子进程终止。
4. 点击从断点恢复。
5. 展示已成功节点复用。
6. 展示最终报告。

### 30.5 降级演示

1. 关闭 AI 或使 AI 返回错误。
2. 重新运行任务。
3. llm_summarize 显示 skipped。
4. 扫描、风险组、证据和报告仍正常生成。

### 30.6 离线演示

1. 断开外网。
2. 保持本地 Docker 服务。
3. 使用 DVWA 和 Mock。
4. 关闭 AI。
5. 展示本地扫描、报告和 Mermaid 兜底。

## 第三十一章 交付验收清单

### 31.1 运行

- Docker Compose 配置通过。
- 前端可登录。
- API 健康。
- Postgres、Redis、Worker healthy。
- ZAP 在线。
- OpenVAS 在 full profile 下 available。

### 31.2 功能

- 创建 DVWA 任务。
- 创建 Mock 任务。
- 认证扫描成功。
- Finding 可以展开。
- 风险组可以展开。
- 报告 HTML 加载。
- 工作流 PNG 加载。
- JSON 可以下载。
- 取消和恢复可用。
- 历史资产可用。
- AI 设置不回显密钥。

### 31.3 安全

- 未勾选授权返回 403。
- 未知 auth_ref 返回 403。
- max_rps 超过 5 返回 403。
- 未授权 redirect 被拦截。
- 元数据地址被拦截。
- JWT 无效返回 401。
- Worker 无宿主机端口。

### 31.4 质量

- 66 个自动化测试通过。
- 前端生产构建通过。
- Docker 默认和 full config 通过。
- 报告和工作流视觉检查通过。
- 离线包校验通过。

## 第三十二章 深度设计篇说明

### 32.1 为什么需要第二版说明书

第一版说明书已经覆盖了系统的功能、节点、工具、API、部署和验收，但它更偏向“使用手册”和“能力目录”。当读者需要回答以下问题时，仅说明“调用了 ZAP”或“使用 LangGraph”是不够的。

1. 为什么用 FastAPI，而不是把 API、编排和扫描写在一个进程里。
2. 为什么扫描任务先进入 PostgreSQL，再通过 Celery 投递，而不是在 HTTP 请求中直接运行。
3. 为什么用 LangGraph，而不是普通 if/else、状态机库或多 Agent 框架。
4. 为什么工具适配器要统一继承 `BaseAdapter`，统一返回 `Finding`。
5. 每个外部工具究竟通过 CLI 子进程、REST API、GMP XML 还是 Python 库调用。
6. 工具输出如何解析、如何过滤越界结果、如何去做重和评分。
7. 前端如何把轮询、SSE、数据库状态和工作流图组合起来。
8. 当前系统凭什么证明结果真实有效，又需要哪些实验才能证明可以替代人工。

第二版在原文档之后增加深度设计篇，不删除使用说明。这样同一份文档既能指导操作，也能支持答辩、代码审查、项目验收和后续科研实验。

### 32.2 证据等级

本文将结论分为三个证据等级。

| 等级 | 含义 | 文档写法 |
|---|---|---|
| 已实现 | 当前代码存在，且运行路径可以在 Compose 环境中触发 | 直接描述，并给出源码位置或调用链 |
| 已测试 | 有自动化测试、验收脚本或实际任务记录 | 给出测试名称、任务 ID 或验证命令 |
| 待验证 | 设计上成立，但尚未完成足够样本的独立实验 | 明确写为实验计划或限制，不写成既成事实 |

例如，“系统可以调用 OpenVAS 并生成 Finding”属于已实现；“OpenVAS 在真实生产资产上的检出率高于人工”属于待验证。两者不能混写。

### 32.3 本文的源码坐标

后续各章使用“层、模块、函数”三层坐标。

| 层 | 主要目录 | 解决的问题 |
|---|---|---|
| 运行层 | `docker-compose.yml`、`docker-compose.full.yml`、Dockerfile、启动脚本 | 服务如何启动、隔离和互相访问 |
| 接口层 | `backend/app/api/`、`backend/app/schemas/` | 请求如何进入、校验和返回 |
| 编排层 | `backend/app/graph/`、`backend/app/budget.py` | 任务如何按状态推进、跳过和恢复 |
| 工具层 | `backend/app/adapters/`、`backend/app/capabilities.py` | 外部工具如何被执行和解析 |
| 语义层 | `dedup.py`、`risk_groups.py`、`memory.py`、`ai_service.py` | 结果如何归一、融合、解释和记忆 |
| 交付层 | `evidence.py`、`report.py`、`workflow_image.py` | 如何形成可复核的证据与报告 |
| 展示层 | `frontend/src/` | 用户如何配置、观察和下载结果 |

## 第三十三章 从需求到设计：整体框架与关键取舍

### 33.1 需求约束

本项目的设计不是先选技术再找场景，而是由一组硬约束反推出来的。

| 约束 | 业务含义 | 对架构的影响 |
|---|---|---|
| 必须授权后扫描 | 防止误扫、越权和法律风险 | 提交任务必须有授权确认，入口和执行节点双重校验 |
| 本地优先 | 演示现场可能没有外网，不能依赖云平台 | Docker Compose、自托管数据库、本地报告、关闭 AI 仍可运行 |
| 工具异构 | 不同工具有 CLI、REST、GMP 和 JSON/XML/文本输出 | 引入 Adapter 抽象和统一 Finding |
| 长任务 | ZAP、OpenVAS、Wapiti 可能运行几十秒到数十分钟 | API 与 Worker 分离，任务异步化，引入时间预算 |
| 可观察 | 用户需要知道每个节点做了什么、为何跳过 | LangGraph 节点状态、执行轨迹、SSE、工作流图 |
| 可恢复 | 长任务失败或取消后不应全部重跑 | PostgreSQL checkpoint、resume、已完成节点复用 |
| 可复核 | 漏洞报告不能只有一句自然语言 | 原始证据、证据哈希、来源、指纹、处置剧本 |
| 可降级 | 外部工具或 AI 不可用时不能使全系统失效 | capability 探测、节点 skipped、AI 失败不影响主链路 |
| 安全边界 | 不能成为任意网络代理或漏洞利用平台 | Scope Guard、重定向检查、元数据地址拦截、无利用载荷 |
| 可扩展 | 后续可以新增工具和风险类型 | 适配器、工具注册、别名映射、测试契约 |

### 33.2 分层框架

系统采用“控制面与执行面分离、接口与工具分离、原始结果与解释分离”的三条主线。

```text
用户
  |
  v
React 控制台
  |
  v
FastAPI 控制面 ---- PostgreSQL（任务/用户/审计/快照/checkpoint）
  |                         |
  |                         +---- 历史记忆
  |
  +---- Redis ---- Celery ---- Worker 执行面
                                  |
                                  +---- LangGraph 编排
                                  |
                                  +---- 本地 CLI 适配器
                                  |       Subfinder / dnsx / httpx / Nmap / Nuclei ...
                                  |
                                  +---- 外部 REST 服务
                                  |       ZAP
                                  |
                                  +---- 外部 GMP 服务
                                  |       OpenVAS
                                  |
                                  +---- 可选增强
                                          OAST / AI / 报告渲染
```

控制面负责“用户能做什么”，执行面负责“扫描如何发生”。这样划分的原因是：

1. Web API 不应被重型扫描阻塞。HTTP 请求只做校验、入库和投递，约几百毫秒返回。
2. 扫描进程需要不同的资源、生命周期和安全策略。Worker 可以单独重启，不影响登录和报告查询。
3. 外部工具升级不应导致 API 代码变化。适配器承担版本差异和输出差异。
4. 任务状态必须脱离单个 Python 进程存在。数据库记录是最终事实，SSE 只是实时增量。

### 33.3 八条核心设计原则

#### 原则一：确定性优先

工具命令、授权范围、候选路由条件、评分公式和报告主内容仍由确定性程序生成。AI 可在确定性候选集合存在之后选择“下一个候选节点”，但不能增加目标、生成命令、修改速率、绕过 Scope Guard 或调用候选集合之外的工具。

这样设计的原因是安全扫描属于高影响操作。模型幻觉一旦进入命令生成，可能造成越界目标访问、异常载荷或不可复现结果。

#### 原则二：所有外部结果都必须归一化

每个工具都有自己的字段名和严重度体系。系统在适配器边界把结果统一成 `Finding`，后续的去重、评分、风险组、历史、证据和前端只依赖统一模型。

如果把解析逻辑散落在节点、API 和前端，任何工具字段变化都会引发多处修改。适配器模式把变化限制在一个文件内。

#### 原则三：状态只做增量写入

LangGraph 节点不返回整个状态，而是只返回本节点产生的变化。列表字段使用追加 reducer，字典字段使用合并 reducer。这样节点可以独立测试，也能避免多个节点互相覆盖。

#### 原则四：条件不满足不是错误

“没有 JS 文件”“没有 OpenAPI”“没有 KUBECONFIG”“OpenVAS 未启用”是业务条件，不是扫描器故障。因此系统使用 `skipped` 表示不适用或未选中，使用 `failed` 表示已经开始执行但发生异常。两者在界面、错误统计和恢复策略上不同。

#### 原则五：原始证据与解释分离

`findings.json`、`evidence/*.json` 和风险组中的 `instances` 是事实层；AI 摘要和修复建议是解释层。解释层不能删除、覆盖或伪造事实层。

#### 原则六：所有外部地址再次做 Scope Guard

初始目标通过授权范围校验不代表重定向和工具输出可信。系统对重定向、OpenAPI servers、工具 Finding 的 URL 再执行范围校验，防止 DNS 重绑定和扫描器被当作代理。

#### 原则七：可用能力必须由运行环境探测

前端不能硬编码“工具在线”。Worker 启动后执行版本命令、HTTP 健康检查和 GMP 查询，写入 `/output/capabilities.json`。节点通过该文件判断是否执行，前端通过 API 显示状态。

#### 原则八：失败可以降级，事实不能丢失

ZAP 超时、AI 失败或某个工具缺少时，系统保留已经完成的 Finding，并把节点标记为 skipped 或 failed。报告仍生成，任务可恢复。

### 33.4 关键架构决策表

| 决策 | 选择 | 原因 | 代价 |
|---|---|---|---|
| 应用形态 | 本地 Docker Compose | 可离线、环境一致、便于验收 | 首次构建大，资源消耗高 |
| API | FastAPI | Pydantic 校验、异步 SSE、自动 OpenAPI 文档 | 需要自行设计任务队列和权限 |
| 编排 | LangGraph StateGraph | 显式状态、条件路由、checkpoint、恢复 | 学习成本高于普通函数 |
| 队列 | Celery + Redis | 长任务异步、重试、与 Web 进程解耦 | 多一套 broker 和监控 |
| 主数据库 | PostgreSQL | JSON 与关系数据并存、可靠事务、LangGraph checkpoint | 运维成本高于 SQLite |
| 扫描接入 | 子进程 + REST + GMP | 兼容异构工具，保持许可证隔离 | 需要捕获进程、超时和解析错误 |
| 结果模型 | Finding + Risk Group | 单实例可复核，聚合结果可阅读 | 需要维护两套语义 |
| 报告 | Jinja2 HTML + JSON + Mermaid | 人类可读、机器可读、离线可编辑 | 模板和渲染需要测试 |
| 前端 | React SPA + Vite | 状态交互复杂、组件化、构建简单 | 需要处理令牌和实时连接 |
| AI | 可选 OpenAI 兼容接口 | 可接入云端或本地模型，默认关闭 | 输出质量和数据治理依赖外部 |

### 33.5 为什么不是单体脚本

单体脚本可以用几十行完成“subfinder -> nmap -> nuclei -> 报告”，但本项目需要同时满足：

1. 在浏览器中查看每个节点的实时状态。
2. 取消一个正在运行的 ZAP 或 OpenVAS 子进程。
3. 失败后从某个节点继续，不重复已完成节点。
4. 同一个任务产生证据、JSON、HTML 和 PNG。
5. 在无 AI、无 OpenVAS、无网络的情况下仍能降级运行。
6. 对工具输出做授权过滤和统一评分。

这些需求已经超过一个脚本的生命周期管理能力，因此采用服务化架构。

### 33.6 为什么不是多 Agent

当前任务的核心不是多个自主角色协商，而是一个有明确边界的长事务。所有扫描节点都是确定性函数，输入是资产和目标配置，输出是 Finding。多 Agent 会引入额外的提示词、角色通信和不可预测决策，却不会自动提高扫描质量。

未来可以把“误报复核”“报告审阅”作为独立 Agent 实验，但前提是它们只读事实层，并且其结论必须经过确定性规则和人工复核。当前主链路不依赖这种设计。

## 第三十四章 技术栈、工具链与版本控制

### 34.1 技术栈全景

| 层 | 技术 | 当前版本 | 作用 | 选型原因 |
|---|---|---|---|---|
| 前端运行时 | React | 18.3.1 | 构建控制台 SPA | 组件化、状态模型清晰、生态成熟 |
| 前端构建 | Vite | 6.0.5 | 开发服务器和生产构建 | 启动快、配置少、支持现代模块 |
| 样式 | Tailwind CSS | 3.4.17 | 原子类与设计令牌 | 与 JSX 组合方便，能快速建立一致界面 |
| 图标 | Lucide React | 0.468.0 | 工具、状态和导航图标 | 统一线性图标语义，避免手绘 SVG |
| 路由 | React Router | 7.18.5 | 页面切换和受保护路由 | SPA 路由标准方案 |
| 图渲染 | Mermaid | 12.2.0 | 前端工作流兜底渲染 | 无需 Graphviz 服务，可离线 |
| API 框架 | FastAPI | 0.115.6 | REST、JWT 依赖、SSE | 类型校验与自动文档完善 |
| 数据校验 | Pydantic | 2.10.4 | 请求、配置、Finding 模型 | 与 FastAPI 深度集成 |
| 配置 | pydantic-settings | 2.7.1 | 环境变量与 `.env` | 类型转换和默认值集中管理 |
| ORM | SQLAlchemy | 2.0.36 | 用户、任务、快照和缓存的持久化 | 事务清晰，支持 JSON 与 PostgreSQL |
| PostgreSQL 驱动 | psycopg | 3.2.3 | 连接 PostgreSQL | 与 SQLAlchemy 2.x 兼容 |
| 身份 | PyJWT + bcrypt | 2.10.1 / 4.2.1 | JWT 与密码哈希 | 轻量、成熟、易于本地部署 |
| 队列 | Celery + Redis | 5.4.0 / 5.2.1 | 异步任务与事件总线 | 长任务解耦、支持重试 |
| 编排 | LangGraph | 0.2.62 | 节点状态机和 checkpoint | 显式状态、条件边和恢复 |
| checkpoint | langgraph-checkpoint-postgres | 2.0.10 | PostgreSQL 状态持久化 | 任务中断后可恢复 |
| 报告 | Jinja2 | 3.1.5 | 生成深色 HTML 报告 | 模板可控、无前端依赖 |
| 工作流图 | mermaidx | 0.10.1 | 后端 Mermaid 转 PNG | 本地渲染、无需在线服务 |
| 外部模型 | OpenAI 兼容 HTTP API | 可选 | 风险语义归并与解读 | 同时支持云端和本地兼容服务 |
| 浏览器 | Chromium/Edge/Firefox | 由用户环境决定 | 控制台运行环境 | 标准 Web 技术 |

### 34.2 后端依赖分组

后端基础镜像只安装 API、数据库、队列、编排和报告依赖。扫描 CLI 不进入 API 镜像，而是由 Worker 镜像提供。

```text
fastapi==0.115.6
uvicorn[standard]==0.34.0
pydantic==2.10.4
pydantic-settings==2.7.1
sqlalchemy==2.0.36
psycopg[binary]==3.2.3
PyJWT==2.10.1
bcrypt==4.2.1
celery[redis]==5.4.0
redis==5.2.1
langgraph==0.2.62
langgraph-checkpoint-postgres==2.0.10
jinja2==3.1.5
mermaidx==0.10.1
PyYAML==6.0.2
httpx==0.28.1
cryptography==50.0.2
```

Worker 额外安装 `zaproxy`、`python-gvm`、`schemathesis`、`wapiti3`。这些依赖被隔离在 Worker 镜像中，避免 API 进程承担扫描工具的运行风险。

### 34.3 前端依赖与构建链

前端由 Vite 构建为静态文件，再由 Nginx 提供。开发模式下 Vite 将 `/api` 和 `/health` 代理到 `localhost:8000`；生产模式下 Nginx 将 `/api/` 和 `/health` 代理到 Docker 服务 `backend:8000`。

```javascript
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": "http://localhost:8000",
      "/health": "http://localhost:8000",
    },
  },
});
```

Nginx 配置关闭了代理缓冲和缓存，并设置长读超时。原因是 SSE 事件流和报告下载需要持续连接，不能被默认代理缓冲吞掉。

```nginx
location /api/ {
  proxy_pass $backend_upstream;
  proxy_http_version 1.1;
  proxy_buffering off;
  proxy_cache off;
  proxy_read_timeout 3600s;
}
```

### 34.4 扫描工具版本固定

Worker Dockerfile 使用固定版本和 SHA-256 校验来降低供应链漂移。

| 工具 | 固定版本 | 调用形态 |
|---|---:|---|
| Subfinder | 2.17.0 | CLI 子进程 |
| dnsx | 1.3.1 | CLI 子进程 |
| httpx | 1.12.0 | CLI 子进程，失败时使用 Python httpx 兜底探测 |
| Nmap | 7.93 | CLI 子进程 |
| Nuclei | 3.11.1 | CLI 子进程 |
| Subjack | 3.1.0 | CLI 子进程 |
| Gitleaks | 8.30.1 | CLI 子进程 |
| Kubescape | 4.0.16 | CLI 子进程 |
| Nikto | 2.6.1 | CLI 子进程 |
| Nuclei Templates | 10.5.1 | 构建时固化模板 |
| ZAP | 2.17.0 | 独立容器 REST API |
| OpenVAS | 26.07.27.01 镜像 | 独立容器 GMP |

固定版本的意义不是“永远不升级”，而是让每次构建、报告和实验都能复现同一工具行为。升级应作为单独变更处理，并重跑适配器测试和验收用例。

### 34.5 工具安装的供应链设计

Worker Dockerfile 先尝试镜像地址下载，再回退到官方 GitHub 地址；每个压缩包执行 SHA-256 校验后再安装。这样可以兼顾网络环境，又避免直接信任任意下载内容。

```dockerfile
curl -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/nuclei/tool.zip || \
  curl -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/nuclei/tool.zip
echo "${NUCLEI_SHA256}  /tmp/nuclei/tool.zip" | sha256sum -c -
unzip -q /tmp/nuclei/tool.zip -d /tmp/nuclei
install -m 0755 /tmp/nuclei/nuclei /opt/bin/nuclei
```

### 34.6 许可证隔离

`python-gvm` 和 `gvm-tools` 按文档属于 GPL 组件。项目没有在应用 Python 代码中 import `gvm`，而是只执行 `gvm-cli` 可执行文件。OpenVAS 本身是独立容器；ZAP 也通过独立服务 REST API 调用。

这是一种工程隔离，不等同于法律意见。商业交付前仍需根据实际分发方式、修改情况和组织政策完成许可证审查。

## 第三十五章 容器运行时、服务拓扑与启动机制

### 35.1 Compose 服务分解

基础 Compose 中的服务可以分为五类。

| 类别 | 服务 | 关键职责 |
|---|---|---|
| 持久化 | postgres | 用户、任务、审计、快照、AI 配置和 checkpoint |
| 消息 | redis | Celery broker/result 与 SSE Pub/Sub |
| 控制面 | backend、frontend | API 与控制台 |
| 执行面 | worker | LangGraph 和扫描适配器 |
| 外部工具/实验 | zap、oast、dvwa、mock | Web 扫描、回调验证和靶场 |

`docker-compose.full.yml` 再叠加 `openvas`，并把 backend/worker 的 `OPENVAS_ENABLED` 设为 true。

### 35.2 启动顺序与健康依赖

Compose 通过 `depends_on.condition` 表达启动依赖。

1. postgres 和 redis 必须先通过健康检查。
2. backend 依赖 postgres、redis 健康。
3. worker 依赖 postgres、redis、zap、oast 健康。
4. frontend 依赖 backend 健康。
5. full profile 下 worker 依赖 openvas 健康，并等待 `start_period` 结束。

这是一种“可启动性保证”，不是完整的服务编排系统。应用仍需要自己处理短时重连、工具不可用和任务恢复。

### 35.3 网络暴露面

宿主机只映射必要端口。

| 服务 | 映射 | 原因 |
|---|---|---|
| frontend | `3000:80` | 用户访问控制台 |
| backend | `8000:8000` | API 和 OpenAPI 文档 |
| DVWA | `8081:80` | 实验访问 |
| Mock | `18000:8000`、`16443:6443` | 条件边测试 |
| OAST | `127.0.0.1:18001:8001` | 本机回调测试 |
| worker | 无 | 不直接暴露执行面 |
| postgres/redis/zap | 无默认宿主机映射 | 只在内网服务名访问 |
| OpenVAS | 无宿主机映射 | Worker 通过容器网络访问 |

Worker 不映射端口，减少外部直接触发扫描执行面的风险。ZAP 仅允许容器网络内部访问；其 API Key 通过 Compose 环境变量注入。

### 35.4 数据卷设计

| Volume | 持久化内容 | 是否包含敏感数据 |
|---|---|---|
| postgres_data | 任务、用户、审计、快照、AI Key 密文、checkpoint | 是 |
| redis_data | 队列和 SSE 中间状态 | 低到中 |
| output_data | HTML/JSON/PNG/Mermaid/证据 | 是，可能包含目标响应 |
| zap_data | ZAP 工作数据 | 中 |
| oast_data | 回调 token 和命中记录 | 是 |
| openvas_data | GMP 数据库、CA 和 feed | 是 |

删除数据卷前必须先确认报告和证据是否可以删除。`docker compose down` 默认保留 volume，`down -v` 才会删除持久化数据。

### 35.5 只读根文件系统与临时目录

backend、worker、oast 和 mock 都启用了 `read_only: true`，并使用 `tmpfs` 存放临时文件。Worker 还设置了：

```yaml
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
init: true
```

这样可以降低容器被扫描结果、临时文件或工具输出影响后修改根文件系统的风险。Gitleaks 和 Wapiti 需要临时目录，因此 Worker 使用 `/tmp` tmpfs；这也避免扫描产生的临时文件长期留在容器层。

### 35.6 Windows 启动脚本的完整流程

`start.bat` 先检查 Docker 和 Docker Compose v2，再调用 `ensure-docker.ps1` 启动或等待 Docker Desktop。随后读取 `.env` 中需要用于输出和分支判断的值。

```powershell
if /I "%OPENVAS_ENABLED%"=="true" (
  docker compose -f docker-compose.yml -f docker-compose.full.yml ^
    --profile full --profile dvwa --profile mock up -d --build
) else (
  docker compose --profile dvwa --profile mock up -d --build
)
```

启动完成后，脚本轮询 `/health` 最长 180 秒，然后调用 VAS 控制器启动可选外部程序。

### 35.7 VAS 启动器的进程模型

VAS 启动器支持 `.exe`、`.cmd`、`.bat`、`.ps1` 和 HTTP(S) URL。启动脚本把启动命令分派给独立进程，并将 PID 写入 `.vas-launcher.pid`。停止时优先调用 `VAS_STOPPER`，未配置停止器时终止已记录的 PID。

启动器不把 VAS 放进 Compose，因为 VAS 可能是 Windows GUI 程序或第三方安装包，不属于当前仓库构建产物。适配器只负责控制生命周期，不假设 VAS 的内部接口。

### 35.8 OpenVAS 的独立服务设计

OpenVAS 的镜像默认以单容器模式运行，GMP 可能只监听 Unix socket，而不是 TCP 端口。`scripts/openvas-entry.sh` 先启动上游服务，等待 `/run/gvmd/gvmd.sock` 出现，然后用 `socat` 建立 TLS TCP 代理到 9390。

```bash
socat \
  OPENSSL-LISTEN:9390,reuseaddr,fork,verify=0,\
cert=/var/lib/gvm/CA/servercert.pem,\
key=/var/lib/gvm/private/CA/serverkey.pem \
  UNIX-CONNECT:/run/gvmd/gvmd.sock &
```

Worker 只读取 OpenVAS 数据卷中的 CA 文件并执行 `gvm-cli`。这样既保持 GMP 兼容性，也避免把 OpenVAS 的完整运行时装进 Worker。

## 第三十六章 后端应用框架与启动生命周期

### 36.1 FastAPI 应用组成

`backend/app/main.py` 是整个 API 进程的装配入口。它没有把业务写在路由函数里，而是把职责分为：

1. 应用生命周期：建表、迁移、初始化管理员、回填资产快照。
2. 中间件：CORS。
3. 路由注册：认证、任务、事件、Finding、报告、历史、AI、审计和健康检查。
4. 依赖注入：数据库 Session 与当前用户。

这种结构使 API 文件只负责协议转换和权限入口，具体扫描逻辑由 Worker 和 LangGraph 承担。

### 36.2 启动阶段的真实顺序

FastAPI 使用 `lifespan` 异步上下文管理器。启动时执行以下动作：

```python
@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    db: Session = SessionLocal()
    try:
        if db.query(User).filter(User.username == settings.admin_username).first() is None:
            db.add(User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
            ))
            db.commit()
        backfill_snapshots(db)
    finally:
        db.close()
    yield
```

这里的设计原因是：初始化必须发生在接收请求之前，否则第一个请求可能遇到不存在的管理员或缺失的旧表字段。`backfill_snapshots` 让升级后的数据库可以从已有任务补建资产历史，而不是要求用户重新扫描。

### 36.3 配置对象的加载与合并

`Settings` 使用 `pydantic-settings` 读取环境变量，多数字段有本地默认值。Compose 注入的环境变量优先于 `.env` 中的值，而 `.env` 又优先于代码默认值。

```python
class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://scanner:scanner@postgres:5432/scanner"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "change-me"
    max_task_seconds: int = 7200
    zap_url: str = "http://zap:8090"
    openvas_enabled: bool = False
    llm_enabled: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
```

把配置集中在一个对象中，可以避免节点、适配器和 API 各自读取 `os.getenv` 造成默认值不一致。例外是能力探测和外部服务 URL，因为它们需要在测试中被动态替换。

### 36.4 数据库连接和会话边界

SQLAlchemy Engine 使用 `pool_pre_ping=True`，防止连接池拿到已经失效的 PostgreSQL 连接。每个 FastAPI 请求通过 `get_db()` 获得独立 Session，并在请求结束时关闭。

```python
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)
```

`expire_on_commit=False` 的设计目的是让任务对象在 commit 后仍然能安全读取用于响应的字段，减少额外查询。Worker 也使用独立的 `SessionLocal`，不共享 Web 请求 Session。

### 36.5 轻量迁移的原因

项目使用 `Base.metadata.create_all` 处理首次建表，并使用 `migrate_schema()` 的 PostgreSQL `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` 处理增量字段。

这不是完整的 Alembic 迁移体系，优点是本地部署简单、旧数据库可以直接升级；缺点是复杂字段变更、数据回填和回滚没有版本化记录。生产化时应迁移到 Alembic 或等价迁移工具，并为每条迁移增加测试和回滚方案。

### 36.6 为什么路由层不直接执行扫描

创建任务 API 只执行以下步骤：

```python
decision = validate_task(payload)
task = Task(id=str(uuid.uuid4()), status="queued", node_status=initial_node_status())
db.add(task)
db.add(AuditLog(action="task.create", ...))
db.commit()
queued = celery_app.send_task("run_task", args=[task.id])
task.celery_task_id = queued.id
db.commit()
return _response(task)
```

这段代码体现了“先持久化，再投递”的 outbox 思路。即使 Celery 投递失败，任务记录仍然存在，管理员可以检查并人工重投；反过来如果先投递再入库，Worker 可能拿到一个不存在的 task_id。

严格生产环境还应增加事务 outbox、幂等键和重复投递检测。当前版本使用数据库记录 + 管理员排错，属于本地部署规模下的简化实现。

## 第三十七章 API 设计与请求链

### 37.1 API 分层

API 层只做四件事：

1. 用 Pydantic 解析和校验请求。
2. 用 `get_current_user` 验证 JWT。
3. 查询或写入数据库。
4. 调用服务函数或投递 Celery。

因此 API 业务较少，但每个端点的权限、状态码和副作用需要明确。

### 37.2 认证流程

登录端点接收用户名和密码，查询 `users` 表，使用 bcrypt 验证密码，生成带 `sub` 和 `exp` 的 JWT。

```python
@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid username or password")
    return TokenResponse(access_token=create_access_token(user.username))
```

除 `/health` 和 `/api/auth/login` 外，其余 API 使用 `get_current_user`。该依赖同时支持 `Authorization: Bearer` 和 SSE 的查询参数 token。查询参数方案在公网部署前必须替换为安全 Cookie 或代理注入 Header。

### 37.3 完整 API 端点表

| 方法 | 路径 | 鉴权 | 请求重点 | 内部动作 |
|---|---|---|---|---|
| POST | `/api/auth/login` | 否 | username/password | 查询用户、bcrypt 校验、签发 JWT |
| GET | `/health` | 否 | 无 | 返回 `{"status":"ok"}` |
| GET | `/api/capabilities` | 是 | 无 | 读取能力文件或重新探测 |
| GET | `/api/auth-profiles` | 是 | 无 | 读取 YAML，返回非敏感认证摘要 |
| POST | `/api/tasks` | 是 | target、auth_ref、预算、授权确认 | validate_task、入库、审计、投递 run_task |
| GET | `/api/tasks/{id}` | 是 | task_id | 查询任务并组装 TaskResponse |
| POST | `/api/tasks/{id}/cancel` | 是 | task_id | 写 Redis cancel 标记、revoke、更新状态 |
| POST | `/api/tasks/{id}/resume` | 是 | task_id | 仅 failed/cancelled，重算 deadline、投递 resume_task |
| GET | `/api/tasks/{id}/events` | token | task_id | 校验 JWT，订阅 Redis Pub/Sub，输出 SSE |
| GET | `/api/tasks/{id}/findings` | 是 | severity 可选 | 读取 Task.findings 并过滤严重度 |
| GET | `/api/tasks/{id}/report` | 是 | format=html/json | 读取 HTML 文件或 report_json |
| GET | `/api/tasks/{id}/workflow.png` | 是 | task_id | 返回鉴权 PNG |
| GET | `/api/tasks/{id}/graph.mmd` | 是 | task_id | 返回 Mermaid 源 |
| GET | `/api/tasks/{id}/evidence/{fingerprint}` | 是 | fingerprint | 查证据索引、校验 SHA-256、返回 JSON |
| GET | `/api/history/tasks` | 是 | limit | 最近任务，limit 上限 500 |
| GET | `/api/history/assets` | 是 | 无 | 聚合资产快照 |
| GET | `/api/history/assets/{asset_key}` | 是 | asset_key、limit | 资产快照时间线 |
| GET | `/api/ai/config` | 是 | 无 | 返回配置但只显示 Key 是否已配置 |
| PUT | `/api/ai/config` | 是 | enabled/base_url/model/api_key | Fernet 加密保存并审计 |
| POST | `/api/ai/test` | 是 | 请求配置或沿用已保存配置 | 调用 OpenAI 兼容端点 |
| GET | `/api/audit` | 是 | limit | 查询审计记录 |

### 37.4 任务创建校验链

提交任务时，`TaskCreate` 首先执行 Pydantic 校验：

1. `mode` 只能是 `passive/active/full`。
2. `tool_profile` 只能是四个固定值。
3. 时间策略只能是 `quick/standard/deep`。
4. 自定义时间必须在 60 到 7200 秒之间。
5. OAST 只在 `validation_level=deep` 时允许。

随后 `validate_task` 再做安全校验：

1. `authorization_confirmed` 必须为 true。
2. `max_rps` 必须在 1 到 5。
3. 自定义时间不能超过服务端 `MAX_TASK_SECONDS`。
4. 认证引用必须存在，或者使用 `none`。
5. scope 和 allowed CIDR 被读取。
6. 目标主机解析结果必须落在允许 CIDR 内。
7. 元数据地址和未显式授权的私网地址被拒绝。

Pydantic 负责协议合法性，Guard 负责授权和网络边界，两者不能合并。这样后续新增 API 或内部调用时可以复用同一套安全规则。

### 37.5 取消 API 的语义

取消不是简单地把数据库状态设为 `cancelled`。系统执行三件事：

```python
redis_client.set(f"cancel:{task_id}", "1", ex=3600)
if task.celery_task_id:
    celery_app.control.revoke(task.celery_task_id, terminate=False)
if task.status in {"queued", "running", "resuming"}:
    task.status = "cancelled"
```

Redis 标记供节点和 `BaseAdapter._run` 轮询；Celery revoke 阻止尚未开始的排队任务；数据库状态为前端提供即时反馈。因为 revoke 不保证已经运行的子进程立刻停止，真正的子进程清理由适配器的 cancel checker 完成。

### 37.6 恢复 API 的语义

只有 `failed` 或 `cancelled` 任务可以恢复。恢复时 API 重新设置 deadline，投递 `resume_task`。Worker 尝试从 checkpoint 读取状态；如果 checkpoint 不可用，则读取数据库保存的 `resume_state`；如果两者都没有，则从初始状态重新执行。

恢复不是重复执行全部节点。已完成扫描节点如果仍在 checkpoint 中，会被标记为复用；失败节点或最早的 pending/cancelled 节点作为起点。

### 37.7 SSE 协议的实现

SSE 端点从查询参数取 JWT，验证用户后订阅 Redis 频道：

```python
@router.get("/{task_id}/events")
async def task_events(task_id: str, request: Request):
    token = request.query_params.get("token", "")
    if not token:
        raise HTTPException(status_code=401, detail="token required")
    username = decode_token(token)
    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(f"task:{task_id}:events")
    ...
    return StreamingResponse(stream(), media_type="text/event-stream")
```

前端用 `EventSource` 接收事件，并将事件按节点合并。SSE 只提供实时性，任务最终状态仍从数据库读取；这保证连接断开或事件丢失时不会丢掉任务。

### 37.8 错误码设计

| 状态码 | 典型原因 | 处理建议 |
|---:|---|---|
| 200 | 查询成功 | 直接展示 |
| 202 | 任务已接收，尚未执行 | 通过 task_id 轮询或 SSE |
| 401 | 未登录、JWT 过期、用户不存在 | 清除令牌并回到登录页 |
| 403 | 未授权确认、scope 不允许、速率超限 | 展示安全错误，不重试 |
| 404 | 任务、报告、工作流或证据不存在 | 检查任务状态和输出目录 |
| 409 | 恢复任务状态不允许，或证据哈希不匹配 | 不自动重试，人工检查 |
| 422 | Pydantic 字段格式错误 | 修正请求字段 |
| 502 | AI 连接失败 | 降级并保留确定性结果 |
| 500 | 未处理服务异常 | 查看 backend/worker 日志 |

## 第三十八章 数据模型与持久化设计

### 38.1 数据模型总览

| 表 | 作用 | 关键字段 |
|---|---|---|
| users | 登录用户 | username、password_hash |
| tasks | 扫描任务及结果索引 | target、auth_ref、status、node_status、findings、report_json、resume_state |
| audit_logs | 用户操作审计 | username、action、target、task_id、detail |
| asset_snapshots | 资产历史快照 | asset_key、target、risk_types、severity_counts |
| ai_config | AI 配置 | enabled、base_url、model、api_key_ciphertext |
| ai_analysis_cache | AI 结果缓存 | cache_key、model、payload |

### 38.2 为什么任务大字段使用 JSON

`findings`、`risk_groups`、`node_status`、`resume_state` 等字段使用 PostgreSQL JSON 列。原因是这些数据的结构随工具和实验阶段演化，且通常按任务整体读取。如果把它们拆成几十张关系表，早期开发成本会显著增加。

关系型字段保留给需要稳定查询和索引的内容：任务 ID、状态、目标、创建时间、资产键。JSON 字段用于任务级聚合和结果快照。生产规模扩大后，可以把 Finding、风险组和证据索引拆成独立表，并增加按宿主、严重度、风险类型的查询索引。

### 38.3 Task 状态字段的关系

主状态 `Task.status` 是用户看到的总体状态；`node_status` 是 19 个节点的细粒度状态；`resume_state` 保存最后的状态快照；`report_json.execution_trace` 保存轨迹。

```text
Task.status
  queued -> running -> completed
                    -> partial
                    -> failed
                    -> cancelled
                    -> blocked

Task.node_status
  auth_gate: done
  recon: done
  dns_resolve: done
  ...
  host_vuln_scan: skipped
  merge_and_score: done
  llm_summarize: skipped
  report: done
```

数据库仍保留 19 个节点的细粒度状态，但任务页主数据流只显示实际执行过的工具。主状态回答“这次任务整体是否完成”，节点状态回答“每个工具为什么执行或跳过”，未进入候选的节点只汇总数量。

### 38.4 资产快照键

资产键由目标字符串标准化后计算 SHA-256：

```python
def asset_key(target: str) -> str:
    normalized = target.strip().rstrip("/").lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
```

标准化只去掉尾部斜杠和大小写差异。它不会把 `http://dvwa` 与 `https://dvwa` 合并，也不会把不同路径视为同一资产。这是一种保守策略：宁可多记一个资产，也不要错误合并两个不同入口。

### 38.5 审计模型

创建、取消、恢复和 AI 配置更新都会写审计日志。日志保存用户名、动作、目标、任务 ID 和 JSON 详情。审计日志不替代完整的合规审计系统，但能回答“谁在什么时候对哪个目标创建/取消了任务”。

### 38.6 checkpoint 与任务表的双写

LangGraph checkpoint 存在 PostgreSQL 中，任务主表也保存 `resume_state`。这是有意的冗余：

1. checkpoint 适合图状态恢复。
2. Task 表适合列表、查询、报告和人工排错。
3. checkpoint 格式升级或读取失败时，可以退回 Task.resume_state。
4. 两者都存在时，Worker 优先 checkpoint，再退回任务快照。

### 38.7 数据库迁移策略

当前迁移语句直接检查列是否存在，适合本地升级。正式部署应补充：

1. 迁移版本表。
2. 向前迁移和回滚脚本。
3. JSON 字段兼容性测试。
4. 大表在线迁移策略。
5. 数据库备份和恢复演练。

## 第三十九章 安全模型与威胁分析

### 39.1 信任边界

系统有六个信任边界：

| 边界 | 外部输入 | 防护 |
|---|---|---|
| 浏览器到 API | 用户名、目标、认证引用、参数 | JWT、Pydantic、Guard |
| API 到 Worker | task_id 和执行配置 | Redis 队列、数据库任务记录 |
| Worker 到扫描工具 | 目标、URL、子进程参数 | 范围二次校验、固定命令、超时 |
| Worker 到 ZAP | REST 请求和认证 Cookie | API Key、容器网络、上下文排除 |
| Worker 到 OpenVAS | GMP XML | TLS、CA、固定 XML 模板 |
| 报告到浏览器 | 工具输出、URL、证据 | HTML 模板 autoescape、证据哈希 |

### 39.2 授权门禁

授权门禁不是只检查前端复选框。前端复选框只是用户体验，后端 `validate_task` 是安全事实：

```python
if not task.authorization_confirmed:
    raise GuardError(
        "authorization confirmation is required; only scan targets you own "
        "or have explicit permission to test"
    )
```

即使攻击者绕过前端直接调用 API，没有 `authorization_confirmed=true` 仍然返回 403。

### 39.3 Scope Guard 的三层检查

第一层检查目标主机是否在授权 scope 内。第二层解析 DNS，并检查结果是否落在 allowed CIDR。第三层检查元数据地址、未显式授权的私网地址和重定向目标。

```python
if not any(_scope_matches(host, item) for item in values):
    raise GuardError(f"target {host!r} is outside the authorized scope")

resolved = _resolve_addresses(host)
if cidrs:
    networks = [ipaddress.ip_network(item, strict=False) for item in cidrs]
    for value in resolved:
        if not any(ipaddress.ip_address(value) in network for network in networks):
            raise GuardError(f"DNS rebinding blocked for {host}: {value}")
```

### 39.4 为什么在每个适配器再次过滤

初始目标合法不代表工具输出合法。Nmap 可能报告多个地址，OpenAPI 文档可能包含外部 server，重定向可能跳到其他域。`BaseAdapter._filter_findings` 对每条 Finding 的 URL 或 host 再执行 `validate_scope`。

```python
def _filter_findings(self, findings, options):
    output = []
    for finding in findings:
        candidate = finding.url or finding.host
        if candidate and self._candidate_allowed(candidate, options):
            output.append(finding)
    return output
```

被拦截的目标会写入 `blocked_targets`，在任务页和报告中显示，而不是静默丢弃。

### 39.5 不包含攻击性利用

系统明确不做漏洞利用、口令爆破、持久化、横向移动和破坏性上传。主动验证中的命令回显检测只使用标记回显，不执行下载、反弹 shell 或修改系统；上传检查只使用非执行扩展名和静态内容，不尝试访问或执行上传文件。

这一边界一方面降低对目标的影响，另一方面使报告定位为“侦察与漏洞定位”，而不是自动渗透平台。

### 39.6 凭据和敏感数据

1. 密码使用 bcrypt 哈希存储。
2. AI Key 使用由 `JWT_SECRET` 派生密钥的 Fernet 加密。
3. API 读取 AI 配置只返回 `api_key_configured`。
4. 事件和错误经过 `redact`，递归屏蔽 password、token、cookie、authorization、api_key、secret。
5. URL userinfo 中的密码被替换为 `***`。
6. OAST 回调服务不保存 Authorization、Cookie 和 x-api-key 请求头。

### 39.7 证据完整性

证据文件按 `evidence_hash.json` 保存，JSON 中保存标准化 payload。下载前重新计算 evidence 部分的 SHA-256，并与文件名和索引比较。这个机制主要用于发现意外修改和文件错配，不等同于数字签名或不可篡改审计。

### 39.8 容器安全边界

Worker 不映射端口、只读根文件系统、丢弃所有 capabilities，能降低容器被利用后的持久化能力。但 Worker 仍需执行外部扫描器并访问网络，因此不能把它视为完全无风险的沙箱。生产环境应使用独立扫描网段、最小出站策略和镜像签名。

### 39.9 威胁模型表

| 威胁 | 当前防护 | 剩余风险 |
|---|---|---|
| 未授权扫描 | 后端授权确认、scope、CIDR | 用户伪造授权文件 |
| DNS 重绑定 | 解析结果与 allowed CIDR | 复杂 DNS 轮换需进一步监测 |
| 扫描器被当代理 | 重定向和 Finding 二次校验 | 工具内置外部请求可能绕过应用层 |
| JWT 泄露 | 过期时间、只存 localStorage | XSS 或本机泄露 |
| SSE token 泄露 | 本地部署、短期 JWT | 查询参数可能进入日志 |
| 证据篡改 | SHA-256 校验 | 有权改文件和数据库的人仍可重写 |
| 工具输出注入 HTML | Jinja2 autoescape、Mermaid 文本转义 | 浏览器 iframe 内容仍需 CSP 强化 |
| AI 泄露敏感数据 | 默认关闭、脱敏后发送 | 外部模型服务的数据治理 |
| 容器逃逸 | 只读根、drop caps、no-new-privileges | 宿主和内核漏洞 |

## 第四十章 LangGraph 编排框架与状态机

### 40.1 为什么使用 StateGraph

扫描任务具有以下特征：

1. 节点数量多，但大部分节点是确定的处理步骤。
2. 部分节点依赖前序资产条件。
3. 每个节点需要独立状态、轨迹、错误和耗时。
4. 长任务需要 checkpoint 和恢复。
5. 任务可以被取消，后续节点需要显示取消状态。

普通函数可以用一个 `for` 循环执行，但难以表达节点独立状态和恢复点。LangGraph 的 `StateGraph` 允许：

1. 给每个节点注册名字。
2. 用 TypedDict 定义共享状态。
3. 通过 reducer 合并节点增量。
4. 用条件边表达路由。
5. 用 checkpointer 保存任务状态。
6. 通过 `graph.invoke` 执行完整流程。

### 40.2 PentestState 的组成

状态可以分为七类。

| 类别 | 字段 | 说明 |
|---|---|---|
| 任务身份 | task_id、target、auth_ref | 任务和目标基础信息 |
| 授权 | scope、allowed_cidrs、resolved_ips | 授权和解析结果 |
| 预算 | time_profile、stage_budgets、deadline_at | 时间限制 |
| 资产 | subdomains、resolved_hosts、live_endpoints、port_findings | 前序发现结果 |
| 结果 | vuln_findings、api_findings、secret_findings 等 | 各类 Finding |
| 观测 | node_status、execution_trace、errors | 状态与错误 |
| 交付 | findings、risk_groups、memory_context、report_result | 最终输出 |

### 40.3 reducer 的意义

LangGraph 节点返回的是状态增量。普通字段默认覆盖，列表字段需要 reducer 明确表示合并策略。

```python
class PentestState(TypedDict, total=False):
    execution_trace: Annotated[list[dict[str, Any]], operator.add]
    node_status: Annotated[dict[str, str], merge_dicts]
    errors: Annotated[list[str], operator.add]
    current_node: Annotated[str, take_last]
    status: Annotated[str, merge_status]
```

`operator.add` 表示追加，`merge_dicts` 表示字典合并，`take_last` 表示后写覆盖，`merge_status` 使用优先级避免一个节点把 blocked 状态覆盖为 running。

### 40.4 节点包装器的作用

`build_graph` 不直接注册 `nodes.node_xxx`，而是用 `wrap` 包装。包装器负责：

1. 记录阶段开始时间。
2. 向前端发出 `on_chain_start`。
3. 判断恢复时是否复用已完成节点。
4. 判断工具 profile 是否选择该节点。
5. 判断任务是否取消。
6. 判断阶段预算是否耗尽。
7. 捕获 Adapter 取消、预算超时和普通异常。
8. 发出 `on_chain_end` 或 `on_chain_error`。

节点函数只关心“正常执行时做什么”，包装器负责所有横切关注点。这样每个扫描节点不需要重复写取消和错误处理。

### 40.5 条件边的真实实现

图中有两个条件边：

```python
graph.add_conditional_edges(
    "auth_gate",
    route_after_auth,
    {"recon": "recon", "report": "report"},
)
graph.add_conditional_edges(
    "router",
    route_after_router,
    {
        **{name: name for name in nodes.SCAN_NODES},
        "merge_and_score": "merge_and_score",
    },
)
```

第一个条件边是授权失败后直接进入 report，避免执行任何扫描器。第二个条件边根据 state 中的 `next_scan_node` 选择当前扫描器；每个扫描器执行结束后重新回到 router：

```python
for scan_node in nodes.SCAN_NODES:
    graph.add_edge(scan_node, "router")
```

router 每次执行时先计算候选工具，再从 `scan_decisions` 记录的历史中排除已尝试节点。若 AI 可用，模型只能从剩余候选里选择下一个节点或返回 finish；若 AI 未配置、超时或返回非法节点，则按固定安全顺序选择第一个剩余工具。这样设计的原因是：

1. 扫描器共享速率和目标，避免同时请求造成超载。
2. 顺序执行便于 checkpoint 和恢复。
3. AI 能读取前一个扫描器的 Finding、错误和摘要，再决定下一步。
4. 每次选择都受授权、候选集合和工具 profile 限制，不能生成新命令或增加目标。
5. 失败被局部记录，后续节点仍可继续。

由于增加了 router 回环，Worker 的 LangGraph recursion limit 提高到 64，避免 8 个候选工具全部执行时超过默认步数限制。

### 40.6 跳过、失败和部分完成的判定

| 状态 | 触发 | 后续动作 |
|---|---|---|
| skipped | 条件不满足、工具缺失、profile 排除、预算耗尽 | 记录 trace，继续后续节点 |
| failed | 节点已经执行但出现未处理异常 | 记录错误，可恢复 |
| cancelled | 用户取消或适配器检测到 Redis 标记 | 终止扫描，生成可恢复状态 |
| partial | 总预算或阶段预算耗尽 | 保留已完成 Finding，仍生成报告 |
| blocked | 授权或范围校验失败 | 不执行扫描，直接报告 |

### 40.7 checkpoint 与恢复

Worker 优先使用 `PostgresSaver`：

```python
checkpointer_cm = PostgresSaver.from_conn_string(dsn)
with checkpointer_cm as checkpointer:
    checkpointer.setup()
    graph = build_graph(checkpointer=checkpointer, event_sink=_event_sink(task_id))
    result = graph.invoke(state, config={"configurable": {"thread_id": task_id}})
```

恢复时，Worker 从 checkpoint 读取状态，判断最早失败节点；如果 checkpoint 不可读，则使用 Task.resume_state。`_resume_node` 的查找顺序为：

1. 最早 failed 节点。
2. 显式 `resume_from`。
3. 最早的 cancelled/running 节点。
4. 最早的 pending 节点。
5. 最后退回 merge_and_score。

这保证系统不会因为某个节点失败而重跑所有已完成扫描器。

### 40.8 事件流的双层记录

每个节点开始和结束时，`event_sink` 同时执行两个动作：

1. 发布到 Redis `task:{task_id}:events`，供 SSE 实时展示。
2. 更新 Task.node_status 和 errors，供数据库轮询和最终结果使用。

```python
redis_client.publish(channel, json.dumps(event, ensure_ascii=False))
...
node_status[node] = event.get("status") or ...
local_task.node_status = node_status
local_db.commit()
```

Redis 是实时层，PostgreSQL 是最终事实层。这样即使 SSE 断线，浏览器重新查询任务仍能得到完整状态。

## 第四十一章 19 个节点的逐项设计、输入输出与调用方式

### 41.1 auth_gate：授权门禁

目的：确保执行面的真实性，即使任务已经通过 API 校验，仍在 Worker 内重新从 State 构造 `TaskCreate` 并执行 `validate_task`。

输入：target、auth_ref、max_rps、mode、tool_profile、time_profile、validation_level、OAST 开关。

动作：

1. 把 State 转为 `TaskCreate(..., authorization_confirmed=True)`。
2. 调用 `validate_task`。
3. 写入 scope、allowed_cidrs、resolved_ips。
4. 失败时设置 status=blocked，条件边直接进入 report。

关键代码：

```python
try:
    decision = validate_task(task)
    return {
        **_update(state, "auth_gate", "done", f"scope={len(decision.scope)}"),
        "scope": decision.scope,
        "allowed_cidrs": decision.allowed_cidrs,
        "resolved_ips": decision.resolved_ips,
        "status": "running",
    }
except GuardError as exc:
    return {
        **_update(state, "auth_gate", "failed", "blocked", str(exc)),
        "status": "blocked",
        "errors": [str(exc)],
    }
```

输出：授权后的 scope 和解析地址，或 blocked 状态。

失败语义：这里失败不是工具失败，而是授权边界阻止任务继续。

### 41.2 recon：被动子域发现

工具：Subfinder 2.17.0。

入口条件：目标不是 localhost、IP 或单标签本地主机。

动作：

1. 解析目标主机。
2. 本地目标直接写入 subdomains。
3. 远程域名执行 Subfinder。
4. 把每个子域转为 `Finding(vuln_type="subdomain")`。
5. 用 `_filter_findings` 过滤越界结果。

调用命令：

```text
subfinder -d <domain> -silent -json -rl <max_rps*10>
```

输出：`subdomains` 列表。

为什么不是只依赖工具：本地 DVWA 和 Mock 没有公共子域语义，直接跳过能缩短任务并避免产生无意义网络请求。

### 41.3 dns_resolve：DNS 解析

工具：dnsx 1.3.1。

输入：recon 得到的 subdomains。

本地目标策略：全部为 localhost、IP 或单标签主机时，直接把原主机作为 resolved_hosts，不调用 dnsx。

远程目标策略：将主机列表通过 stdin 传给 dnsx，解析 A/AAAA 记录。

```text
dnsx -silent -a -resp -rl <max_rps*10>
```

输出：`resolved_hosts`。即使 dnsx 返回空，也会保留原始主机，避免后续 HTTP 节点完全失去目标。

### 41.4 takeover_check：子域接管检查

工具：Subjack 3.1.0。

入口条件：目标不是纯本地或单标签主机，且存在多个可检查子域。

调用命令：

```text
subjack -w - -t <max_rps> -ssl -c /opt/subjack/fingerprints.json -v
```

解析逻辑：只保留包含 `vulnerable` 的输出行，生成 `subdomain_takeover` Finding，严重度 high。

为什么跳过本地目标：子域接管依赖公共 CNAME 和托管服务指纹，IP/Docker 服务没有相同语义。

### 41.5 http_probe：HTTP 存活和端点发现

工具：httpx CLI，Python `httpx` 作为后备。

输入：

1. 原始 target。
2. resolved_hosts 生成的 HTTP URL。

动作：

1. 通过 stdin 运行 `httpx -l - -silent -json -sc -title -td -rl ...`。
2. 把 JSON 转为 live_endpoint Finding。
3. 如果某个目标没有被 CLI 命中，用 Python httpx 进行一次 GET。
4. 对每个 endpoint 探测 `/swagger.json`、`/openapi.json`、`/v3/api-docs`。
5. 对 OpenAPI 文档中的 `servers[].url` 再执行 Scope Guard。

输出：`live_endpoints` 列表，每项包含 url、host、port、status_code、title、tech 等。

设计原因：httpx CLI 覆盖面好，但某些本地容器或特殊响应可能需要 Python 请求兜底。两者都使用受限重定向和 Scope Guard。

### 41.6 port_scan：端口和服务识别

工具：Nmap 7.93。

调用命令：

```text
nmap -sT -sV -sC -Pn --max-rate <max_rps*10> -oX - <host>
```

额外动作：无论主扫描是否发现端口，都额外对 6443 进行短时探测，用于触发 K8s 条件分支。

解析逻辑：只把 state=open 的 port 转为 `open_port` Finding，记录 service、product、version。

为什么使用 `-sT`：本地容器和普通用户权限下 TCP connect scan 更稳定，不依赖原始套接字权限。

### 41.7 credential_session_analysis：认证与会话分析

入口条件：

1. `validation_level != off`。
2. `auth_ref` 存在。
3. 认证类型为 `form`。

动作：

1. 创建 `AuthAnalysisAdapter`。
2. 通过统一 `authenticate` 进行多次登录。
3. 比较登录前 Cookie 和登录后 Cookie。
4. 计算 Cookie 长度、熵和多次样本是否变化。
5. 在 deep 模式下读取配置的弱口令字典，执行最多 8 组凭据尝试。
6. 若 profile 开启 rate_limit_probe，执行 3 次低量无效登录并检查 423、429、Retry-After 和提示词。

输出：weak_session_id、session_fixation、default_credentials、brute_force 等 Finding。

安全边界：不是无限爆破；弱口令字典必须显式配置，尝试次数有上限，且只针对已授权认证档案。

### 41.8 router：AI 动态编排与固定流程回退

前面节点产生：

1. live_endpoints。
2. port_findings。
3. mode。
4. validation_level。
5. tool_profile。

router 根据条件生成候选 routes：

| 条件 | 候选节点 |
|---|---|
| live_endpoints 非空 | web_scan、nuclei_scan、server_baseline |
| validation_level 非 off | active_validation |
| URL 包含 swagger/openapi | api_fuzz |
| URL 以 .js 结尾 | js_secret_scan |
| 6443 被 Nmap 发现 | k8s_audit |
| mode=full | host_vuln_scan |

然后使用 `TOOL_PROFILE_ROUTES` 过滤：

```python
TOOL_PROFILE_ROUTES = {
    "full_agent": set(SCAN_NODES),
    "nuclei": {"nuclei_scan"},
    "zap_wapiti_nuclei": {"web_scan", "nuclei_scan", "server_baseline"},
    "validation_only": {"active_validation"},
}
```

router 会排除已经执行、失败或跳过的节点，然后：

1. 若 AI 已启用且配置有效，把候选工具、前一个扫描器摘要、已有 Finding、端点和错误发送给模型。
2. 模型只能返回候选节点之一或 `finish`；返回其他工具名时视为非法并回退。
3. 每次选择写入 `scan_decisions`，包含 step、node、tool、source、reason 和 confidence。
4. AI 未配置、超时、失败或返回非法值时，按固定安全顺序选择下一个候选节点。
5. `finish` 或候选耗尽后，进入 `merge_and_score`。

未进入候选的节点会得到 `condition_not_met`、`tool_profile_excluded` 等原因；任务页主数据流默认不再铺开这些节点，只显示实际进入执行链的工具。

### 41.9 web_scan：ZAP Web 动态扫描

工具：ZAP 2.17.0，通过 `zapv2` REST 客户端调用。

输入：live_endpoints 的唯一 origin。

调用链：

1. 创建 ZAP 客户端。
2. 新建 ZAP Session。
3. 设置线程、延迟、整次扫描时间和单规则时间。
4. 创建 context，限制目标 host。
5. 应用 safe_path_denylist 和 active_scan_exclude。
6. 认证扫描时安装 Cookie/Header replacer。
7. Spider。
8. Active Scan。
9. 读取 `core.alerts(baseurl=target)`。

ZAP 适配器不把浏览器依赖装入 Worker；Worker 只通过 REST 调用独立 ZAP 容器。

### 41.10 nuclei_scan：模板漏洞扫描

工具：Nuclei 3.11.1。

调用命令：

```text
nuclei -u <url> -jsonl -silent -severity <severity> \
  -rate-limit <max_rps> -duc -ni
```

若 `NUCLEI_TAGS` 非空，增加 `-tags` 参数。

解析逻辑：JSONL 每行解析模板 ID、matched-at、severity、description，生成 Finding。模板版本在构建时固定，避免运行时自动下载导致结果漂移。

### 41.11 js_secret_scan：前端密钥扫描

工具：Gitleaks 8.30.1，Python httpx 用于下载 JS 文件。

动作：

1. 只取已发现 URL 中以 `.js` 结尾的地址。
2. 最多下载 20 个文件。
3. 每次重定向重新检查 Scope。
4. 把 JS 写入临时目录。
5. 运行 `gitleaks detect --no-git --source <dir> --report-format json --report-path -`。
6. 把文件映射回原 URL。

输出：`secret:<RuleID>` Finding，严重度 high。

限制：只扫描已发现 JS，不是完整前端资源爬虫。

### 41.12 api_fuzz：OpenAPI 契约检查

工具：Schemathesis 3.38.5。

入口条件：live_endpoints 中存在 swagger/openapi URL。

调用命令：

```text
schemathesis run <url> --checks all --max-examples <max_rps>
```

解析策略：如果返回码不正，生成 `api_contract_failure` Finding，并保存输出尾部作为证据。它不是通用 API 模糊测试器，不会在没有契约时盲目猜测接口。

### 41.13 k8s_audit：Kubernetes 基线

工具：Kubescape 4.0.16。

入口条件：Nmap 发现 6443，且环境内存在 KUBECONFIG。

调用命令：

```text
kubescape scan framework nsa --format json --output -
```

解析：只把非 passed/skipped 的 controls 转为 `k8s_control:<id>` Finding。

设计边界：扫描器不把远程 6443 自动当成可访问的本地集群。没有 kubeconfig 就 skipped，而不是推测凭据。

### 41.14 server_baseline：Nikto + Wapiti

目的：对唯一 origin 做服务器配置和参数级检查。

工具组合：

1. Nikto：服务器配置、危险文件、默认页面。
2. Wapiti：SQLi、XSS、文件、上传、重定向、SSRF、XXE、备份、HTTP headers 等。

容错策略：两个工具都可以失败；只有一个成功时节点仍为 done，并把失败写入 errors；两者都失败时节点 failed。

### 41.15 active_validation：通用主动验证

工具：内置 Python 验证器，使用 `httpx`。

能力：

1. 安全页面 crawl，最多 25 页，safe 模式最多 15 页。
2. 参数 SQL 错误差分。
3. deep 模式低影响命令回显差分。
4. 危险扩展名但不可执行内容的上传策略检查。
5. OAST 盲 SSRF、XXE 和命令回调验证。

每个请求都经过 Scope Guard、最大参数/请求数限制和速率延迟。

### 41.16 host_vuln_scan：OpenVAS/GVM 主机扫描

入口条件：mode=full、OPENVAS_ENABLED=true、capability available、feed 可用于查询。

GMP 生命周期：

```text
get_configs
get_scanners
create_target
create_task
start_task
get_tasks (poll)
get_report
delete_task
delete_target
```

全部通过 `gvm-cli` 子进程发送 XML。取消或预算耗尽时调用 `stop_task`，在 finally 中清理临时 target/task。

### 41.17 merge_and_score：归一化、去重与评分

输入字段：

1. takeover_findings。
2. port_findings。
3. vuln_findings。
4. api_findings。
5. k8s_findings。
6. secret_findings。

动作：

1. 用 `Finding.model_validate` 统一验证。
2. 合并工具别名。
3. 计算 fingerprint。
4. 合并同指 Finding，记录 also_reported_by。
5. 计算 confidence 和 score。
6. 递归脱敏 evidence/raw。
7. 写证据文件和 evidence_index.json。
8. 关联 playbook。
9. 生成 risk_groups。
10. 更新历史记忆。

### 41.18 llm_summarize：可选 AI 增强

入口条件：

1. AI 配置 enabled。
2. base_url 和 model 非空。
3. AI 节点之前的所有确定性合并已经完成。

动作：

1. 读取脱敏后的 risk_groups 和 memory_context。
2. 按 `LLM_BATCH_SIZE` 分批。
3. 先查 `ai_analysis_cache`。
4. 调用 OpenAI 兼容 `/chat/completions`。
5. 校验模型不能跨 host/port/vuln_type 合并。
6. 接受合法字段，丢弃非法字段。
7. 失败时节点 skipped，不修改原始 Finding。

### 41.19 report：报告与工作流

输入：findings、node_status、execution_trace、risk_groups、memory_context、budget_context。

输出：

1. HTML 报告。
2. report.json。
3. findings.json。
4. workflow.mmd。
5. workflow.png（渲染成功时）。

报告状态判定：

```text
cancelled -> cancelled
deadline_exceeded -> partial
status in blocked/failed -> 保持
status partial -> partial
其余 -> completed
```

报告是流程的最终事实快照。即使某个节点 skipped 或 failed，也记录其状态和原因，不伪造成功。

## 第四十二章 适配器框架与工具调用机制

### 42.1 为什么需要 BaseAdapter

外部工具有五种差异：

1. 调用方式不同：CLI、REST API、GMP XML、Python 库。
2. 输入不同：域名、主机列表、URL 列表、文件目录。
3. 输出不同：JSONL、JSON、XML、纯文本。
4. 严重度不同：有的只有 risk=Medium，有的给 CVSS，有的完全不给。
5. 失败方式不同：返回码、HTTP 状态、XML 错误、超时和输出为空。

`BaseAdapter` 把这些差异封装为统一契约：

```python
class BaseAdapter(ABC):
    name = "base"
    tool_version = "unknown"

    @abstractmethod
    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        """Execute one adapter and return normalized, authorized findings."""
```

节点只依赖 `run()` 和 `available()`，不关心工具是 CLI 还是 REST。

### 42.2 BaseAdapter 的初始化参数

| 参数 | 作用 |
|---|---|
| capabilities | 当前工具能力字典 |
| cancel_check | 调用 Redis 取消标记的回调 |
| deadline_monotonic | 当前节点的阶段截止时间 |

`_adapter()` 在节点中统一构造适配器：

```python
def _adapter(adapter_cls, state, node):
    return adapter_cls(
        state.get("capabilities") or {},
        cancel_check=cancel_requested,
        deadline_monotonic=stage_deadline_monotonic(
            state.get("deadline_at"),
            state.get("stage_budgets"),
            node,
            state.get("stage_started_at"),
        ),
    )
```

这样取消和时间预算不是适配器各自实现，而是所有工具共享同一套规则。

### 42.3 子进程执行模型

CLI 工具通过 `subprocess.Popen` 启动，不使用 `shell=True`。

```python
process = subprocess.Popen(
    command,
    stdin=subprocess.PIPE if input_text is not None else None,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding="utf-8",
    errors="replace",
    start_new_session=True,
)
```

设计要点：

1. 参数使用列表传递，避免 shell 注入。
2. 输入通过 stdin 传递，支持大量主机列表。
3. stdout/stderr 分开捕获，便于错误摘要。
4. `start_new_session=True` 创建进程组，超时时可以终止子进程树。
5. 使用 `errors="replace"`，防止工具输出非 UTF-8 字符导致 Worker 崩溃。

### 42.4 取消与超时的区别

| 条件 | 抛出的异常 | 结果 |
|---|---|---|
| Redis 中出现 `cancel:{task_id}` | `AdapterCancelled` | 任务 cancelled，可恢复 |
| 阶段 deadline 已到 | `AdapterDeadlineExceeded` | 节点 skipped，任务 partial |
| 单个工具 timeout 到期 | `TimeoutError` | 节点 failed，记录错误 |

三种情况的业务含义不同。用户主动取消不应被写成工具故障；阶段预算耗尽应保留已有结果；工具自身超时则需要记录具体节点。

### 42.5 子进程树终止

Linux 下使用进程组发送 SIGTERM，最多等待 3 秒，再发送 SIGKILL：

```python
try:
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=3)
except (AttributeError, ProcessLookupError, subprocess.TimeoutExpired):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError):
        pass
```

Windows 下使用 `taskkill /T /F` 终止整个进程树。之所以要按进程组处理，是因为 Nmap、Wapiti、Nikto 等工具可能启动子进程。

### 42.6 速率控制

`_rate` 将 max_rps 限制在 1 到 5：

```python
def _rate(self, options):
    try:
        return max(1, min(5, int(options.get("max_rps", 5))))
    except (TypeError, ValueError):
        return 5
```

不同工具映射方式不同：

| 工具 | 速率参数 |
|---|---|
| Subfinder/dnsx/httpx | `-rl max_rps*10` |
| Nmap | `--max-rate max_rps*10` |
| Nuclei | `-rate-limit max_rps` |
| Subjack | `-t max_rps` |
| ZAP | 线程数 1，delay 为 `1000/max_rps` 毫秒 |
| Wapiti | `--wait 1/max_rps` |
| 内置验证器 | 每次请求前 sleep |

速率限制的实现不是全局限流，而是每个工具和任务内部限速。组织级分布式限流属于生产化待建设能力。

### 42.7 工具能力探测

Worker 启动时调用 `write_capabilities()`，逐个执行版本命令。探测结果写入 `/output/capabilities.json`。

```python
CLI_TOOLS = {
    "subfinder": ["subfinder", "-version"],
    "dnsx": ["dnsx", "-version"],
    "httpx": ["httpx", "-version"],
    "nmap": ["nmap", "--version"],
    "nuclei": ["nuclei", "-version"],
    "nikto": ["nikto", "-Version"],
    "wapiti": ["wapiti", "--version"],
    "schemathesis": ["schemathesis", "--version"],
    "kubescape": ["kubescape", "version"],
    "subjack": ["subjack", "-h"],
    "gitleaks": ["gitleaks", "version"],
}
```

ZAP 通过 `/JSON/core/view/version/` 探测；OAST 通过 `/health` 探测；OpenVAS 先做 TCP 连接，再执行 `gvm-cli` 查询版本和 feed。

### 42.8 能力文件而不是每次调用都探测

每次扫描都执行全部版本命令会拖慢任务，并可能阻塞 API。因此 Worker 启动和任务开始时刷新能力文件，节点读取缓存结果。OpenVAS 首次同步较慢，Worker 使用带间隔的重试线程刷新能力。

### 42.9 Finding 的统一构造

适配器使用 `_finding()` 或直接构造 `Finding`。统一字段包括：

| 字段 | 含义 |
|---|---|
| source | 工具或验证器名称 |
| host | 受影响主机 |
| url | 具体地址 |
| port | 端口 |
| vuln_type | 风险类型或工具原始类型 |
| severity | info/low/medium/high/critical |
| evidence | 面向复核的精简证据 |
| raw | 原始工具对象或摘要 |
| also_reported_by | 其他工具印证来源 |
| fingerprint | 去重指纹 |
| confidence | 置信度 |
| evidence_hash | 证据哈希 |
| playbook | 处置剧本文件名 |

### 42.10 原始输出到 Finding 的转换原则

1. 只保留证明漏洞所需的最小证据。
2. 原始工具对象放在 raw，便于后续扩展。
3. 不在适配器内做跨工具融合。
4. 不在适配器内写 HTML 或自然语言报告。
5. 不在适配器内决定最终风险组。
6. 越界 URL 和 host 通过 `_filter_findings` 去掉。

### 42.11 缺失工具的处理

节点先调用 `adapter.available()`。不可用时返回 `_skipped(...)`，不会伪造空 Finding，也不会把任务状态设为 failed。

示例：

```python
if not adapter.available():
    return _skipped(state, "nuclei_scan", "nuclei")
```

这使报告中可以明确写出“Nuclei 未安装或不可用”，而不是给出误导性的“没有漏洞”。

### 42.12 适配器扩展契约

新增适配器至少需要：

1. 继承 `BaseAdapter`。
2. 声明 `name` 和 `tool_version`。
3. 实现 `run()`。
4. 使用 `_run()` 或受控 HTTP 客户端执行外部调用。
5. 使用 `_filter_findings()` 做范围过滤。
6. 为解析器增加单元测试。
7. 增加 capability 探测命令。
8. 在节点中添加入口条件和输出字段。

## 第四十三章 14 类扫描引擎与精确调用方式

### 43.1 Subfinder：被动子域发现

定位：在不直接探测目标的前提下，从公共数据源发现子域。

输入：单个域名。

调用：

```python
completed = self._run([
    "subfinder", "-d", domain, "-silent", "-json",
    "-rl", str(self._rate(options) * 10),
], settings.subfinder_timeout_seconds)
```

解析：每行尝试 JSON，失败则按纯文本主机处理。生成 `subdomain` Finding，evidence 中包含域名和子域。

适用条件：公共域名。localhost、IP、单标签容器名不适合。

### 43.2 dnsx：DNS 解析

定位：把候选子域解析为地址，减少后续无效扫描。

输入：子域列表，通过 stdin。

调用：

```python
completed = self._run(
    ["dnsx", "-silent", "-a", "-resp", "-rl", str(self._rate(options) * 10)],
    settings.dnsx_timeout_seconds,
    "\n".join(hosts) + "\n",
)
```

解析：匹配 `host [address]` 行；不能匹配时保留第一列作为主机。生成 `resolved_host` Finding。

### 43.3 httpx：HTTP 存活、标题和技术栈

定位：发现 live endpoint，为后续 ZAP、Nuclei 和验证器提供入口。

调用：

```python
completed = self._run([
    "httpx", "-l", "-", "-silent", "-json", "-sc",
    "-title", "-td", "-rl", str(self._rate(options) * 10),
], settings.httpx_timeout_seconds, "\n".join(targets) + "\n")
```

解析字段：url、host、port、status_code、title、tech、webserver。

兜底：CLI 没有返回时，用 Python httpx GET，限制 5 次重定向并逐次验证 scope。兜底证据标记 `fallback: python-httpx`。

### 43.4 Nmap：端口与服务

定位：网络层发现开放端口、服务名、产品和版本。

主命令：

```python
[
    "nmap", "-sT", "-sV", "-sC", "-Pn",
    "--max-rate", str(self._rate(options) * 10),
    "-oX", "-", host,
]
```

附加 6443 探测：

```python
["nmap", "-sT", "-Pn", "-p", "6443", "-oX", "-", host]
```

解析 XML：只保留 `<state state="open">`。服务信息转换为 evidence。6443 的发现用于 router 触发 k8s_audit，不代表系统自动拥有集群凭据。

### 43.5 Subjack：子域接管

定位：识别公共 CNAME 指向未接管托管服务的风险。

命令：

```text
subjack -w - -t <rate> -ssl -c /opt/subjack/fingerprints.json -v
```

输出只保留包含 vulnerable 的行。Finding 类型 `subdomain_takeover`，默认 high。

### 43.6 ZAP：Web 动态扫描

定位：真实浏览器代理式 Web 扫描，覆盖配置、注入、Cookie、安全头和请求方法等。

调用不是 shell 命令，而是 Python `zapv2` REST 客户端：

```python
client = zapv2.ZAPv2(
    proxies={"http": settings.zap_url, "https": settings.zap_url},
    apikey=settings.zap_api_key,
)
client.core.new_session(apikey=settings.zap_api_key)
client.ascan.set_option_thread_per_host(1)
client.ascan.set_option_delay_in_ms(max(0, int(1000 / rate)))
client.ascan.set_option_max_scan_duration_in_mins(...)
client.context.new_context(context_name)
client.spider.scan(target, recurse=True, contextname=context_name)
client.ascan.scan(target, recurse=True, contextid=context_id)
client.core.alerts(baseurl=target)
```

认证复用：

1. 统一 `authenticate(auth_ref)` 获得 Cookie 和 Header。
2. 通过 ZAP Replacer 规则把 Cookie/Header 注入请求。
3. 扫描结束后移除 replacer 和 context。

安全控制：

1. 排除 safe_path_denylist 和 active_scan_exclude。
2. 禁用可疑插件 10104。
3. 整次和单规则都有时间上限。
4. 取消时调用 `spider.stop_all_scans` 或 `ascan.stop_all_scans`。

### 43.7 Nuclei：模板漏洞扫描

定位：用固定模板检测已知 CVE、暴露配置和常见错误。

命令：

```text
nuclei -u <url> -jsonl -silent -severity <levels> \
  -rate-limit <rate> -duc -ni [-tags <tags>]
```

参数解释：

| 参数 | 含义 |
|---|---|
| `-jsonl` | 每行一个 JSON，便于流式解析 |
| `-silent` | 减少 banner |
| `-severity` | 限制严重度，默认 medium/high/critical |
| `-duc` | 禁用自动更新检查 |
| `-ni` | 禁用交互输入 |
| `-tags` | 可选的模板标签过滤 |

解析：匹配模板、URL、host、port、严重度、description 转为 Finding。

### 43.8 Gitleaks：前端密钥扫描

定位：检查已发现 JS 文件中的 API Key、Token、私钥等泄露特征。

下载阶段：

1. 只接受 `.js` URL。
2. 最多 20 个文件。
3. 禁止自动跟随未授权重定向。
4. 临时目录保存在 tmpfs。

检测命令：

```text
gitleaks detect --no-git --source <temp-dir> \
  --report-format json --report-path -
```

输出：rule ID、description、match、file。vuln_type 格式为 `secret:<RuleID>`。

### 43.9 Schemathesis：OpenAPI 契约检查

定位：读取 OpenAPI 文档，按 schema 生成请求并检查契约异常。

命令：

```text
schemathesis run <openapi-url> --checks all --max-examples <rate>
```

解析：如果命令返回码非零，生成 `api_contract_failure` Finding，并保存 stdout/stderr 尾部。证据说明必须结合契约文档复核，不能只凭返回码断定存在安全漏洞。

### 43.10 Kubescape：Kubernetes 基线

定位：检查当前 KUBECONFIG 所指集群的 NSA 基线。

命令：

```text
kubescape scan framework nsa --format json --output -
```

输出解析：只保留非 passed/skipped 的 controls。没有 KUBECONFIG 时节点直接 skipped。

该工具扫描的是环境中的集群配置，不是对任意远程 6443 端口做认证爆破。

### 43.11 Nikto：Web 服务器基线

定位：检查危险文件、默认页面、服务器配置和已知路径。

命令：

```text
nikto -host <url> -Format json -output - -nointeractive
```

解析：JSON 列表或 `vulnerabilities` 数组，每条生成 medium Finding。由于 Nikto 的原始消息类型很丰富，最终风险类型由别名映射和后处理进一步归一。

### 43.12 Wapiti：参数级 Web 检查

定位：对 URL、表单、参数和常见 Web 漏洞做主动检查。

核心命令：

```text
wapiti -u <url> -f json -o <report.json> --flush-session \
  --max-scan-time 900 --max-attack-time 180 --scope folder -l 2 \
  -m sql,timesql,xss,file,upload,redirect,exec,permanentxss,\
http_headers,csp,brute_login_form,backup,ssrf,xxe,crlf,methods,\
shellshock,spring4shell,log4shell,ssl \
  --max-links-per-page 100 --max-parameters 100 --wait <interval>
```

认证：先通过统一 `authenticate` 获取 Cookie Header，再通过 `-C` 传入。若认证失败，适配器抛出 `authentication_failed`，避免把匿名扫描结果当成认证后的结果。

排除：safe_path_denylist 和 active_scan_exclude 转换为 `-x` 参数。

解析：按 category 和 level 转 Finding，保留 parameter、method、path、info。

### 43.13 OpenVAS/GVM：主机与网络漏洞

定位：对目标执行主机层配置和已知漏洞扫描。

通信：`gvm-cli` 子进程 + TLS TCP + GMP XML。

完整 XML 生命周期：

```xml
<get_configs/>
<get_scanners/>
<create_target>
  <name>scanner-<timestamp></name>
  <hosts>target</hosts>
  <port_range>T:1-65535</port_range>
</create_target>
<create_task>
  <name>scanner-<timestamp></name>
  <config id="..."/>
  <target id="..."/>
  <scanner id="..."/>
</create_task>
<start_task task_id="..."/>
<get_tasks task_id="..."/>
<get_report report_id="..."/>
<delete_task task_id="..." ultimate="1"/>
<delete_target target_id="..." ultimate="1"/>
```

调用代码：

```python
completed = self._run(
    [
        "gvm-cli",
        "--gmp-username", settings.openvas_username,
        "--gmp-password", settings.openvas_password,
        "--timeout", str(timeout),
        "tls",
        "--hostname", settings.openvas_host,
        "--port", str(settings.openvas_port),
        *tls_options,
        "--xml", xml,
    ],
    timeout + 15,
)
```

结果解析：从 `<result>` 读取 name、host、severity、port、description、solution、nvt/oid。severity 的 CVSS 数值映射为 info/low/medium/high/critical。

### 43.14 内置主动验证器：不依赖外部二进制

定位：对需要更低影响和更明确控制的行为做补充验证。

调用：Python `httpx.Client`，不使用 shell。

特点：

1. 页面 crawl 有最大页数。
2. 参数和请求有最大数量。
3. 每个请求前检查 Scope 和取消。
4. SQL 使用错误差分，不执行 union、时间盲注或数据导出。
5. 命令检测使用控制组和标记回显，避免把普通反射误判为命令执行。
6. 上传只检查危险扩展名是否被接受，不执行上传文件。
7. OAST 使用一次性 token 等待外部回调。

### 43.15 OAST：回调服务

定位：验证目标是否主动访问攻击者指定的回调地址，用于盲 SSRF、XXE 和盲命令执行。

架构：

1. 独立 FastAPI 服务。
2. SQLite 保存 token 和命中。
3. `POST /api/tokens` 创建一次性 token。
4. 目标访问 `/cb/{token}` 时写入 hit。
5. Worker 通过 `GET /api/tokens/{token}` 查询命中。

安全设计：

1. 管理 API 使用 `X-OAST-Secret`。
2. 回调入口只记录非敏感 Header。
3. 每个 token 一次性用于一个验证场景。
4. OAST 默认只在 deep validation 下启用。

### 43.16 引擎选择矩阵

| 层级 | 覆盖内容 | 主要工具 |
|---|---|---|
| 资产发现 | 子域、DNS、存活、HTTP 指纹 | Subfinder、dnsx、httpx |
| 服务识别 | 端口、服务、版本 | Nmap |
| 已知漏洞 | CVE、模板、服务器配置 | Nuclei、Nikto |
| Web 参数 | SQLi、XSS、文件、上传、请求走私类参数 | ZAP、Wapiti、内置验证器 |
| API | OpenAPI 契约和属性 | Schemathesis |
| 前端代码 | JS 密钥泄露 | Gitleaks |
| 云原生 | K8s 基线 | Kubescape |
| 主机层 | CVE、端口和主机配置 | OpenVAS |
| 带外验证 | 盲 SSRF、XXE、命令执行 | OAST |

没有任何单一工具覆盖全部层级，因此需要多引擎编排。多引擎也会产生重复和误报，因此需要第四十六章的融合设计。

## 第四十四章 认证档案与统一会话引擎

### 44.1 为什么认证要单独抽象

ZAP、Wapiti、认证分析和主动验证都需要登录态。如果每个工具各自读取账号密码、实现 CSRF 和验证登录成功，会出现四个问题：

1. Cookie 和 Header 格式不一致。
2. 登录失败时仍执行“认证扫描”，结果被误认为已覆盖登录区域。
3. 敏感环境变量散落在多个适配器。
4. 同一目标需要重复登录。

系统因此使用统一的 `auth_session.py`，把认证配置、登录动作、Cookie/Header 和验证结果统一为 `AuthSession`。

### 44.2 AuthProfile 配置模型

`AuthProfile` 是 Pydantic 模型，支持五种类型：

| type | 用途 | 关键字段 |
|---|---|---|
| none | 不需要认证 | 无 |
| form | 表单登录 | login_url、字段名、CSRF、验证页面 |
| cookie | 已有 Cookie Header | cookie_env |
| bearer | Bearer Token | token_env |
| basic | HTTP Basic | basic_username_env、basic_password_env |

通用字段还包括 target_hosts、safe_path_denylist、active_scan_exclude、session_samples 和 rate_limit_probe。

### 44.3 认证配置示例

```yaml
auth_refs:
  local-dvwa:
    authentication:
      type: form
      target_hosts: [dvwa]
      login_url: http://dvwa/login.php
      verification_url: http://dvwa/index.php
      username_env: DVWA_USERNAME
      password_env: DVWA_PASSWORD
      username_field: username
      password_field: password
      csrf_field: user_token
      submit_field: Login
      submit_value: Login
      logged_in_indicator: Logout
      logged_out_indicator: Login
      safe_path_denylist: [logout.php, setup.php]
      active_scan_exclude: [vulnerabilities/csrf/]
      rate_limit_probe: true
```

敏感值不直接写在 YAML，而是通过 `username_env` 和 `password_env` 指向环境变量。认证配置 API 只返回 auth_ref、label、type、target_hint 等非敏感摘要。

### 44.4 表单登录的完整流程

1. GET 登录页面。
2. 保存登录前 Cookie。
3. 用 HTMLParser 查找 CSRF 字段 value。
4. 组合 extra_fields、username、password、submit 字段和 CSRF。
5. 使用配置的方法（默认 POST）提交。
6. 保存登录后 Cookie。
7. 检查状态码和 logged_in_indicator。
8. 如配置 verification_url，再访问验证页检查登录状态和注销标识。
9. 返回 AuthSession。

关键代码：

```python
page = initial.get(profile.login_url)
page.raise_for_status()
pre_cookies = {
    str(cookie.name): str(cookie.value) for cookie in initial.cookies.jar
}
token = ""
if profile.csrf_field:
    parser = _FieldParser(profile.csrf_field)
    parser.feed(page.text)
    token = parser.value

payload = dict(profile.extra_fields)
payload[profile.username_field] = username
payload[profile.password_field] = password
if profile.submit_field:
    payload[profile.submit_field] = profile.submit_value or "1"
if profile.csrf_field and token:
    payload[profile.csrf_field] = token
```

### 44.5 登录是否成功的判定

系统不只检查 HTTP 200，还会检查：

1. `logged_in_indicator` 是否出现在响应正文。
2. `success_url_contains` 是否出现在最终 URL。
3. verification_url 的响应是否仍包含登录标识。
4. verification_url 是否出现 logged_out_indicator。

如果登录未通过，ZAP 和 Wapiti 不会把匿名扫描结果当作认证覆盖。这是报告可信度的关键条件。

### 44.6 Cookie/Bearer/Basic

Cookie 模式从环境变量读取完整 Cookie Header，转换为字典，并可选访问 verification_url。

Bearer 模式从环境变量读取 token，生成 `Authorization: Bearer <token>`，并复用相同验证逻辑。

Basic 模式从环境变量读取用户名和密码，通过 httpx 的 `auth=(username, password)` 传递，避免手工拼接 Authorization Header。

### 44.7 会话安全分析

认证分析器采集最多 5 个会话，默认 3 个。对每个 Cookie 统计：

1. 多次登录是否不同。
2. 最小长度。
3. 最小字符熵。

弱会话判定：所有样本相同、长度小于 16 或熵小于 3.0。会话固定判定：登录前 Cookie 与登录后 Cookie 同名且值相同。

```python
minimum_entropy = min(_entropy(item) for item in samples)
if distinct == 1 or minimum_length < 16 or minimum_entropy < 3.0:
    weak_names.append({
        "cookie": name,
        "distinct": distinct,
        "min_length": minimum_length,
        "min_entropy": round(minimum_entropy, 3),
    })
```

### 44.8 弱口令与登录限速

弱口令探测只读取显式配置的字典，最多尝试 8 组。成功后立即停止，不继续扩大尝试。

登录限速探测执行最多 3 次无效登录，若观察到 423、429、Retry-After 或“too many/locked/captcha”等标记，则视为存在防护，不生成 Finding。

这不是完整防爆破测试，只是一次低影响、可配置的登录防护抽查。

### 44.9 认证失败为何不自动降级为匿名

如果用户明确选择了认证扫描，但登录失败，系统应报告认证失败并跳过依赖认证的扫描，而不是偷偷执行匿名扫描。否则报告中无法判断哪些页面真正被认证覆盖，可能造成严重误判。

## 第四十五章 主动验证、差异检测与 OAST

### 45.1 为什么需要内置主动验证

ZAP 和 Wapiti 覆盖面广，但结果类型多、噪声大。内置验证器用于补充少量可控、可解释的验证：

1. SQL 错误差分。
2. 命令标记回显。
3. 危险扩展名上传策略。
4. 盲 SSRF、XXE、命令回调。

它的目标不是替代 ZAP/Wapiti，而是为特定风险提供额外印证和更明确的证据。

### 45.2 安全与深度级别

| 级别 | 行为 |
|---|---|
| off | 不执行 active_validation 和认证分析 |
| safe | 页面 crawl 最多 15 页，执行 SQL 差分等低影响检查 |
| deep | 最多配置页数，增加命令差分、上传策略和 OAST |

safe 模式默认关闭命令执行标记和 OAST。deep 模式仍不执行破坏性利用。

### 45.3 页面爬取

`_PageParser` 继承 HTMLParser，收集：

1. `<a href>` 链接。
2. `<form>` action、method、enctype。
3. input 名称、值、类型。
4. password 字段。
5. file 字段。
6. textarea 和 select。

爬取只跟随同 origin，深度最多 2，页数受 limits 控制。包含 logout、setup、install、reset、delete、change-password 等标记的表单不执行。

### 45.4 请求安全包装

所有验证请求统一经过 `_request`：

```python
self._check_cancel()
if state["requests"] >= int(options["_limits"]["max_requests"]):
    return None
validate_scope(url, options.get("scope", []), options.get("allowed_cidrs", []))
```

然后执行速率延迟、重定向校验和响应处理。任何重定向到范围外都会写入 blocked_targets。

### 45.5 SQL 错误差分

基线请求保存正常 SQL 错误签名。对参数追加单引号后重新请求：

```python
attack_params[index] = (name, f"{params[index][1]}'")
response = self._request(client, "GET", attack_url, options, state)
signature = self._sql_signature(response.text)
if signature and not baseline_sql:
    findings.append(self._query_finding(
        "sql_injection", attack_url, name,
        {"signature": signature, "method": "GET"},
    ))
```

只有新出现数据库错误签名才算，避免目标本来就返回 SQL 错误时产生静态噪声。

### 45.6 命令注入的控制组设计

deep 模式生成随机 marker，例如 `SCANNER_CMD_a1b2c3d4`。分别发送：

1. 控制值：直接包含 marker。
2. 命令值：`;printf SCANNER_CMD_x`。

只有命令响应包含 marker、控制响应不包含 marker 时，才生成命令注入 Finding。这样可以过滤普通反射型回显。

### 45.7 上传检查

上传文件名使用 `.php` 等高风险扩展名，但内容只有静态 GIF 头和探测文本：

```python
files = {
    field: (
        "scanner_probe.php",
        b"GIF89a;SCANNER_UPLOAD_POLICY_PROBE",
        "image/gif",
    )
}
```

系统只判断服务器是否接受了危险扩展名，不访问上传文件、不执行代码、不尝试绕过 WAF。

### 45.8 OAST 完整调用链

1. Worker 向 OAST 创建 token。
2. OAST 返回 callback_url。
3. Worker 把 callback_url 放入 URL 参数、表单字段、XML entity 或命令值。
4. 目标服务在解析 URL、XXE 或执行命令时访问 callback_url。
5. OAST 记录 hit。
6. Worker 轮询 token hits。
7. 命中后生成 ssrf、xxe 或 command_injection Finding。

请求示例：

```python
token = oast.create_token(f"ssrf:{parameter}")
params = [
    (name, token.callback_url if name == parameter else value)
    for name, value in params
]
hit = oast.wait_for_hit(token, timeout=4)
if hit:
    output.append(self._finding(
        host="", url=attack_url, vuln_type="ssrf", severity="high",
        evidence={"parameter": parameter, "callback": token.callback_url, "hit": hit},
    ))
```

### 45.9 OAST 为什么需要独立服务

目标可能无法访问 Docker 内部 `http://oast:8001`，因此对外部目标必须配置目标可达的 `OAST_PUBLIC_BASE_URL`，通常通过带 HTTPS 的反向代理暴露回调入口。OAST Secret 必须更换为随机值。

### 45.10 主动验证的能力边界

1. 不是完整模糊测试器。
2. 不执行数据库导出、反弹 shell 或持久化上传。
3. 不覆盖业务逻辑漏洞。
4. 对加密参数、复杂 JSON 请求和 SPA 前端路由覆盖有限。
5. OAST 命中需要目标能够访问外部回调地址。

## 第四十六章 多引擎结果融合、置信度与风险组

### 46.1 为什么需要融合而不是简单拼接

假设 ZAP、Wapiti 和 Nuclei 都报告同一个 URL 的 SQL 注入。简单拼接会产生三条风险，用户难以判断优先级；完全按 URL 去重又会把不同风险类型错误合并。

系统采用两级融合：

1. Finding 级：同 host、port、url、vuln_type 的实例合并，保留所有来源。
2. Risk Group 级：同 host、port、vuln_type 的示例聚合为一个风险组，受 URL 数量影响但不重复放大风险。

### 46.2 Finding 指纹

```python
payload = {
    "host": self.host.lower(),
    "port": self.port,
    "url": self.url or "",
    "vuln_type": self.vuln_type.lower(),
}
encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True)
return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]
```

指纹使用规范 JSON 和稳定字段，保证同样输入得到同样指纹。截取 32 位十六进制足够本地任务使用。

### 46.3 风险类型别名

不同工具使用不同名称：

```text
SQL Injection -> sql_injection
SQLi -> sql_injection
Cross Site Scripting -> cross_site_scripting
```

`config/vuln_alias.json` 保存别名，`normalize_vuln_type` 先精确匹配，再做包含匹配，最后把空格和连字符替换为下划线。

### 46.4 去重合并

同一指纹再次出现时：

1. 保留更高严重度。
2. 合并来源到 also_reported_by。
3. 在 raw.corroborating 中追加其他来源的证据。
4. 重新计算置信度和分数。

```python
if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
    existing.severity = finding.severity
for source in {finding.source, *finding.also_reported_by}:
    if source and source != existing.source and source not in existing.also_reported_by:
        existing.also_reported_by.append(source)
```

### 46.5 置信度公式

```text
source_score = min(100, (1 + 其他来源数量) * 35)
evidence_score = 有值字段数 / 5 * 100
severity_score = severity基础分 / 5 * 100
exposure_score = 本地25 / 私网55 / HTTPS公网75 / 其他公网100
confidence =
  source_score * 0.30 +
  evidence_score * 0.30 +
  severity_score * 0.25 +
  exposure_score * 0.15
```

这个公式表达四个假设：

1. 多来源印证比单工具更可信。
2. 证据字段越完整越可信。
3. 高严重度风险优先于低严重度。
4. 暴露程度影响实际风险。

它不是统计校准后的概率，也不是 CVE 官方 CVSS。报告中应写“置信度指标”，不能写成“真实概率”。

### 46.6 风险组键

风险组默认按 host、port、vuln_type 聚合。对 information_disclosure 和 sensitive_file_exposure，再增加 detail key（pluginId、template-id、alert 或 id），避免把完全不同类型的敏感文件合并成一个模糊组。

```python
payload = {
    "host": str(finding.get("host") or "").lower(),
    "port": finding.get("port"),
    "vuln_type": canonical,
    "detail": _detail_key(finding, canonical),
}
key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]
```

### 46.7 风险组字段

每个风险组包含：

| 字段 | 含义 |
|---|---|
| title_zh/title_en | 中英文风险名称 |
| severity | 所有实例中的最高严重度 |
| confidence | 最高或合并后的置信度 |
| sources | 所有工具来源 |
| affected_urls | 受影响 URL 去重列表 |
| fingerprints | 成员 Finding 指纹 |
| instances | 每条实例的证据摘要 |
| description/impact | 解读和影响 |
| reproduction_steps | 复核步骤 |
| false_positive_checks | 误报检查 |
| remediation | 修复建议 |
| retest_steps | 复测步骤 |
| analysis_source | deterministic 或 ai |

### 46.8 当前融合是否已经足够

当前融合是确定性的“同资产、同类型聚合 + 来源印证 + 静态置信度”，没有学习权重，也没有贝叶斯证据合成。它能解决重复展示和排序问题，但还没有证明每种工具的误报率、召回率和融合权重。

因此：

1. 当前可以证明系统完成了可复现的融合流程。
2. 当前不能仅凭 3×3 消融证明完整 Agent 一定优于三引擎组合。
3. 要证明融合设计有效，需要第五十三章的对照实验。

## 第四十七章 历史记忆、资产变化与重复扫描

### 47.1 设计目标

单次扫描只能回答“现在有什么”。重复扫描需要回答：

1. 这个风险是新增、持续还是已经消失。
2. 上次扫描是什么时候，结果数量和严重度如何变化。
3. 同一个资产是否有多个 URL 入口，是否共享相同风险。
4. 报告能否在历史上下文中解释结果。

系统因此保存 `AssetSnapshot`，并在任务开始前加载最近 10 次记录。

### 47.2 快照内容

快照保存：

1. asset_key。
2. target。
3. task_id。
4. status。
5. finding_count。
6. risk_group_count。
7. severity_counts。
8. risk_types。
9. created_at。

快照不是完整 Finding 副本，而是用于历史对比的摘要。完整 Finding 仍在 Task.findings 和任务输出中。

### 47.3 记忆上下文的生成

任务开始时，`load_memory_context` 查询同一 asset_key 最近 10 条快照，取最新一条作为 previous。任务合并后，`complete_memory_context` 计算：

```python
previous_types = set(previous.get("risk_types") or [])
current_types = set(risk_type_summary(groups))
new_types = current_types - previous_types
persistent_types = current_types & previous_types
resolved_types = previous_types - current_types
```

结果是新增、持续和消失的风险类型列表，而不是 URL 级别的简单 diff。

### 47.4 为什么使用风险类型而不是 Finding 差异

风险类型级别的变化更稳定：

1. ZAP 的 pluginId 可能版本变化。
2. URL 参数顺序可能变化，但风险类型不变。
3. 多次扫描的临时路径可能不同。
4. 用户更需要看到“新增 SQL 注入/已消失缺安全头”，而不是被 URL 随机变化淹没。

Finding 级差异仍保留在原始结果中，未来可以增加更细粒度 diff。

### 47.5 快照补建

应用启动时 `backfill_snapshots` 扫描已完成的旧 Task，若不存在快照则补建。它使升级前已有的任务也进入历史视图，避免版本升级后历史页面为空。

### 47.6 重复扫描的可验证性

重复扫描需要固定同一 scope、认证配置和工具版本。若只改变 tool_profile，必须记录变化，否则无法判断风险差异来自目标变化还是扫描器组合变化。

因此实验记录至少要保存：

1. task_id。
2. target 和 auth_ref。
3. mode、tool_profile、time_profile。
4. max_rps。
5. validation_level。
6. 工具版本和模板版本。
7. 扫描开始和结束时间。

## 第四十八章 AI 增强层：能力、约束与失效隔离

### 48.1 AI 在系统中的位置

AI 是可选后处理层，调用位置固定为 `merge_and_score` 之后、`report` 之前。它不能改变：

1. 扫描目标。
2. 工具命令。
3. 请求速率。
4. 授权范围。
5. 原始 Finding。
6. 证据文件。

它能做：

1. 对同一 host、port、vuln_type 的候选组做语义归并建议。
2. 生成中英双语解读。
3. 补充误报检查、修复和复测建议。
4. 给出 AI 自身置信度（展示用，不替代 Finding confidence）。

### 48.2 AI 配置存储

AI 配置可以来自数据库或环境变量。数据库配置优先级更高。

API Key 的加密流程：

```python
digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
fernet = Fernet(base64.urlsafe_b64encode(digest))
ciphertext = fernet.encrypt(api_key.encode("utf-8")).decode("ascii")
```

JWT_SECRET 轮换后旧密文无法解密，因此更换 JWT_SECRET 时应明确处理 AI Key 重新录入。读取接口只返回 `api_key_configured=true/false`，不回显明文。

### 48.3 OpenAI 兼容接口

请求端点：

```text
POST <base_url>/chat/completions
Authorization: Bearer <api_key>
Content-Type: application/json
```

请求体包含 model、messages、temperature 和 max_tokens。系统不绑定特定厂商，只要提供 OpenAI 兼容 chat completions 即可。

### 48.4 输入脱敏

AI 输入来自风险组和记忆上下文，包括：

1. group_key。
2. vuln_type。
3. host、port。
4. severity、confidence、sources。
5. affected_url_count 和最多 5 个 URL。
6. 最多 3 条 evidence sample。
7. 历史风险类型变化。

输入在发送前经过 `redact`，密码、token、Cookie、Authorization 和 API Key 被替换为 `***`。输出写回前再次经过 `redact_text`。

### 48.5 分批与缓存

`LLM_BATCH_SIZE` 默认 6，最多限制到 20。每个批次单独请求、单独校验和单独缓存。缓存键包含：

1. 批次中的组键、类型、host、port、URL 样本和来源。
2. memory context。
3. model。

缓存对象存放在 `ai_analysis_cache`。目标、组合或模型变化时缓存键变化，不会错误复用旧结果。

### 48.6 输出校验

模型输出必须是 JSON 对象。系统校验：

1. `member_group_keys` 必须来自输入候选组。
2. 同一 key 只能分配一次。
3. 一个合并组内的 host、port、vuln_type 必须完全一致。
4. 文本字段截断到 4000 字符。
5. 列表字段最多 20 条。
6. AI confidence 裁剪到 0 到 100。

如果模型尝试把不同风险类型合并，校验直接拒绝该组，原始组保留。

### 48.7 失败策略

AI 失败有三种级别：

1. 单个批次失败：该批次降级，其他批次继续。
2. 全部批次失败：`llm_summarize` skipped，任务继续。
3. 模型无输出或非法 JSON：skipped，不写 Finding。

`llm_summarize` 不会把任务主状态设置为 failed，除非外层流程图本身异常。报告仍使用确定性风险组。

### 48.8 如何评价 AI 是否真正有用

需要单独设计实验，而不是只看是否返回内容：

1. 人工标注 AI 摘要的事实正确率。
2. 语义归并是否错误合并不同根因。
3. 修复建议是否可执行。
4. 复测步骤是否会导致额外风险。
5. 与确定性模板相比，阅读时间是否下降。
6. 关闭 AI 与开启 AI 的 Finding 数量是否不变。
7. 延迟、成本和失败率。

当前代码和测试证明 AI 接入、加密、缓存、分批、跨类型拒绝和失败降级可用；真实模型输出质量尚未完成独立大规模验收。

## 第四十九章 证据链、报告与工作流图

### 49.1 输出目录结构

每个任务在 `/output/{task_id}/` 下有：

```text
report.html
report.json
findings.json
workflow.mmd
workflow.png
evidence/
  evidence_index.json
  <evidence_hash>.json
```

证据与报告分开保存，报告可以重新生成，证据文件仍可独立校验。

### 49.2 EvidenceStore 的职责

`EvidenceStore.write` 做四件事：

1. 构造包含 fingerprint、source、host、url、port、vuln_type、severity、evidence、raw 的 payload。
2. 对 evidence 字段计算规范 JSON SHA-256。
3. 以 hash 为文件名保存。
4. 把 hash 写回 Finding。

下载时 `read_verified` 重新计算 evidence 哈希，若不匹配返回 409。

### 49.3 报告 JSON 与 HTML 的分工

JSON 是机器可读事实：

1. task_id。
2. target。
3. status。
4. node_status。
5. execution_trace。
6. findings。
7. risk_groups。
8. memory_context。
9. budget_context。
10. workflow 路径。

HTML 是人类可读呈现：

1. 深色封面和指标卡。
2. 时间预算。
3. 历史变化。
4. AI 摘要（如启用）。
5. 风险组详情和修复剧本。
6. Finding 实例证据。
7. 被拦截目标。
8. 覆盖范围说明。
9. Mermaid 源。

HTML 使用 Jinja2 的 `autoescape=True`，工具输出和 URL 不会被当作原始 HTML 执行。

### 49.4 深色报告设计

报告的 CSS 使用 `color-scheme: dark`，主区域、iframe、滚动条和 workflow 容器使用同一暗色背景。设计目的是：

1. 避免报告加载时白色闪烁。
2. 让工作流图与报告视觉一致。
3. 在演示和评测环境中保持稳定对比度。

报告不是营销页面，采用信息密度较高的表格、折叠详情和等宽证据块，方便安全人员扫描和比较。

### 49.5 工作流图的双路径

后端先生成 Mermaid：

1. 只绘制实际进入执行链的节点，不再固定画出全部 19 个节点。
2. 按 execution trace 的真实顺序连接为单向数据流。
3. 每节点显示中英文名称、工具和摘要。
4. 状态类名映射颜色。

然后尝试用 mermaidx 渲染 PNG。渲染失败时：

1. 返回 workflow.png 不存在。
2. 前端读取 graph.mmd。
3. 使用本地 npm `mermaid` 包在浏览器中渲染 SVG。

这样不依赖在线渲染服务，也避免 Graphviz 缺失导致报告页面无法展示。

### 49.6 中文字体处理

Worker 镜像安装 `fonts-wqy-microhei`。工作流渲染优先使用：

1. `WORKFLOW_CJK_FONT` 指定字体。
2. `/usr/share/fonts/truetype/wqy/wqy-microhei.ttc`。
3. Noto CJK。
4. Windows 的 SimHei/微软雅黑（仅本地开发）。

没有字体时，mermaidx 可能把中文渲染为方框。因此中文工作流不是仅靠 CSS，而是容器内真实安装字体。

### 49.7 报告重建

历史任务可通过脚本重新生成报告和工作流：

```powershell
docker compose exec -T worker python /app/scripts/regenerate_reports.py --task-id <task_id>
docker compose exec -T worker python /app/scripts/regenerate_workflows.py --task-id <task_id>
```

重建使用数据库中保存的 `report_json.execution_trace` 和 `node_status`，不重新扫描目标。因此修复模板或字体后可以批量重新渲染历史报告。

## 第五十章 前端架构、交互状态与视觉系统

### 50.1 前端总体框架

前端是 React 18 单页应用，由 Vite 构建，入口为：

```text
main.jsx
  -> BrowserRouter
  -> App.jsx
  -> Protected route
  -> AppShell
  -> page component
```

页面不是独立 HTML，而是共享一个 `AppShell` 控制面。这样导航、操作员信息、搜索、环境状态和主导航保持一致。

### 50.2 路由与受保护页面

```jsx
function Protected({ children }) {
  const location = useLocation();
  if (!getToken()) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}
```

路由表：

| 路径 | 页面 | 核心作用 |
|---|---|---|
| `/login` | Login | 获取 JWT |
| `/` | Dashboard | 资产、任务、引擎和事件总览 |
| `/scan` | Submit | 创建扫描任务 |
| `/history` | History | 资产历史和任务记录 |
| `/settings/ai` | AISettings | AI 配置和连接测试 |
| `/tasks/:id` | TaskDetail | 19 节点、实时事件、风险组、Finding、下载 |
| `/tasks/:id/report` | Report | 深色工作流和完整 HTML 报告 |

当前前端是客户端路由保护，不是服务端会话页面。真正的权限仍由后端 JWT 和 API 控制，前端隐藏页面只用于体验。

### 50.3 API 客户端

`api.js` 统一处理：

1. 从 localStorage 读取 token。
2. 自动添加 `Authorization: Bearer`。
3. 设置 `cache: no-store`。
4. 解析 JSON 或纯文本。
5. 401 时清除 token 并跳转登录。
6. 非 2xx 抛出带有后端 detail 的错误。

```javascript
const response = await fetch(`${API_BASE}${path}`, {
  cache: "no-store",
  ...options,
  headers,
});
if (response.status === 401 && path !== "/api/auth/login") {
  clearToken();
  window.location.assign("/login");
}
```

下载文件使用独立的 `downloadFile`，因为二进制响应不能经过 JSON 解析。工作流 PNG、MMD 和报告 JSON 都通过带 JWT 的 fetch 获取，再由 Object URL 下载。

### 50.4 实时状态合并

任务详情页同时使用两个数据源：

1. 每 2 秒轮询 `/api/tasks/{id}`。
2. 使用 `EventSource` 连接 `/api/tasks/{id}/events`。

轮询负责最终一致性，SSE 负责实时性。节点状态合并：

```javascript
const nodeStatus = { ...(task?.node_status || {}), ...liveStatus };
```

SSE 事件按 `on_chain_start`、`on_chain_end`、`on_chain_error` 转换为 running、done、failed。数据库查询返回的 node_status 是后端最终事实，实时事件可以在它之上覆盖当前状态。

### 50.5 组件职责

| 组件 | 作用 |
|---|---|
| AppShell | 侧栏、搜索、导航、操作员和退出 |
| PageHeader | 页面标题、动作按钮和说明 |
| StatusBadge | 任务状态色彩和文字 |
| DataFlow | 按真实执行顺序显示工具数据流 |
| NodeGrid | 保留的节点网格组件，当前任务详情主视图不再使用 |
| NodeCard | 单节点名称、工具、状态、摘要和错误 |
| RiskGroupList | 风险组折叠详情 |
| FindingList | Finding 实例列表 |
| TraceView | 执行事件和轨迹 |

### 50.6 视觉系统

主题使用深色控制面：

| 语义 | 颜色 |
|---|---|
| 画布 | `#050506` |
| 面板 | `#0e0e10` |
| 强边框 | `#35353a` |
| 主文字 | `#f5f5f6` |
| 次要文字 | `#8a8a92` |
| 操作蓝 | `#2878ff` |
| 完成绿 | `#c2f56a` |
| 等待琥珀 | `#ffc761` |
| 错误红 | `#ff6f7f` |

低层级背景、面板和边框形成信息层级，状态色只用于传达状态，不用于大面积装饰。

### 50.7 字体与可读性

CSS 的字体变量为：

```css
--ui-font:
  "Segoe UI Variable Text",
  "Segoe UI",
  "SF Pro Text",
  "Helvetica Neue",
  "Noto Sans SC",
  "PingFang SC",
  "Microsoft YaHei UI",
  "Microsoft YaHei",
  sans-serif;
```

设计原因：

1. 优先 Windows 11 的 Segoe UI Variable Text，提高英文可读性。
2. 中文使用微软雅黑或思源/PingFang 作为回退。
3. 启用 `-webkit-font-smoothing: antialiased` 和 `text-rendering: optimizeLegibility`。
4. 等宽内容使用 `ui-monospace`，避免表格和证据字段错位。

字体是否清晰仍受显示器缩放、浏览器缩放和操作系统字体渲染影响。前端可继续增加用户可选的字体大小和清晰模式，但当前未实现该用户级设置。

### 50.8 响应式与最小宽度

当前布局以桌面控制台为主，`body` 设置了 `min-width: 1100px`，并通过 NodeGrid、两个栏布局和横向滚动表格保持信息密度。它不是移动优先产品，手机端需要重新设计导航和操作流程。

如果要在窄屏使用，应把：

1. 侧栏变成可折叠抽屉。
2. 四列节点变为 1 到 2 列。
3. 任务表格改为卡片。
4. 表单和风险声明增加纵向布局。
5. 工作流图保留横向滚动而不是强行缩放。

### 50.9 可访问性和操作安全

当前实现了：

1. 图标按钮提供 `aria-label`。
2. 表单字段有可见标签。
3. 键盘焦点使用蓝色 outline。
4. 授权确认是真实 checkbox。
5. 状态除了颜色还有文字和图标。

仍需改进：

1. 更完整的焦点顺序和键盘导航测试。
2. ARIA live region 用于任务状态变化。
3. 色盲对比度自动检查。
4. 高对比度主题。

## 第五十一章 前端页面逐页数据流与交互

### 51.1 登录页

输入：username、password。

流程：

1. POST `/api/auth/login`。
2. 保存 access_token。
3. 跳转到来源页面或总览页。
4. 错误时显示后端 detail。

登录页不提供自助注册和密码重置，因为项目采用单管理员、本地部署模型。

### 51.2 总览页

数据源：

1. `/api/history/assets`。
2. `/api/history/tasks?limit=50`。
3. `/api/capabilities`。
4. 活跃任务的 SSE。
5. 最近任务 report.json 中的 execution_trace。

展示：

1. 资产数、Finding 数、高危数、任务数。
2. 实时数据流。
3. 引擎状态轮播。
4. 最近任务表。
5. 高频风险排行。

设计取舍：总览页偏向监控和态势，不放复杂的扫描配置；扫描配置集中在 `/scan`。

### 51.3 新建扫描页

页面分为四段：

1. 目标与认证。
2. 扫描策略与工具组合。
3. 时间预算与速率。
4. 主动验证和 OAST。

风险声明放在提交按钮上方，符合“先理解风险，再开始扫描”的操作顺序。授权复选框直接控制提交按钮的禁用状态，后端再次强制校验。

提交请求：

```javascript
const task = await api("/api/tasks", {
  method: "POST",
  body: JSON.stringify({
    target,
    auth_ref: authRef,
    max_rps: Number(maxRps),
    mode,
    tool_profile: toolProfile,
    time_profile: timeProfile,
    time_budget_seconds: Number(budgetMinutes) * 60,
    validation_level: validationLevel,
    oast_enabled: oastEnabled,
    authorization_confirmed: authorizationConfirmed,
  }),
});
navigate(`/tasks/${task.id}`);
```

说明：前端允许填写最多 120 分钟，但后端 `MAX_TASK_SECONDS` 默认 7200 秒，并且 Guard 会拒绝超过服务端上限的值。正式部署应让前端上限与服务端配置一致。

### 51.4 任务详情页

数据流：

1. 首次加载任务、终态时加载 findings 和 execution_trace。
2. 活跃任务每 2 秒轮询。
3. SSE 实时更新节点卡片。
4. 终态后禁用恢复/取消按钮，保留下载。

信息结构：

1. 顶部目标、状态、取消、恢复、新建和报告入口。
2. 指标卡：Finding、风险组、节点完成度、执行预算。
3. 工作流 19 节点。
4. 风险组/Finding 标签页。
5. 任务概览、实时事件、交付文件。
6. AI 辅助研判（可选）。

### 51.5 风险组与 Finding

风险组是阅读入口，Finding 是证据入口。

风险组展开后显示：

1. 中英文标题。
2. 严重度和置信度。
3. 来源工具。
4. 受影响 URL。
5. 复现、误报检查、修复和复测建议。

Finding 展示：

1. 来源、类型、host、port、url。
2. confidence、evidence hash。
3. evidence/raw 详情。
4. 关联 playbook。

### 51.6 报告页

并行加载：

1. HTML 报告。
2. report.json。
3. workflow.png。

如果 PNG 404，读取 graph.mmd 并用前端 Mermaid 渲染；如果两者都无，显示“生成中”。完整 HTML 报告放在 iframe 的 `srcDoc` 中，外框使用深色背景和深色滚动条，避免白屏闪烁。

### 51.7 历史与资产页

页面用资产键聚合历史任务：

1. 资产列表显示目标、风险类型、扫描次数、风险组、Finding delta。
2. 任务记录表支持按目标和状态筛选。
3. 点击资产进入最近一次任务。
4. 当前没有独立资产详情路由，资产详情能力由历史 API 提供，前端主要使用列表视图。

### 51.8 AI 设置页

读取配置时不展示明文 Key，只展示“已配置/未配置”。保存时如果用户留空 Key，后端保留原密文；只有显式提交新 Key 才替换。

测试连接使用当前表单值或已保存配置，不执行扫描，只验证 `/chat/completions` 可达和返回格式。

## 第五十二章 测试体系、质量门禁与可重复性

### 52.1 测试分层

| 层 | 测试文件 | 验证内容 |
|---|---|---|
| 数据与模型 | `test_schemas.py` | Finding 指纹、Task 模型、OAST 约束 |
| 安全门禁 | `test_guard.py`、`test_scope_guard.py` | 授权确认、CIDR、DNS 重绑定、重定向和 OpenAPI 外链 |
| API | `test_api_security.py` | JWT、SSE 格式、403、取消审计 |
| 图状态 | `test_graph.py` | 全链路、工具 profile、跳过、恢复和状态优先级 |
| 适配器 | `test_adapters.py` | 13 类工具的调用和解析 |
| 认证与预算 | `test_auth_budget_validation.py` | form 登录、CSRF、预算、主动验证、OAST |
| Worker | `test_worker_lifecycle.py` | 恢复节点选择、子进程取消和阶段 deadline |
| 融合与记忆 | `test_risk_memory.py`、`test_evidence_report.py` | 去重、置信度、证据哈希、报告、脱敏 |
| AI | `test_llm.py` | 默认关闭、跨类型拒绝、分批、缓存和降级 |
| 历史 API | `test_ai_history_api.py` | Key 掩码、资产历史接口 |

### 52.2 当前测试基线

当前自动化测试结果：

```text
66 passed, 2 warnings
```

两个 warning 来自第三方库弃用提示，不影响测试结果。它们是残余风险，升级上游依赖时需要重新评估。

### 52.3 测试为何使用替身

大部分适配器测试不会真的运行 Nmap 或 ZAP，而是 monkeypatch `_run` 或 REST 客户端，返回固定输出。这样测试验证的是：

1. 命令参数是否完整。
2. 输出解析是否正确。
3. 严重度和 Finding 字段是否一致。
4. 取消和超时是否传播。

真实工具行为由 Compose 集成验收和实际任务 ID 验证，不由单元测试伪造。

### 52.4 测试金字塔

```text
               真实靶场与人工演示
             Compose 集成与验收脚本
          图、API、适配器、解析器测试
       纯函数、Schema、预算和 Guard 测试
```

底层测试快且稳定；上层测试慢但更接近真实。两类测试都需要，不能用单元测试代替靶场验收，也不能只靠一次靶场成功代替所有边界测试。

### 52.5 可重复性验证

一个任务结果可重复，至少要记录：

1. 相同的目标和授权引用。
2. 相同的 Compose profile。
3. 相同的镜像和工具版本。
4. 相同的模板/feed 版本。
5. 相同的 tool_profile、mode、validation_level。
6. 相同的 max_rps 和时间预算。

若目标内容动态变化或扫描器模板变化，结果差异不能直接归因于系统设计。

## 第五十三章 融合实验、真实有效性证明与替代人工验证

### 53.1 当前证据能够证明什么

当前项目已有以下证据：

1. 66 个自动化测试通过。
2. Docker 默认配置和 full 配置能够解析。
3. DVWA、Mock 和 OpenVAS 曾完成实际任务。
4. 任务能够生成 Finding、风险组、证据文件、HTML/JSON 报告和 PNG 工作流。
5. 取消和恢复流程有实际任务 ID 与自动化测试。
6. 3×3 消融脚本和 DVWA ground truth 已经存在。

这些证据可以支持以下结论：

1. 系统是真实可运行的软件，不是静态原型。
2. 多工具调用、状态编排、证据和报告链路已经打通。
3. 在指定靶场和指定版本下，流程可复现。
4. 系统能够自动完成资产发现、扫描调度、结果归一化、报告草稿和大部分重复工作。

这些证据暂时不能支持以下结论：

1. 系统在所有真实公网资产上都比人工更强。
2. 系统的风险组排序已经经过统计校准。
3. AI 输出质量已经达到安全专家水平。
4. 系统可以完全取代安全工程师。
5. 当前完整 Agent 一定优于 ZAP + Wapiti + Nuclei 三引擎组合。

这五条必须通过后续实验证明，不能用“功能存在”替代“效果已被证明”。

### 53.2 “真实有效”的四层证明链

建议把有效性证明拆成四层，每层有不同证据。

| 层次 | 问题 | 需要的证据 |
|---|---|---|
| 真实性 | 系统是否真的执行了扫描 | 任务 ID、容器日志、工具版本、原始输出、证据哈希 |
| 可重复性 | 同样条件下是否能再次得到相近结果 | 多次重复、固定镜像、版本锁定、结果稳定性指标 |
| 有效性 | 是否比单工具或人工基线更好 | Ground Truth、Recall、Precision、F1、时间、成本 |
| 可替代性 | 是否能承担原本由人完成的工作 | 工作分解、时间动作研究、影子运行、人工复核率 |

#### 真实性证据

每个验收任务应保存：

1. task_id。
2. 创建时间和结束时间。
3. target 和 auth_ref。
4. mode、tool_profile、time_profile、validation_level。
5. 工具版本和模板版本。
6. execution_trace。
7. findings.json。
8. report.json。
9. report.html。
10. evidence/*.json 和 SHA-256。
11. Docker Compose 配置摘要。
12. 关键日志。

仅有截图不足以证明结果真实。截图可以由人工伪造；任务 ID、数据库记录、原始证据、哈希、日志和重复执行组合起来，可信度更高。

#### 可重复性证据

对每个目标至少重复 3 次，记录：

1. 每次发现的 Finding 集合。
2. 两次运行之间的 Jaccard 相似度。
3. 风险类型集合差异。
4. 高严重度风险的稳定性。
5. 单次扫描耗时和资源占用。

建议定义：

```text
Jaccard = |A ∩ B| / |A ∪ B|
```

Jaccard 用于 Finding 指纹或风险类型集合。只比较数量是不够的，因为数量相同不代表发现的风险相同；只比较风险类型也不够，因为 URL 和证据可能变化。

#### 有效性证据

必须有独立 Ground Truth。Ground Truth 不应只来自本系统输出，否则会形成循环验证。建议由人工根据靶场文档、源码配置、已知 CVE 和独立工具结果标注，并由第二名分析员复核。

#### 可替代性证据

“替代人工”不是一句总体结论，而是按任务分解衡量：

| 工作项 | 当前自动化程度 | 是否可替代人工 |
|---|---:|---|
| 目标录入和授权确认 | 高 | 仍需人工承担法律责任 |
| 资产发现 | 高 | 大部分可自动完成 |
| 端口和 Web 指纹 | 高 | 大部分可自动完成 |
| 多工具调度 | 高 | 可自动完成 |
| 结果去重和归一化 | 高 | 可自动完成，需抽检 |
| Finding 初筛 | 中到高 | 可减少人工阅读量 |
| 漏洞真实性和影响确认 | 中 | 需要人工复核 |
| 业务逻辑漏洞 | 低 | 当前无法替代 |
| 修复建议 | 中 | 可用于草稿，需专家确认 |
| 修复后复测 | 中到高 | 可自动执行，需人工定义验收 |
| 最终报告签发 | 低 | 必须由责任人确认 |

因此合理目标是“替代重复性操作和初级整理工作”，而不是“完全取代安全工程师”。

### 53.3 当前 3×3 消融结果的正确解释

当前结果：

| 组别 | Mean Recall | Mean Precision | Mean FP Rate | Mean Seconds |
|---|---:|---:|---:|---:|
| 单 Nuclei | 0.000 | 0.000 | 0.000 | 35.30 |
| ZAP + Wapiti + Nuclei | 0.417 | 0.527 | 0.473 | 647.57 |
| 完整 Agent | 0.417 | 0.527 | 0.473 | 647.62 |

结论应写成：

1. 在当前 DVWA 和固定 ground truth 下，单 Nuclei 没有命中标注类别。
2. 三引擎组合把 Recall 提升到 0.417。
3. 当前完整 Agent 与三引擎组合在该样本上结果相同，没有观察到额外收益。
4. 这不能解释为“完整 Agent 无效”，因为当前 ground truth 可能没有覆盖其他工具擅长的类别。
5. 这也不能解释为“完整 Agent 有效替代人工”，因为样本只有 DVWA，重复次数和人工基线不足。

这种如实解释比宣称“全面领先”更符合工程验证要求，也为下一阶段实验提供了明确问题：增加覆盖资产类型、加入人工基线和更细的 ground truth。

### 53.4 融合实验的目标

融合实验要回答四个问题：

1. 多引擎联合是否显著提高 Recall，而不是只增加结果数量。
2. 去重和交叉印证是否显著降低 FP Rate 和重复阅读量。
3. 融合后的风险组排序是否让人工更快处理高风险。
4. 融合是否在不同目标、不同工具组合和多次运行中保持稳定。

### 53.5 实验对象与数据集设计

建议至少包含五类目标：

| 类别 | 示例 | 目的 |
|---|---|---|
| 本地 Web 靶场 | DVWA | 已知漏洞、认证和重复性验证 |
| 条件边 Mock | 项目自带 Mock | OpenAPI、6443 和跳过逻辑 |
| 现代 SPA/API 靶场 | 受控 Juice Shop 或等价本地目标 | JavaScript、API 和现代前端覆盖 |
| 授权真实站点 | 自有或书面授权的 20 到 50 个资产 | 真实噪声、CDN、WAF 和响应差异 |
| 主机层目标 | 受控 Linux VM | Nmap、OpenVAS 和服务层覆盖 |

目标选择要避免只选系统擅长的样本。需要同时包含：

1. 简单静态站点。
2. 带登录的表单站点。
3. API/OpenAPI 服务。
4. 有 CDN 和重定向的站点。
5. 无漏洞目标，用于测量误报。
6. 高噪声目标，用于测量去重能力。

### 53.6 Ground Truth 构建流程

1. 为每个目标建立资产清单和允许范围。
2. 由分析员 A 使用独立工具、源码配置和人工检查标注漏洞。
3. 由分析员 B 在不看 A 结果的情况下独立标注。
4. 对不一致项进行复核，由第三方或双方讨论裁决。
5. 记录漏洞类型、URL、参数、严重度、可利用条件和证据。
6. 冻结 ground truth 版本和 hash。
7. 实验运行期间不根据系统结果修改 ground truth。

建议报告 Cohen's kappa 或 Krippendorff's alpha：

```text
kappa = (Po - Pe) / (1 - Pe)
```

建议目标：两名标注者的一致性 kappa ≥ 0.80。低于该值应先完善标注规范，而不是比较系统效果。

### 53.7 实验分组

至少需要以下六组：

| 组别 | 策略 | 用途 |
|---|---|---|
| M0 | 人工使用常规工具 | 人工基线 |
| M1 | 单 Nuclei | 单引擎基线 |
| M2 | ZAP + Wapiti + Nuclei | 现有三引擎基线 |
| M3 | 完整 Agent + 当前确定性融合 | 当前系统 |
| M4 | 完整 Agent + 加权/证据融合实验 | 未来融合算法 |
| M5 | 完整 Agent + 人工复核 | 人机协同上限 |

可选增加：

| 组别 | 策略 | 用途 |
|---|---|---|
| M6 | M3 + AI 解读 | 评价 AI 对阅读效率和摘要质量的影响 |
| M7 | 多引擎但不去重 | 证明去重本身是否减少噪声 |

### 53.8 重复次数与随机化

1. 每个目标每个组至少重复 3 次。
2. 高噪声或动态目标建议重复 5 到 10 次。
3. 组间顺序随机化，避免缓存或网络状态只影响某一组。
4. 固定工具版本、模板版本和扫描预算。
5. 目标状态在重复之间恢复快照，避免前一次扫描改变目标。

### 53.9 核心指标

#### 检出与误报

```text
Recall = TP / (TP + FN)
Precision = TP / (TP + FP)
F1 = 2 * Precision * Recall / (Precision + Recall)
FP Rate = FP / (FP + TN)
```

TP、FP、FN 需要基于统一漏洞类型和 URL/参数匹配规则。匹配规则必须先冻结，不能在看到结果后调整。

#### 严重度加权召回

严重漏洞漏报比信息级发现漏报代价更高，可以使用：

```text
Weighted Recall = sum(weight_i * hit_i) / sum(weight_i)
```

建议权重：info=1、low=2、medium=3、high=4、critical=5。该权重用于实验排序，不等于真实业务风险。

#### 重复压缩率

```text
Duplicate Reduction =
  (原始工具 Finding 数 - 归一化后 Finding 数) / 原始工具 Finding 数
```

还需要看风险组数量相对 Finding 数量下降多少，但不能把压缩率高直接当成质量高；如果合并过度，Recall 会下降。

#### 人工处理时间

记录：

1. 原始结果阅读时间。
2. 去重和验证时间。
3. 报告整理时间。
4. 人工复核和二次确认时间。
5. 总 wall-clock time。
6. 每个任务的人工切换次数。

#### 可行动性

对每条高风险 Finding 评分：

1. 是否有足够证据定位。
2. 是否能按报告复现。
3. 修复建议是否具体。
4. 是否有误报检查。
5. 是否能在复测中确认修复。

可使用 1 到 5 分的人工评分量表，并计算评分者一致性。

#### 稳定性

对同一目标多次运行计算：

1. Finding 集合 Jaccard。
2. 风险类型集合 Jaccard。
3. 高严重度 Finding 的命中频率。
4. 节点状态是否异常波动。
5. 平均耗时方差。

#### 成本

```text
Cost per asset =
  compute cost + model cost + license cost + storage + human review time
```

没有人工复核的“低成本”是误导，必须把复核时间计入总拥有成本。

### 53.10 统计方法

1. 对连续指标报告均值、标准差和 95% bootstrap 置信区间。
2. 对同一目标不同组的结果使用配对比较，避免目标难度差异。
3. 对“是否检出某风险”使用 McNemar 检验。
4. 对耗时使用 Wilcoxon signed-rank 检验。
5. 对多目标、多组数据可使用混合效应模型，把目标作为随机效应。
6. 对人工评分一致性使用 Cohen's kappa 或 ICC。
7. 对多个指标不要只挑选显著结果，应预先定义主要指标和次要指标。

### 53.11 融合算法实验路线

当前系统使用固定规则去重和线性置信度。下一阶段可以比较：

#### 方案 A：当前确定性融合

同 host、port、url、vuln_type 去重，来源数量和证据完整度加权。

优点：可解释、可复现、无需训练。

#### 方案 B：工具精度加权

用验证集统计每个工具在不同漏洞类型上的 Precision，再对 Finding 进行加权投票。必须按漏洞类型分桶，不能用全局权重代替。

#### 方案 C：证据一致性融合

只有不同工具在相同 URL、参数、CVE 或证据特征上一致时才提高置信度。这样可以减少“相同类型但不同根因”的错误合并。

#### 方案 D：校准置信度

把当前 0 到 100 的 heuristic score 用 logistic regression 或 isotonic regression 校准为可解释的命中概率区间。校准集和测试集必须分离。

#### 方案 E：风险组排序学习

使用严重度、工具来源、证据完整度、暴露程度和历史变化训练排序模型。模型输出只影响阅读顺序，不删除 Finding。

这些方案必须在同一 ground truth 和同一预算下比较，不能只展示某一个成功样本。

### 53.12 人机基线的设计

人工基线不是让分析员随便点几下工具，而是规定相同任务：

1. 相同目标范围。
2. 相同时间预算。
3. 可使用相同或等价工具。
4. 必须输出 Finding、证据和报告。
5. 由独立人员复核结果。

记录时间动作：

| 阶段 | 人工基线 | 系统 |
|---|---|---|
| 建目标和检查授权 | 手工记录 | 表单和 Guard |
| 发现子域和端口 | 多工具手工拼接 | 自动编排 |
| 扫描 | 手工启动和等待 | Worker 自动执行 |
| 去重 | 人工表格 | Finding/风险组 |
| 证据整理 | 手工截图和文件 | EvidenceStore |
| 报告 | 手工写文档 | Jinja2/JSON |
| 复核 | 人工 | 人工 |

### 53.13 替代人手的量化方式

建议定义“受控任务自动化率”：

```text
A = 自动化完成的工作量权重 / 完成任务的总工作量权重
```

权重可按耗时或步骤定义，并分别计算：

1. 数据采集自动化率。
2. 扫描调度自动化率。
3. 结果归一化自动化率。
4. 证据整理自动化率。
5. 报告生成自动化率。
6. 漏洞验证自动化率。
7. 最终签发仍需人工的比例。

还可以定义“同等人力可管理资产数”：

```text
Throughput gain =
  (Targets_manual / Person_hours_manual)
  / (Targets_system / Person_hours_system)
```

这个指标比“节省了多少秒”更接近组织价值，但必须包含人工复核和纠错。

### 53.14 可以合理宣称的替代级别

建议把自动化能力分为五级：

| 级别 | 描述 | 当前判断 |
|---|---|---|
| L0 | 完全人工 | 不是本项目 |
| L1 | 工具辅助，人工执行 | 部分工具可这样用 |
| L2 | 自动扫描，人工复核与签发 | 当前主要定位 |
| L3 | 自动验证，少量人工审批 | 部分场景接近，尚未全面证明 |
| L4 | 无人值守自主决策 | 不符合当前安全边界 |

当前最稳妥的表述是：

> 系统可以替代安全评估中的重复性资产发现、工具调度、结果归一化、证据整理和报告草稿工作，并在受控靶场中形成可复核的扫描闭环；它不能替代授权责任、业务逻辑分析、漏洞影响确认和最终报告签发。

### 53.15 证明“可以替代人手”的实验阶段

#### 阶段一：实验室等价性

目标：DVWA、Mock、现代 Web 靶场。

比较：M0 人工基线与 M3 当前系统。

通过条件建议：

1. 风险类型 Recall 不低于人工基线的 90%。
2. 高危/严重漏洞漏报率不高于人工。
3. 人工复核后有效 Finding 的 Precision 不低于人工。
4. 报告生成和证据整理时间减少 50% 以上。
5. 每个 Finding 都可追溯到工具和证据。

这些是建议门槛，不是当前已完成结果。

#### 阶段二：融合增益实验

比较：M2、M3、M4 和 M7。

通过条件建议：

1. M4 相比 M2 的 Recall 提升具有统计显著性。
2. FP Rate 不显著升高。
3. 风险组阅读量下降，同时不损失高风险 Finding。
4. 多次运行 Jaccard 不低于预设阈值。

#### 阶段三：影子运行

在真实授权环境中，系统与人工团队并行运行，但系统报告不直接作为最终结论。

记录：

1. 系统独有发现。
2. 人工独有发现。
3. 双方一致发现。
4. 人工确认的误报。
5. 人工确认的漏报。
6. 复核耗时。

影子运行是证明真实有效性的关键，因为它使用真实网络、真实噪声和真实流程。

#### 阶段四：小规模试点

在一个团队和一个资产组中让系统生成初稿，人工签发。连续运行 4 到 8 周，观察：

1. 每资产人工小时。
2. 报告返工率。
3. 高危漏报事件。
4. 用户满意度。
5. 数据保留和审计问题。

#### 阶段五：受控替代

只有在阶段一到四达标后，才把部分重复工作从人工流程中移除，例如资产发现、扫描调度、初筛和证据汇总。最终签发、授权和业务影响确认仍保留人工。

### 53.16 证明系统真实性的其他材料

除了实验数据，建议保留：

1. 带时间戳的 Docker 镜像摘要。
2. 任务创建、执行、完成日志。
3. 工具原始输出样本。
4. 项目源代码提交记录和版本标签。
5. API OpenAPI 文档。
6. 数据库任务记录。
7. 证据文件 SHA-256。
8. 重复运行的 task_id 列表。
9. 靶场恢复脚本和 ground truth 版本。
10. 两名评审人员的签字或评审记录。
11. 无法复现的实验单独记录，不删除。

### 53.17 常见“伪证明”要避免

1. 只展示一个成功截图，不展示失败和跳过。
2. 只比较 Finding 数量，不比较准确率。
3. Ground Truth 从系统结果反向生成。
4. 不同实验组使用不同时间预算。
5. 只跑一次，声称稳定。
6. 只挑有漏洞的目标，不测无误报目标。
7. 把 info 级发现计入高危命中。
8. 把 AI 生成的自然语言当作漏洞真实性证据。
9. 没有记录工具版本和模板版本。
10. 把“能运行”错误等同为“能替代人工”。

### 53.18 当前最应该补做的五项实验

1. 扩大 ground truth：从只有 DVWA 扩展到 Mock、现代 Web 靶场和授权真实站点。
2. 加入人工基线：记录人工完成同一任务的真实耗时、发现和误报。
3. 做重复运行：至少 3 次，计算 Jaccard、Recall 方差和耗时分布。
4. 比较融合策略：当前规则、加权投票、证据一致性和不去重基线。
5. 做影子运行：在真实授权资产上并行人机结果，统计系统独有、人工独有和共同发现。

### 53.19 最终可交付的有效性证明包

建议最终形成单独目录：

```text
validation-evidence/
  experiment-protocol.md
  ground-truth/
  targets/
  task-ids/
  raw-outputs/
  findings/
  reports/
  evidence-hashes/
  human-baseline/
  statistical-analysis/
  screenshots/
  reviewer-signoff/
```

验收人应能从目标列表和 task_id 重新得到同一批结果，并能从证据哈希验证报告没有被替换。只有这样，“真实有效”和“可复核”才有工程证据，而不是口头描述。

## 第五十四章 部署、构建、运维与发布

### 54.1 部署层级

| 层级 | 组成 | 用途 |
|---|---|---|
| 单机基础 | frontend/backend/worker/postgres/redis/zap/oast | 日常使用和验收 |
| 实验室 | 基础服务 + dvwa + mock | 条件边和本地靶场 |
| 完整 | 基础服务 + openvas full profile | 主机扫描 |
| 离线 | 预先构建镜像 + 离线包 | 无外网演示 |
| 生产化 | 反向代理、密钥管理、RBAC、独立扫描网段 | 尚未完成 |

### 54.2 环境准备检查表

1. Windows 11 + Docker Desktop，或 Linux Docker Engine + Compose v2。
2. CPU 架构为 AMD64。
3. 至少预留足够磁盘给镜像、PostgreSQL、OpenVAS feed 和输出证据。
4. 端口 3000、8000、8081、18000、16443、18001 未冲突。
5. `.env` 已从 `.env.example` 创建。
6. 所有默认密码和 JWT Secret 已修改。
7. 需要 OpenVAS 时已拉取大镜像并准备 feed 同步时间。

### 54.3 基础启动

```powershell
cd D:\桌面\传智杯\attack-surface-scanner
.\start.bat
```

Linux/macOS：

```sh
./start.sh
```

启动脚本会检查 Docker、Compose、创建 `.env`、拉起基础与实验室 profile、等待 `/health`，最后启动可选 VAS。

### 54.4 full profile

```powershell
.\start-full.bat
```

等效命令：

```powershell
docker compose -f docker-compose.yml -f docker-compose.full.yml `
  --profile full --profile dvwa --profile mock up -d --build
```

OpenVAS 首次同步可能需要很长时间。能力接口可能先显示 `feed_not_synced` 或 `service_unreachable`，这属于预期状态，不应通过伪造 Finding 绕过。

### 54.5 健康检查

```powershell
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
docker compose logs --tail=200 backend worker
```

健康检查只证明 API 可用，不证明所有外部工具可用。工具能力应查询：

```powershell
$body = @{ username = "admin"; password = "changeme" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/auth/login `
  -ContentType application/json -Body $body
$headers = @{ Authorization = "Bearer $($login.access_token)" }
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/capabilities -Headers $headers
```

### 54.6 构建与镜像分层

后端 Dockerfile 分阶段安装 Python 依赖，并以非 root 用户 `scanner` 运行。

Worker Dockerfile：

1. 固定 Debian bookworm。
2. 安装 Python 3.12 运行时。
3. 安装 Nmap、Nikto 和字体。
4. 下载固定版本 ProjectDiscovery 工具并做 SHA-256 校验。
5. 安装 Worker Python 依赖。
6. 单独安装 `gvm-cli` 依赖层，但不 import `gvm`。
7. 复制应用和 Worker 代码。
8. 以 `scanner` 用户运行 Celery。

前端 Dockerfile 是两阶段构建：

```text
node:22.12.0-alpine -> npm ci -> vite build
nginx:1.27.3-alpine -> 复制 dist
```

### 54.7 离线包

联网 AMD64 主机：

```powershell
.\scripts\make_offline_bundle.ps1 -BundleDir offline-bundle
```

离线目标机：

```powershell
.\scripts\load_offline_bundle.ps1 -BundleDir offline-bundle
```

离线包包含基础镜像和 SHA256SUMS，不默认包含体积很大的 OpenVAS。加载离线包前仍应检查校验和、架构和镜像版本。

### 54.8 数据备份与清理

必须备份：

1. `postgres_data`。
2. `output_data`。
3. 需要复现时的 OpenVAS feed/配置。
4. `.env` 的配置模板，但不要明文分发密钥。

清理过期证据前先用 dry-run：

```powershell
python scripts/cleanup_evidence.py --days 30 --dry-run
```

确认后再执行实际删除。生产环境应加入证据保留策略、例外审批和不可篡改审计。

### 54.9 日志与故障定位

| 现象 | 优先检查 |
|---|---|
| 页面打不开 | frontend 容器、端口、Nginx 日志 |
| 登录失败 | `.env` 管理员账号、backend 日志、数据库用户表 |
| 任务一直 queued | Redis、Celery Worker、任务是否已投递 |
| 任务 running 不动 | 当前节点、Worker 日志、阶段 deadline |
| 工具 unavailable | capabilities、PATH、镜像构建、外部服务健康 |
| OpenVAS 不可用 | full profile、9390、CA、gvm-cli、feed 状态 |
| 报告 404 | task 状态、output volume、report 路径 |
| PNG 缺失 | mermaidx、字体、/tmp、graph.mmd 是否已生成 |
| SSE 不更新 | Redis 频道、JWT query token、Nginx 代理缓冲 |
| 恢复后重复扫描 | checkpoint/thread_id、node_status、resume_state |

### 54.10 发布版本管理

每次发布应固定：

1. `VERSION`。
2. Python 依赖版本。
3. npm 依赖版本。
4. 工具版本和 SHA-256。
5. Docker 基础镜像。
6. 数据库迁移。
7. 测试和验收结果。
8. 已知限制。

升级任何扫描工具都要重跑适配器解析测试和至少一组真实靶场验收，因为固定版本升级可能改变 JSON 字段、严重度和默认扫描行为。

## 第五十五章 源码阅读路线与二次开发

### 55.1 第一遍：只读运行骨架

按以下顺序阅读：

1. `docker-compose.yml`：有哪些服务。
2. `docker-compose.full.yml`：OpenVAS 如何叠加。
3. `start.bat` / `start.sh`：服务如何启动和等待。
4. `backend/app/main.py`：API 如何装配。
5. `backend/app/config.py`：有哪些配置。

第一遍不需要理解每个扫描器，先回答“请求从哪里进来、任务从哪里执行、结果写到哪里”。

### 55.2 第二遍：任务主链

1. `schemas/task.py`：请求字段。
2. `api/tasks.py`：创建、取消、恢复。
3. `guard.py`：授权与 Scope。
4. `worker/tasks.py`：状态初始化、Celery、checkpoint 和结果持久化。
5. `graph/build.py`：节点注册、边、包装器和恢复。

读完后应该能画出：

```text
POST /api/tasks
  -> validate_task
  -> Task + AuditLog
  -> celery send_task
  -> _execute
  -> build_graph
  -> graph.invoke
  -> _persist_result
  -> report/evidence/snapshot
```

### 55.3 第三遍：节点与适配器

1. `graph/nodes.py`：19 个节点的业务条件。
2. `graph/state.py`：状态和 reducer。
3. `budget.py`：总预算和阶段预算。
4. `adapters/base.py`：子进程、取消和 Finding 过滤。
5. 各适配器：命令和解析器。

阅读每个节点时回答四个问题：

1. 前置条件是什么。
2. 调用哪个适配器。
3. 成功时写哪些 state 字段。
4. 失败或跳过时写哪个状态和 reason code。

### 55.4 第四遍：语义与交付

1. `schemas/finding.py`：指纹与证据哈希。
2. `dedup.py`：别名、去重、评分。
3. `risk_groups.py`：风险组。
4. `memory.py`：历史快照。
5. `ai_service.py`：AI 输入、校验和缓存。
6. `evidence.py`：证据文件。
7. `report.py` 和 `workflow_image.py`：报告和图形。

### 55.5 第五遍：前端

1. `api.js`：鉴权和错误处理。
2. `App.jsx`：路由。
3. `AppShell.jsx`：导航。
4. `Submit.jsx`：任务配置。
5. `TaskDetail.jsx`：轮询 + SSE。
6. `Report.jsx`：HTML/PNG/MMD。

### 55.6 新增扫描器步骤

1. 在 `backend/app/adapters/` 新建 `<tool>_adapter.py`。
2. 继承 `BaseAdapter`，声明 name 和 tool_version。
3. 实现 `run(target_or_input, options)`。
4. 用 `_run` 或受控 HTTP 调用执行工具。
5. 把输出转为 `Finding`。
6. 通过 `_filter_findings` 做范围过滤。
7. 在 `adapters/__init__.py` 导出。
8. 在 `capabilities.py` 增加版本探测。
9. 在 `nodes.py` 增加节点函数或并入现有节点。
10. 在 `build.py` 和 `budget.py` 注册节点与阶段。
11. 在前端 NodeGrid 和 i18n 增加显示。
12. 增加命令参数、解析器、超时和失败测试。

### 55.7 新增风险类型

1. 在 `config/vuln_alias.json` 增加别名。
2. 在 `backend/app/i18n.py` 增加中英文标签。
3. 在 `frontend/src/i18n.js` 增加前端标签。
4. 在 `risk_groups.py` 判断是否需要 detail key。
5. 在 `playbooks.py` 和 `report/playbooks/` 增加处置剧本。
6. 在 ground truth 和测试中加入该风险。

### 55.8 新增 API

1. 新建 `api/<name>.py`。
2. 定义 Pydantic 请求和响应模型。
3. 使用 `get_current_user`。
4. 写审计日志（如果有副作用）。
5. 在 `main.py` 注册 router。
6. 增加 TestClient 测试。
7. 在前端 api.js 或页面中调用。

### 55.9 新增前端页面

1. 在 `pages/` 新建组件。
2. 在 `App.jsx` 增加受保护路由。
3. 在 `AppShell.jsx` 增加导航。
4. 使用 `api()` 统一请求。
5. 如需实时状态，使用 EventSource 并在清理函数中关闭。
6. 增加空态、加载态、错误态和窄屏布局。
7. 执行 `npm run build` 并检查生产构建。

## 第五十六章 最终验收、真实性证据与替代人工验收清单

### 56.1 软件真实性验收入口

1. 提供项目源码目录和版本号。
2. 提供 `docker compose config` 成功输出。
3. 提供 frontend、backend、worker、postgres、redis、zap、oast healthy 状态。
4. 提供至少一个真实 task_id。
5. 提供该任务的 report.json、findings.json、report.html 和 workflow.png。
6. 提供至少一条 evidence 下载和哈希校验记录。
7. 提供工具 version/capabilities 输出。
8. 提供失败、跳过和恢复案例，而不是只提供成功案例。

### 56.2 功能验收

- [ ] 登录成功，未登录访问受保护页面跳转登录。
- [ ] 未勾选授权提交返回 403。
- [ ] 公开目标填写 `auth_ref=none` 可以创建任务。
- [ ] DVWA 使用 `local-dvwa` 可以执行认证扫描。
- [ ] Mock 触发 OpenAPI 分支。
- [ ] 6443 触发 K8s 路由，无 KUBECONFIG 时 skipped。
- [ ] 19 个节点状态都在 trace/数据库中有记录，任务页只展开实际执行工具。
- [ ] 取消任务后子进程停止，状态为 cancelled。
- [ ] failed/cancelled 任务可以恢复。
- [ ] 风险组可以展开。
- [ ] Finding 可以查看来源、URL、证据和哈希。
- [ ] 报告 JSON 和 HTML 都能打开。
- [ ] PNG 缺失时 MMD 可以在前端渲染。
- [ ] AI 关闭或失败时扫描主链路仍完成。
- [ ] OpenVAS full profile 下能显示能力状态。

### 56.3 安全验收

- [ ] 默认密码和 JWT Secret 已更换。
- [ ] 未授权 redirect 被拦截并记录 blocked_targets。
- [ ] 元数据地址被拒绝。
- [ ] 未授权私网解析被拒绝。
- [ ] AI Key 不以明文返回。
- [ ] 事件和错误中的 password/token/cookie 已脱敏。
- [ ] Worker 无宿主机端口映射。
- [ ] Worker 根文件系统只读、drop ALL。
- [ ] 报告 HTML 对工具文本做转义。
- [ ] 证据哈希不匹配时返回错误。

### 56.4 融合实验验收

- [ ] 实验方案在运行前冻结。
- [ ] Ground Truth 不由系统自身结果单独生成。
- [ ] 至少两人独立标注并记录一致性。
- [ ] 至少包含人工、单工具、多引擎和当前系统四个基线。
- [ ] 每组至少重复 3 次。
- [ ] 工具、模板、预算和目标状态固定。
- [ ] 保存原始输出、Finding、风险组、证据和 task_id。
- [ ] 报告 Recall、Precision、F1、FP Rate 和耗时。
- [ ] 报告置信区间和显著性检验。
- [ ] 保留失败结果。

### 56.5 替代人工验收

- [ ] 对每个工作项明确人工和系统分别完成什么。
- [ ] 测量人工基线总耗时和系统总耗时。
- [ ] 计入人工复核、纠错和签发时间。
- [ ] 测量每资产小时数、同等人力管理资产数和返工率。
- [ ] 对高危漏报单独统计，不以平均 Recall 掩盖。
- [ ] 进行至少 4 到 8 周影子运行或小规模试点。
- [ ] 有安全负责人签字确认可替代的具体环节。
- [ ] 不宣称替代授权责任、业务逻辑分析和最终签发。

### 56.6 有效性结论模板

最终文档应使用可审计的表述，例如：

> 在冻结的 DVWA 和 Mock 数据集上，系统完成了 3 次重复运行，所有 Finding 可追溯到工具和证据。与单 Nuclei 基线相比，多引擎组在 Recall 上有提升；与人工基线相比，报告整理时间下降。当前样本量不足以证明在所有真实资产上都优于人工，下一阶段将通过授权真实站点影子运行验证。

不应写成：

> 系统已经全面替代安全工程师。

前者有证据范围、指标和限制，后者没有可验证依据。

## 附录 A 真实任务工作流图

下图来自真实 DVWA 授权任务，展示信息收集、认证与路由、扫描引擎、汇总与报告四段式布局。

![真实任务工作流](assets/workflow-dark.png)

## 附录 B 状态与原因码

| 状态或原因 | 说明 |
|---|---|
| queued | 已入库，等待 Worker |
| running | 正在执行 |
| resuming | 从断点恢复 |
| completed | 正常完成 |
| partial | 部分完成 |
| failed | 节点异常 |
| cancelled | 已取消 |
| blocked | 授权或范围拒绝 |
| pending | 尚未进入 |
| skipped | 条件不满足或未选择 |
| reused completed checkpoint | 恢复时复用已完成节点 |
| canceled | 取消相关状态的历史拼写 |
| route_not_selected | 当前路由没有选择 |
| condition_not_met | 条件不满足 |
| deadline_exceeded | 预算耗尽 |
| tool_not_installed | 工具缺失 |
| form_authentication_not_configured | 未配置表单认证 |
| no_http_endpoints | 没有 HTTP 端点 |
| no_javascript_assets | 没有 JS 资源 |
| no_openapi_contract | 没有 OpenAPI |
| k8s_route_not_selected | 未发现 K8s 入口 |
| kubescape_requires_kubeconfig | 缺 Kubeconfig |
| validation_disabled | 验证关闭 |
| llm_disabled | AI 关闭 |
| llm_degraded | AI 失败降级 |
| service_unreachable | 外部服务不可达 |
| feed_not_synced | OpenVAS feed 同步中 |

## 附录 C 项目边界清单

使用与演示前逐项确认：

1. 目标所有权或授权文件已归档。
2. `.env` 默认密码已修改。
3. JWT_SECRET 已替换。
4. 只开放给可信网络。
5. 扫描器输出证据按组织要求保存。
6. OpenVAS 不在默认离线包中。
7. AI Key 不写入代码和公开仓库。
8. 业务逻辑漏洞需要人工验证。
9. 报告结论需要结合授权范围和人工复核。

## 附录 D 一次任务从请求到报告的完整调用链

```text
浏览器提交表单
  -> api.js fetch POST /api/tasks
  -> FastAPI get_current_user 验 JWT
  -> TaskCreate Pydantic 校验
  -> validate_task 检查授权、scope、CIDR、预算
  -> Task(status=queued) + AuditLog 入库
  -> celery_app.send_task("run_task", [task_id])
  -> Worker._execute
  -> load_memory_context
  -> write_capabilities
  -> PostgresSaver checkpoint
  -> build_graph
  -> graph.invoke(initial_state)
  -> auth_gate
  -> recon / dns_resolve / takeover_check / http_probe / port_scan
  -> credential_session_analysis
  -> router 计算 routes
  -> web_scan / nuclei_scan / js_secret_scan / api_fuzz / k8s_audit
  -> server_baseline / active_validation / host_vuln_scan
  -> merge_and_score
       -> normalize_vuln_type
       -> merge_findings
       -> calculate_confidence
       -> EvidenceStore.write
       -> build_risk_groups
       -> complete_memory_context
  -> llm_summarize（可选）
  -> report
       -> build_mermaid
       -> mermaidx 渲染 PNG
       -> Jinja2 生成 HTML
       -> 写 report.json / findings.json
  -> _persist_result
       -> Task 状态和结果
       -> AssetSnapshot
  -> 前端轮询 + SSE
  -> 任务页 / 报告页
```

## 附录 E 融合实验记录模板

每个实验批次至少填写以下字段：

| 字段 | 记录内容 |
|---|---|
| experiment_id | 实验唯一编号 |
| protocol_version | 实验方案版本和 hash |
| dataset_version | ground truth 版本和 hash |
| target_set | 目标列表和授权文件 |
| tool_versions | 所有工具、模板、feed 版本 |
| system_version | 项目版本和镜像摘要 |
| group | 人工、单工具、多引擎、完整 Agent、融合算法 |
| repetition | 第几次重复 |
| task_ids | 本批次任务 ID |
| start/end | 开始和结束时间 |
| budget | 总预算、阶段预算、max_rps |
| raw_output_refs | 原始输出路径或对象存储地址 |
| finding_count | 原始和归一化 Finding 数 |
| risk_group_count | 风险组数 |
| tp/fp/fn/tn | 混淆矩阵 |
| recall/precision/f1/fpr | 主要指标 |
| weighted_recall | 严重度加权召回 |
| jaccard | 与同组其他重复的稳定性 |
| human_minutes | 人工复核和报告时间 |
| review_notes | 复核意见和返工原因 |
| status | passed/failed/invalid |
| artifacts | 报告、证据、截图和日志路径 |

## 附录 F 结论与证据映射

| 想证明的结论 | 最低证据 | 当前状态 |
|---|---|---|
| 系统能够启动 | Compose health + 页面 + API | 已有 |
| 系统能执行扫描 | task_id + trace + 原始输出 | 已有 |
| 结果可以复核 | Finding + evidence hash + report | 已有 |
| 任务可以取消 | Redis 标记 + 进程终止 + 状态 | 已有 |
| 任务可以恢复 | checkpoint + resume task | 已有 |
| 多引擎覆盖更广 | 与单工具同条件对照 | 部分有，样本需扩大 |
| 融合减少重复 | 去重前后数量与人工时间 | 流程已有，实验待完善 |
| 融合降低误报 | 人工确认 FP 与基线对照 | 待验证 |
| 比人工更快 | 时间动作研究 | 待验证 |
| 达到人工检出水平 | 盲标注 ground truth + 统计检验 | 待验证 |
| 可以替代部分重复工作 | 影子运行 + 4 到 8 周试点 | 待验证 |
| 可以完全替代安全工程师 | 尚无系统能仅凭当前实验证明 | 不应宣称 |

