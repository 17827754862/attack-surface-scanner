# 第三方组件与许可证

本文件用于工程审核，不替代各项目完整许可证文本。

## 外部扫描工具

| 工具 | 固定版本 | 调用方式 | 许可证 |
|---|---:|---|---|
| Subfinder | 2.17.0 | Worker 子进程 | MIT |
| dnsx | 1.3.1 | Worker 子进程 | MIT |
| httpx | 1.12.0 | Worker 子进程 | MIT |
| Nuclei | 3.11.1 | Worker 子进程 | MIT |
| Subjack | 3.1.0 | Worker 子进程 | MIT |
| Gitleaks | 8.30.1 | Worker 子进程 | MIT |
| Kubescape | 4.0.16 | Worker 子进程 | Apache-2.0 |
| Nmap | 7.93+dfsg1-1 | Worker 子进程 | Nmap Public Source License |
| Nikto | 2.6.1 | Worker 子进程 | GPL-2.0 |
| Wapiti | 3.3.2 | Worker 子进程 | GPL-2.0 |
| OWASP ZAP | 2.17.0 | 独立容器 REST API | Apache-2.0 |
| OpenVAS/GVM Community Image | 26.07.27.01 | 独立容器 GMP | AGPL-3.0 及组件各自许可证 |

GPL/AGPL 工具不复制源码到本项目。Nikto、Wapiti 和 `gvm-cli` 只通过子进程执行；
OpenVAS 只通过隔离容器的 GMP 网络接口使用。扫描应用代码不 import `gvm`，
不链接 AGPL 代码。

## 基础设施

| 组件 | 版本 | 许可证说明 |
|---|---:|---|
| PostgreSQL | 16.6 | PostgreSQL License |
| Redis | 7.4.1 | RSALv2 / SSPLv1 双许可 |
| Nginx | 1.27.3 | BSD-2-Clause |
| Node.js | 22.12.0 | MIT 及依赖各自许可证 |
| Docker 镜像基础系统 | 固定标签 | Debian 各组件许可证 |
| WenQuanYi Micro Hei | Debian `fonts-wqy-microhei` | Apache-2.0；仅用于工作流 PNG 中文字体渲染 |

## Python 与前端依赖

版本锁定在以下文件：

- `backend/requirements.txt`
- `backend/worker/requirements.txt`
- `frontend/package.json`

主要包括：

| 依赖 | 许可证 |
|---|---|
| FastAPI、Pydantic、pydantic-settings、SQLAlchemy、PyJWT、Redis Python、LangGraph、LangGraph Postgres Checkpoint、mermaidx、pytest | MIT |
| Uvicorn、Celery、Jinja2、httpx | BSD-3-Clause |
| bcrypt、python-multipart | Apache-2.0 |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| PyYAML | MIT |
| psycopg | LGPL-3.0 |
| zaproxy Python client | Apache-2.0 |
| Schemathesis | MIT |
| python-gvm、gvm-tools | GPL-3.0-or-later，仅执行 `gvm-cli` 子进程 |
| Wapiti3 | GPL-2.0，仅执行 `wapiti` 子进程 |
| React、React DOM、React Router、Mermaid、Vite、Tailwind CSS、PostCSS、Autoprefixer、Vite React Plugin | MIT |

每个包的完整许可证文本以其发行包和上游仓库为准。

## 实验室镜像

- `vulnerables/web-dvwa`：仅通过 `dvwa` profile 启动，禁止用于生产环境。
- `immauss/openvas`：仅通过 `full` profile 启动，镜像包含 Greenbone 组件，许可证以其上游项目为准。

## AGPL 边界

项目源代码和默认离线包不包含 AGPL 代码。可选的 OpenVAS profile 通过容器边界调用
AGPL/GPL 服务，默认不构建、不启动，也不进入默认离线包。需要商业分发时仍应进行独立法律审查。
