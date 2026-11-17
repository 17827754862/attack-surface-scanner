# 攻击面扫描系统离线运行资源说明

## 文件关系

- `attack-surface-scanner-上传版.zip`：源码、文档、Dockerfile 和配置模板，用于上传 GitHub。
- `offline-bundle/images.tar`：已经构建好的 Docker 镜像，用于无外网环境直接加载。
- `attack-surface-scanner-离线运行资源.7z`：把源码包、离线镜像包和本说明放在一起发送给同学。

## 离线镜像里有什么

`offline-bundle/images.txt` 列出的镜像包括：

```text
attack-surface-scanner-backend
attack-surface-scanner-frontend
attack-surface-scanner-mock
attack-surface-scanner-oast
attack-surface-scanner-worker
ghcr.io/zaproxy/zaproxy:2.17.0
postgres:16.6-alpine
redis:7.4.1-alpine
vulnerables/web-dvwa
```

Worker 镜像已经包含：

- Subfinder
- dnsx
- httpx
- Nmap
- Nuclei 与固定模板
- Subjack
- Gitleaks
- Kubescape
- Nikto
- Wapiti
- Schemathesis
- ZAP Python 客户端
- `gvm-cli`

ZAP 是单独容器，OpenVAS 不在默认离线镜像中。

## 同学本地运行步骤

1. 安装 Docker Desktop，确认 Docker Compose v2 可用。
2. 解压 `attack-surface-scanner-上传版.zip`。
3. 把 `offline-bundle` 文件夹放到解压后的项目根目录，确保路径是 `attack-surface-scanner/offline-bundle`。
4. 打开 PowerShell，进入项目根目录。
5. 执行：

```powershell
.\scripts\load_offline_bundle.ps1 -BundleDir offline-bundle
```

6. 等待镜像加载和容器启动。
7. 浏览器打开：

```text
http://127.0.0.1:3000
```

8. 使用 `.env` 中的 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 登录。

## OpenVAS

离线包默认不包含 OpenVAS。需要 OpenVAS 时：

- 使用单独批准的内网镜像；
- 通过 `docker-compose.full.yml` 启动 `full` profile；
- 首次启动仍需确认 feed 状态；
- 不要把 OpenVAS 镜像塞进 GitHub 仓库。

## 工具没有丢失

GitHub 源码包中的工具安装逻辑位于 `backend/worker/Dockerfile`。Worker 构建时会从固定版本地址下载工具、校验 SHA-256 并安装到 `/opt/bin`。离线镜像包则已经把这些二进制固化在 Worker 镜像中。
