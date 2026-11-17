FROM python:3.12.8-slim-bookworm AS python-runtime

FROM debian:bookworm-slim

ARG TARGETARCH=amd64
ARG NMAP_VERSION=7.93+dfsg1-1
ARG SUBFINDER_VERSION=2.17.0
ARG DNSX_VERSION=1.3.1
ARG HTTPX_VERSION=1.12.0
ARG NUCLEI_VERSION=3.11.1
ARG SUBJACK_VERSION=3.1.0
ARG GITLEAKS_VERSION=8.30.1
ARG KUBESCAPE_VERSION=4.0.16
ARG NIKTO_VERSION=2.6.1
ARG NUCLEI_TEMPLATES_VERSION=10.5.1
ARG GITHUB_MIRROR=https://ghfast.top/https://github.com
ARG GITHUB_OFFICIAL=https://github.com
ARG RAW_MIRROR=https://ghfast.top/https://raw.githubusercontent.com
ARG RAW_OFFICIAL=https://raw.githubusercontent.com
ARG SUBFINDER_SHA256=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
ARG DNSX_SHA256=438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533
ARG HTTPX_SHA256=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG SUBJACK_SHA256=632bd003cd97deb77f5ce5bd4a8d9fe5e08668eb5a2016ea6c01c45e7f472a2a
ARG SUBJACK_FINGERPRINTS_SHA256=e82c5caca61e1274953ec142f717de7e840093b588f6ffed30b373365f09619e
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG KUBESCAPE_SHA256=71ed716b13487a6fa57500af6b191ee7fd51eb0b31809ea5994a696b1f36f874
ARG NIKTO_SHA256=d1ca1acb05d81a5a6f374c0afdd76b33afa0089278631a20673c0210a71d992f
ARG NUCLEI_TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    TMPDIR=/tmp \
    NUCLEI_TEMPLATES_DIRECTORY=/opt/nuclei-templates

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        fonts-wqy-microhei \
        libpcap0.8 \
        libssl3 \
        perl \
        libio-socket-ssl-perl \
        libjson-perl \
        libnet-ssleay-perl \
        libxml-writer-perl \
        nmap=${NMAP_VERSION} \
        python3 \
        python3-pip \
        python3-venv \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH}"; \
    if [ "$arch" != "amd64" ]; then echo "this release currently supports linux/amd64 only: $arch"; exit 1; fi; \
    mkdir -p /opt/bin /tmp/subfinder; \
    path="projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/subfinder/tool.zip || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/subfinder/tool.zip; \
    echo "${SUBFINDER_SHA256}  /tmp/subfinder/tool.zip" | sha256sum -c -; \
    unzip -q /tmp/subfinder/tool.zip -d /tmp/subfinder; \
    install -m 0755 /tmp/subfinder/subfinder /opt/bin/subfinder

RUN set -eux; \
    arch="${TARGETARCH}"; \
    mkdir -p /opt/bin /tmp/dnsx; \
    path="projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${arch}.zip"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/dnsx/tool.zip || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/dnsx/tool.zip; \
    echo "${DNSX_SHA256}  /tmp/dnsx/tool.zip" | sha256sum -c -; \
    unzip -q /tmp/dnsx/tool.zip -d /tmp/dnsx; \
    install -m 0755 /tmp/dnsx/dnsx /opt/bin/dnsx

RUN set -eux; \
    arch="${TARGETARCH}"; \
    mkdir -p /opt/bin /tmp/httpx; \
    path="projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${arch}.zip"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/httpx/tool.zip || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/httpx/tool.zip; \
    echo "${HTTPX_SHA256}  /tmp/httpx/tool.zip" | sha256sum -c -; \
    unzip -q /tmp/httpx/tool.zip -d /tmp/httpx; \
    install -m 0755 /tmp/httpx/httpx /opt/bin/httpx

RUN set -eux; \
    arch="${TARGETARCH}"; \
    mkdir -p /opt/bin /tmp/nuclei; \
    path="projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/nuclei/tool.zip || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/nuclei/tool.zip; \
    echo "${NUCLEI_SHA256}  /tmp/nuclei/tool.zip" | sha256sum -c -; \
    unzip -q /tmp/nuclei/tool.zip -d /tmp/nuclei; \
    install -m 0755 /tmp/nuclei/nuclei /opt/bin/nuclei

RUN set -eux; \
    mkdir -p /opt/bin /opt/subjack; \
    path="haccer/subjack/releases/download/v${SUBJACK_VERSION}/subjack-linux-${TARGETARCH}"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /opt/bin/subjack || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /opt/bin/subjack; \
    echo "${SUBJACK_SHA256}  /opt/bin/subjack" | sha256sum -c -; \
    chmod 0755 /opt/bin/subjack; \
    raw_path="haccer/subjack/v${SUBJACK_VERSION}/subjack/fingerprints.json"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${RAW_MIRROR}/${raw_path}" -o /opt/subjack/fingerprints.json || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${RAW_OFFICIAL}/${raw_path}" -o /opt/subjack/fingerprints.json; \
    echo "${SUBJACK_FINGERPRINTS_SHA256}  /opt/subjack/fingerprints.json" | sha256sum -c -

RUN set -eux; \
    mkdir -p /tmp/gitleaks; \
    path="gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/gitleaks/tool.tar.gz || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/gitleaks/tool.tar.gz; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks/tool.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks/tool.tar.gz -C /opt/bin gitleaks; \
    chmod 0755 /opt/bin/gitleaks

RUN set -eux; \
    mkdir -p /tmp/kubescape; \
    path="kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_amd64.tar.gz"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/kubescape/tool.tar.gz || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/kubescape/tool.tar.gz; \
    echo "${KUBESCAPE_SHA256}  /tmp/kubescape/tool.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/kubescape/tool.tar.gz -C /opt/bin; \
    chmod 0755 /opt/bin/kubescape

RUN set -eux; \
    mkdir -p /tmp/nikto /opt/nikto; \
    path="sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/nikto/tool.tar.gz || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/nikto/tool.tar.gz; \
    echo "${NIKTO_SHA256}  /tmp/nikto/tool.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nikto/tool.tar.gz -C /opt/nikto --strip-components=1; \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto; \
    chmod 0755 /opt/nikto/program/nikto.pl

RUN set -eux; \
    mkdir -p /tmp/nuclei-templates /opt/nuclei-templates; \
    path="projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 600 -fsSL "${GITHUB_MIRROR}/${path}" -o /tmp/nuclei-templates/templates.tar.gz || \
      curl --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 600 -fsSL "${GITHUB_OFFICIAL}/${path}" -o /tmp/nuclei-templates/templates.tar.gz; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates/templates.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nuclei-templates/templates.tar.gz \
      -C /opt/nuclei-templates --strip-components=1; \
    test -d /opt/nuclei-templates/http

COPY --from=python-runtime /usr/local /usr/local

ENV PATH="/opt/bin:${PATH}"

WORKDIR /app
COPY requirements.txt ./requirements.txt
COPY worker/requirements.txt ./worker/requirements.txt
RUN pip install --no-cache-dir --upgrade pip==24.3.1 \
    && pip install --no-cache-dir -r worker/requirements.txt

# python-gvm and gvm-tools are GPL. They are installed only for the
# gvm-cli executable and are never imported into the scanner application.
COPY worker/gvm-requirements.txt ./worker/gvm-requirements.txt
RUN pip install --no-cache-dir -r worker/gvm-requirements.txt

RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home --home-dir /tmp scanner \
    && mkdir -p /output /tmp/.cache \
    && chown -R scanner:scanner /output /tmp

COPY app ./app
COPY worker ./worker

ENV PATH="/opt/bin:${PATH}"
USER scanner

CMD ["celery", "-A", "worker.tasks.celery_app", "worker", "--loglevel=INFO", "--concurrency=1"]
