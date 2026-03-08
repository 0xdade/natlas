FROM python:3.13-slim AS nmap-builder

ARG NMAP_VERSION=7.98

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libpcap-dev \
    libssl-dev \
    wget \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN wget -q https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 \
    && tar xjf nmap-${NMAP_VERSION}.tar.bz2 \
    && cd nmap-${NMAP_VERSION} \
    && ./configure --prefix=/opt/nmap \
    && make -j$(nproc) \
    && make install


FROM python:3.13-slim AS base

# libpcap is required at runtime; libssl3 and zlib1g are already present
# in python:3.13-slim via Python's own OpenSSL/zlib linkage
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nmap-builder /opt/nmap/bin/nmap /usr/local/bin/nmap
COPY --from=nmap-builder /opt/nmap/share/nmap /usr/local/share/nmap

COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY agent/pyproject.toml ./agent/
RUN uv sync --frozen --no-dev --package natlas-agent

COPY agent/ ./agent/

ARG GIT_COMMIT=dev
ENV GIT_COMMIT=$GIT_COMMIT

CMD ["python", "-m", "agent"]
