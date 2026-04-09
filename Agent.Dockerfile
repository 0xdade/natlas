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


FROM rust:slim AS rustscan-builder

ARG RUSTSCAN_VERSION=2.4.1

RUN cargo install rustscan --version ${RUSTSCAN_VERSION}


FROM debian:bookworm-slim AS masscan-builder

ARG MASSCAN_VERSION=1.3.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    git \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${MASSCAN_VERSION} \
    https://github.com/robertdavidgraham/masscan.git /build \
    && cd /build \
    && make -j$(nproc)


FROM python:3.13-slim AS base

# libpcap is required at runtime by both nmap and masscan;
# libssl3 and zlib1g are already present via Python's own linkage
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 libssl3 zlib1g libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nmap-builder /opt/nmap/bin/nmap /usr/local/bin/nmap
COPY --from=nmap-builder /opt/nmap/share/nmap /usr/local/share/nmap
COPY --from=rustscan-builder /usr/local/cargo/bin/rustscan /usr/local/bin/rustscan
COPY --from=masscan-builder /build/bin/masscan /usr/local/bin/masscan

COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock ./
COPY agent/pyproject.toml ./agent/
COPY protocol/ ./protocol/
RUN uv sync --frozen --no-dev --package natlas-agent \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap) \
    && uv run playwright install --with-deps chromium

COPY agent/ ./agent/
RUN cp ./agent/nse/*.nse /usr/local/share/nmap/scripts/ \
    && nmap --script-updatedb 2>&1 | tail -1

ARG GIT_COMMIT=dev
ENV GIT_COMMIT=$GIT_COMMIT

CMD ["python", "-m", "agent"]
