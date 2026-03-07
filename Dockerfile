FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY manage.py ./
COPY config/ ./config/
COPY apps/ ./apps/
COPY static/ ./static/

EXPOSE 8000

ARG GIT_COMMIT=dev
ENV GIT_COMMIT=$GIT_COMMIT

CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "2"]


FROM base AS dev

RUN uv sync --frozen
