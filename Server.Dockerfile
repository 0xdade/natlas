FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.10 /uv /usr/local/bin/uv

# Install the venv at /venv so a volume mount on /app can't shadow it
ENV VIRTUAL_ENV=/venv
ENV PATH="/venv/bin:$PATH"

# Install deps from a staging dir; only pyproject files are needed here
WORKDIR /workspace
COPY pyproject.toml uv.lock ./
COPY server/pyproject.toml ./server/
RUN UV_PROJECT_ENVIRONMENT=/venv uv sync --frozen --no-dev --package natlas-server

WORKDIR /app
COPY server/ ./

ARG GIT_COMMIT=dev
ENV GIT_COMMIT=$GIT_COMMIT

# Collect static files for production, disable DEBUG mode so that local builds don't break
RUN DJANGO_SECRET_KEY=collectstatic DJANGO_DEBUG=False python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "2"]


FROM base AS dev

WORKDIR /workspace
RUN UV_PROJECT_ENVIRONMENT=/venv uv sync --frozen --all-groups --all-packages
WORKDIR /app
