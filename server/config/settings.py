import os
from pathlib import Path

import django_stubs_ext
import sentry_sdk

if _sentry_dsn := os.environ.get("SENTRY_DSN"):
    sentry_sdk.init(
        dsn=_sentry_dsn,
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "1.0")),
        send_default_pii=True,
    )

BASE_DIR: Path = Path(__file__).resolve().parent.parent


GIT_VERSION: str = os.environ.get("GIT_COMMIT", "unknown")

# SECURITY WARNING: set a strong secret key in production via DJANGO_SECRET_KEY
SECRET_KEY: str = os.environ.get(
    "DJANGO_SECRET_KEY",
    "insecure-dev-only-secret-key-replace-before-deploying",
)

DEBUG: bool = os.environ.get("DJANGO_DEBUG", "True") == "True"

ALLOWED_HOSTS: list[str] = [
    h
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h
]


_DJANGO_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.postgres",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

_THIRD_PARTY_APPS: list[str] = [
    "django_celery_beat",
    "django_cotton",
    "djangoql",
    "netfields",
    "waffle",
]

_FIRST_PARTY_APPS: list[str] = [
    "apps.core",
    "apps.instrumentation",
    "apps.auto_admin",
    "apps.custom_user",
    "apps.natlas",
]

INSTALLED_APPS: list[str] = _DJANGO_APPS + _THIRD_PARTY_APPS + _FIRST_PARTY_APPS

AUTH_USER_MODEL: str = "custom_user.User"

MIDDLEWARE: list[str] = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "waffle.middleware.WaffleMiddleware",
]

if DEBUG:
    INSTALLED_APPS.append("debug_toolbar")
    MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
    DEBUG_TOOLBAR_CONFIG: dict[str, object] = {
        "SHOW_TOOLBAR_CALLBACK": lambda _request: True,
    }

ROOT_URLCONF: str = "config.urls"

TEMPLATES: list[dict[str, object]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "OPTIONS": {
            "loaders": [
                (
                    "django.template.loaders.cached.Loader",
                    [
                        "django_cotton.cotton_loader.Loader",
                        "django.template.loaders.filesystem.Loader",
                        "django.template.loaders.app_directories.Loader",
                    ],
                )
            ],
            "builtins": ["django_cotton.templatetags.cotton"],
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.version",
            ],
        },
    },
]

WSGI_APPLICATION: str = "config.wsgi.application"


DATABASES: dict[str, dict[str, object]] = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "natlas"),
        "USER": os.environ.get("POSTGRES_USER", "natlas"),
        "PASSWORD": os.environ.get(
            "POSTGRES_PASSWORD", "natlas-dev-password-do-not-use"
        ),
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE: str = "en-us"
TIME_ZONE: str = "UTC"
USE_I18N: bool = True
USE_TZ: bool = True

STATIC_URL: str = "static/"
STATICFILES_DIRS: list[Path] = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD: str = "django.db.models.BigAutoField"

# Celery
CELERY_BROKER_URL: str = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND: str = os.environ.get(
    "CELERY_RESULT_BACKEND", "redis://localhost:6379/0"
)
CELERY_BEAT_SCHEDULER: str = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_BEAT_SCHEDULE: dict = {
    "tick-scan-cycle": {
        "task": "apps.natlas.tasks.tick_scan_cycle",
        "schedule": 30.0,  # seconds
    },
    "reap-stale-tasks": {
        "task": "apps.natlas.tasks.reap_stale_tasks",
        "schedule": 60.0,  # seconds
    },
}

if DEBUG:
    CELERY_BEAT_SCHEDULE["mock-agent-tick"] = {
        "task": "apps.natlas.tasks.mock_agent_tick",
        "schedule": 2.0,  # seconds
    }

# Scan cycle tuning
# Fraction of total scope to keep as pending ScanTasks. The tick refills
# the queue when pending drops below this threshold and gates new cycle
# creation until tasks have drained past it.
NATLAS_SCAN_FILL_RATIO: float = 0.5
# Hard ceiling on pending tasks regardless of scope size.
NATLAS_SCAN_MAX_PENDING: int = 1000
# Minutes before a claimed task with no update is considered abandoned.
NATLAS_SCAN_CLAIM_TIMEOUT_MINUTES: int = 15
# Maximum times a task is retried before being marked FAILED.
NATLAS_SCAN_MAX_CLAIM_ATTEMPTS: int = 3
# When True, consecutive cycles with the same scope size reuse the previous
# LCG step and continue from where the last cycle ended, producing a
# consistent repeating scan order and more predictable inter-scan intervals.
# When False (default), each cycle randomizes its step and starting position.
NATLAS_SCAN_CONSISTENT_ORDER: bool = False

# Email
# For local development the default backend points at the maildev SMTP container.
# In production, set EMAIL_BACKEND to an anymail backend, e.g.:
#   anymail.backends.mailgun.EmailBackend
#   anymail.backends.sendgrid.EmailBackend
EMAIL_BACKEND: str = os.environ.get(
    "EMAIL_BACKEND",
    "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST: str = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT: int = int(os.environ.get("EMAIL_PORT", "1025"))
EMAIL_HOST_USER: str = os.environ.get("EMAIL_HOST_USER", "natlas")
EMAIL_HOST_PASSWORD: str = os.environ.get(
    "EMAIL_HOST_PASSWORD", "natlas-dev-password-do-not-use"
)
EMAIL_USE_TLS: bool = os.environ.get("EMAIL_USE_TLS", "False") == "True"
DEFAULT_FROM_EMAIL: str = os.environ.get("DEFAULT_FROM_EMAIL", "noreply@natlas.test")

ANYMAIL: dict[str, str] = {
    "WEBHOOK_SECRET": os.environ.get("ANYMAIL_WEBHOOK_SECRET", ""),
}

# OpenTelemetry
OTEL_ENABLE: bool = os.environ.get("OTEL_ENABLE", "False") == "True"
OTEL_COLLECTOR: str = os.environ.get("OTEL_COLLECTOR", "localhost:4317")
OTEL_SERVICE_NAME: str = os.environ.get("OTEL_SERVICE_NAME", "natlas-django")


django_stubs_ext.monkeypatch()  # runtime typehint support for Django
