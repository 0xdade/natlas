from __future__ import annotations

from django.conf import settings
from django.core.cache import cache

from apps.audit.log import EventType, log_event

# Cache key templates — namespaced to avoid collisions with other cache users.
_FAILS_USER = "natlas:auth:fails:user:{}"
_FAILS_IP = "natlas:auth:fails:ip:{}"
_LOCKED_USER = "natlas:auth:locked:user:{}"
_LOCKED_IP = "natlas:auth:locked:ip:{}"


def _max_attempts() -> int:
    return int(getattr(settings, "AUTH_LOCKOUT_MAX_ATTEMPTS", 5))


def _window() -> int:
    return int(getattr(settings, "AUTH_LOCKOUT_WINDOW_SECONDS", 300))


def _duration() -> int:
    return int(getattr(settings, "AUTH_LOCKOUT_DURATION_SECONDS", 900))


def is_locked_out(username: str, ip: str | None) -> bool:
    """Return True if this username or source IP is currently locked out."""
    if cache.get(_LOCKED_USER.format(username)):
        return True
    if ip and cache.get(_LOCKED_IP.format(ip)):  # noqa: SIM103
        return True
    return False


def record_failure(username: str, ip: str | None) -> None:
    """Increment failure counters for the username and IP.

    Triggers a lockout (and writes an audit event) when either counter reaches
    the configured threshold.
    """
    max_attempts = _max_attempts()
    window = _window()
    duration = _duration()

    # Atomically increment the username counter, creating it if absent.
    user_key = _FAILS_USER.format(username)
    cache.add(user_key, 0, timeout=window)
    user_fails: int = cache.incr(user_key)

    if user_fails >= max_attempts and not cache.get(_LOCKED_USER.format(username)):
        cache.set(_LOCKED_USER.format(username), 1, timeout=duration)
        log_event(
            EventType.USER_LOCKED_OUT,
            properties={
                "username": username,
                "failed_attempts": user_fails,
                "window_seconds": window,
                "lockout_seconds": duration,
            },
        )

    if not ip:
        return

    ip_key = _FAILS_IP.format(ip)
    cache.add(ip_key, 0, timeout=window)
    ip_fails: int = cache.incr(ip_key)

    if ip_fails >= max_attempts and not cache.get(_LOCKED_IP.format(ip)):
        cache.set(_LOCKED_IP.format(ip), 1, timeout=duration)
        log_event(
            EventType.IP_LOCKED_OUT,
            properties={
                "ip": ip,
                "failed_attempts": ip_fails,
                "window_seconds": window,
                "lockout_seconds": duration,
            },
        )


def clear_failures(username: str) -> None:
    """Clear the failure counter for a username after a successful login."""
    cache.delete(_FAILS_USER.format(username))
