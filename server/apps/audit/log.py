from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.http import HttpRequest

from apps.audit.models import AuditLog

# Re-export for convenience so callers only need to import from here.
EventType = AuditLog.EventType
TargetType = AuditLog.TargetType

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


def get_client_ip(request: HttpRequest) -> str | None:
    """Return the client IP, using X-Forwarded-For when behind a proxy."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_event(  # noqa: PLR0913
    event_type: str,
    *,
    request: HttpRequest | None = None,
    actor_user: AbstractBaseUser | None = None,
    actor_ip: str | None = None,
    target_type: str = "",
    target_id: str = "",
    target_repr: str = "",
    properties: dict[str, Any] | None = None,
) -> None:
    """Record an audit event.

    Pass ``request`` to automatically populate ``actor_user`` and ``actor_ip``
    from the current session. Either can be overridden explicitly.

    Leave ``actor_user`` as None (and don't pass a request with an authenticated
    user) to record a system-initiated action.

    Use ``target_type`` / ``target_id`` / ``target_repr`` to identify the object
    the event acted on. ``target_repr`` should be a human-readable snapshot of
    the target's name/label at the time of the event so the log remains readable
    after the target is renamed or deleted.

    Example::

        log_event(
            EventType.USER_DISABLED,
            request=request,
            target_type=TargetType.USER,
            target_id=str(user.pk),
            target_repr=user.username,
        )
    """
    if request is not None:
        if (
            actor_user is None
            and hasattr(request, "user")
            and request.user.is_authenticated
        ):
            actor_user = request.user  # type: ignore[assignment]
        if actor_ip is None:
            actor_ip = get_client_ip(request)

    AuditLog.objects.create(
        event_type=event_type,
        actor_user=actor_user,
        actor_ip=actor_ip,
        target_type=target_type,
        target_id=target_id,
        target_repr=target_repr,
        properties=properties or {},
    )
