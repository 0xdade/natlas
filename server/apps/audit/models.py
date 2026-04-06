from __future__ import annotations

import typing

import uuid6
from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditLog(models.Model):
    class EventType(models.TextChoices):
        # Authentication
        USER_LOGIN = "user.login", "User login"
        USER_LOGOUT = "user.logout", "User logout"
        USER_LOGIN_FAILED = "user.login_failed", "User login failed"
        USER_LOCKED_OUT = "user.locked_out", "User locked out"
        IP_LOCKED_OUT = "ip.locked_out", "IP locked out"
        # User management
        USER_CREATED = "user.created", "User created"
        USER_DISABLED = "user.disabled", "User disabled"
        USER_ENABLED = "user.enabled", "User enabled"

    class TargetType(models.TextChoices):
        USER = "user", "User"
        AGENT = "agent", "Agent"
        SCOPE_ITEM = "scope_item", "Scope Item"

    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    event_type = models.CharField(
        max_length=64, choices=EventType.choices, db_index=True
    )

    # Who did it. Null actor_user = system-initiated action.
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_actions",
    )
    actor_ip = models.GenericIPAddressField(null=True, blank=True)

    # What was acted on — denormalized so the log survives deletions/renames.
    # target_repr is a human-readable snapshot captured at event time.
    target_type = models.CharField(
        max_length=64, choices=TargetType.choices, blank=True, default=""
    )
    target_id = models.CharField(max_length=64, blank=True, default="")
    target_repr = models.CharField(max_length=255, blank=True, default="")

    # Per-event structured data (e.g. {"username": "bob"} for a failed login,
    # {"old": "10.0.0.0/8", "new": "10.0.1.0/8"} for a scope change).
    properties = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering: typing.ClassVar = ["-timestamp"]
        indexes: typing.ClassVar = [
            models.Index(fields=["actor_user", "-timestamp"]),
            models.Index(fields=["target_type", "target_id", "-timestamp"]),
        ]

    def __str__(self) -> str:
        actor = str(self.actor_user) if self.actor_user_id else "system"
        target = f" → {self.target_repr}" if self.target_repr else ""
        return (
            f"[{self.event_type}] {actor}{target} at {self.timestamp:%Y-%m-%d %H:%M:%S}"
        )
