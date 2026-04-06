from __future__ import annotations

from django.contrib import admin
from django.http import HttpRequest

from apps.audit.models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "event_type",
        "actor_user",
        "actor_ip",
        "target_type",
        "target_repr",
    )
    list_filter = ("event_type", "target_type")
    search_fields = (
        "actor_user__username",
        "actor_ip",
        "target_repr",
        "target_id",
    )
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    readonly_fields = (
        "id",
        "timestamp",
        "event_type",
        "actor_user",
        "actor_ip",
        "target_type",
        "target_id",
        "target_repr",
        "properties",
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(
        self, request: HttpRequest, obj: AuditLog | None = None
    ) -> bool:
        return False

    def has_delete_permission(
        self, request: HttpRequest, obj: AuditLog | None = None
    ) -> bool:
        return False
