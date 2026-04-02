from __future__ import annotations

import json

from django import forms
from django.contrib import admin, messages
from django.http import HttpRequest, HttpResponse
from django.utils.html import format_html, mark_safe
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import JsonLexer

from apps.core.admin import DjangoQLAdminMixin
from apps.natlas.models import ScanCycle, ScanResult, ScopeItem, Tag
from apps.natlas.models.agent import Agent
from apps.natlas.models.dns import DNSRecord
from apps.natlas.models.ssl_certificate import SSLCertificate
from apps.natlas.models.task import ScanTask


class TagSelectWidget(forms.SelectMultiple):
    """SelectMultiple that Select2 upgrades to support inline tag creation."""

    class Media:
        css = {
            "screen": (
                "admin/css/vendor/select2/select2.css",
                "admin/css/autocomplete.css",
                "natlas/admin/css/tag_select.css",
            )
        }
        js = (
            "admin/js/jquery.init.js",
            "natlas/admin/js/select2_compat.js",
            "admin/js/vendor/select2/select2.full.js",
            "natlas/admin/js/tag_autocomplete.js",
        )

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]
        self.attrs["class"] = "tag-select"


class TagsFormField(forms.MultipleChoiceField):
    """
    Multi-select field for tags.

    Accepts both existing tag PKs (selected from the list) and new tag names
    (typed in via Select2 tags mode). New names are created with get_or_create
    when the form is saved.
    """

    widget = TagSelectWidget

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("required", False)
        kwargs.setdefault("choices", [])
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]

    def valid_value(self, value: object) -> bool:
        return True

    def clean(self, value: object) -> list[Tag]:
        if not value:
            return []
        tags: list[Tag] = []
        for v in value:  # type: ignore[union-attr]
            try:
                tags.append(Tag.objects.get(pk=int(v)))
            except (ValueError, Tag.DoesNotExist):
                tag, _ = Tag.objects.get_or_create(name=str(v).strip())
                tags.append(tag)
        return tags


class ScopeItemAdminForm(forms.ModelForm[ScopeItem]):
    tag_names = TagsFormField(label="Tags")

    class Meta:
        model = ScopeItem
        fields = ["target", "is_blocked"]

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[call-arg]
        self.fields["tag_names"].choices = [
            (t.pk, t.name) for t in Tag.objects.order_by("name")
        ]
        if self.instance.pk:
            self.initial["tag_names"] = list(
                self.instance.tags.values_list("pk", flat=True)
            )


@admin.register(Tag)
class TagAdmin(DjangoQLAdminMixin, admin.ModelAdmin[Tag]):
    list_display = ["name", "scope_item_count", "address_count", "created_at"]
    readonly_fields = ["address_count", "created_at", "updated_at"]
    search_fields = ["name"]

    @admin.display(description="Scope items")
    def scope_item_count(self, obj: Tag) -> int:
        return obj.scope_items.count()

    @admin.display(description="Addresses")
    def address_count(self, obj: Tag) -> int:
        return obj.address_count


@admin.register(DNSRecord)
class DNSRecordAdmin(DjangoQLAdminMixin, admin.ModelAdmin[DNSRecord]):
    list_display = [
        "name",
        "record_type",
        "value",
        "resolved_ip",
        "first_seen",
        "last_seen",
    ]
    list_filter = ["record_type"]
    search_fields = ["name", "value", "resolved_ip"]
    readonly_fields = ["name_reversed", "first_seen", "last_seen"]
    fields = [
        "name",
        "record_type",
        "value",
        "resolved_ip",
        "name_reversed",
        "first_seen",
        "last_seen",
    ]
    djangoql_extra_fields = ["name", "name_reversed"]


@admin.register(ScopeItem)
class ScopeItemAdmin(DjangoQLAdminMixin, admin.ModelAdmin[ScopeItem]):
    form = ScopeItemAdminForm
    list_display = ["target", "address_count", "is_blocked", "get_tags", "created_at"]
    readonly_fields = ["address_count", "created_at", "updated_at"]
    list_filter = ["is_blocked", "tags"]
    search_fields = ["target"]

    @admin.display(description="Addresses")
    def address_count(self, obj: ScopeItem) -> int:
        return obj.address_count

    @admin.display(description="Tags")
    def get_tags(self, obj: ScopeItem) -> str:
        return ", ".join(obj.tags.values_list("name", flat=True))

    def save_related(
        self,
        request: HttpRequest,
        form: ScopeItemAdminForm,  # type: ignore[override]
        formsets: object,
        change: bool,
    ) -> None:
        super().save_related(request, form, formsets, change)
        form.instance.tags.set(form.cleaned_data.get("tag_names", []))


@admin.register(ScanTask)
class ScanTaskAdmin(DjangoQLAdminMixin, admin.ModelAdmin[ScanTask]):
    list_display = [
        "target",
        "status",
        "scan_result",
        "agent",
        "claimed_at",
        "created_at",
    ]
    list_filter = ["status"]
    readonly_fields = [
        "target",
        "status",
        "agent",
        "claimed_at",
        "completed_at",
        "claim_count",
        "scan_result",
        "created_at",
        "updated_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(
        self, request: HttpRequest, obj: ScanTask | None = None
    ) -> bool:
        return False


@admin.register(Agent)
class AgentAdmin(DjangoQLAdminMixin, admin.ModelAdmin[Agent]):
    list_display = ["name", "id", "is_active", "last_used", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["name", "id"]
    readonly_fields = [
        "id",
        "token_hash",
        "created_at",
        "updated_at",
        "last_used",
    ]
    actions = ["regenerate_token"]

    def save_model(
        self, request: HttpRequest, obj: Agent, form: object, change: bool
    ) -> None:
        if not change:
            token = Agent.generate_token()
            obj.set_token(token)
            request._agent_token = token  # type: ignore[attr-defined]
        super().save_model(request, obj, form, change)

    def response_add(
        self, request: HttpRequest, obj: Agent, post_url_continue: str | None = None
    ) -> HttpResponse:
        token: str | None = getattr(request, "_agent_token", None)
        if token:
            self.message_user(
                request,
                f"Agent created. Copy this token now — it will not be shown again: "
                f"{obj.make_token_string(token)}",
                level=messages.WARNING,
            )
        return super().response_add(request, obj, post_url_continue)

    @admin.action(description="Regenerate token")
    def regenerate_token(self, request: HttpRequest, queryset: object) -> None:
        for agent in queryset:  # type: ignore[union-attr]
            token = Agent.generate_token()
            agent.set_token(token)
            agent.save(update_fields=["token_hash", "updated_at"])
            self.message_user(
                request,
                f"New token for {agent} — copy now, will not be shown again: "
                f"{agent.make_token_string(token)}",
                level=messages.WARNING,
            )


@admin.register(ScanCycle)
class ScanCycleAdmin(DjangoQLAdminMixin, admin.ModelAdmin[ScanCycle]):
    list_display = [
        "id",
        "status",
        "total_ips",
        "ips_queued",
        "progress",
        "created_at",
        "completed_at",
    ]
    list_filter = ["status"]
    readonly_fields = [
        "total_ips",
        "ips_queued",
        "scope_snapshot",
        "lcg_m",
        "lcg_a",
        "lcg_b",
        "lcg_current",
        "completed_at",
        "created_at",
        "updated_at",
    ]
    fields = [
        "status",
        "total_ips",
        "ips_queued",
        "completed_at",
        "scope_snapshot",
        "lcg_m",
        "lcg_a",
        "lcg_b",
        "lcg_current",
        "created_at",
        "updated_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.display(description="Progress")
    def progress(self, obj: ScanCycle) -> str:
        if not obj.total_ips:
            return "—"
        pct = obj.ips_queued / obj.total_ips * 100
        return f"{obj.ips_queued:,} / {obj.total_ips:,} ({pct:.1f}%)"


_JSON_FORMATTER = HtmlFormatter(
    style="friendly",
    noclasses=True,
    prestyles="overflow:auto;max-height:600px;padding:0.75rem;border-radius:4px;",
)


@admin.register(ScanResult)
class ScanDataAdmin(DjangoQLAdminMixin, admin.ModelAdmin):  # type: ignore[type-arg]
    """Shared read-only config for ScanResult and LatestScanResult."""

    list_display = ["id", "target", "agent", "scanned_at"]
    list_filter = ["agent"]
    search_fields = ["target", "id"]
    readonly_fields = [
        "id",
        "target",
        "agent",
        "scanned_at",
        "scan_start",
        "scan_stop",
        "port_count",
        "is_up",
        "raw_data_pretty",
    ]
    fieldsets = [
        ("Scan", {"fields": ["id", "target", "agent"]}),
        ("Timestamps", {"fields": ["scanned_at", "scan_start", "scan_stop"]}),
        ("Results", {"fields": ["port_count", "is_up"]}),
        (
            "Raw Data",
            {"fields": ["raw_data_pretty", "raw_nmap"], "classes": ["collapse"]},
        ),
    ]

    @admin.display(description="Raw data")
    def raw_data_pretty(self, obj: ScanResult) -> str:
        pretty = json.dumps(obj.raw_data, indent=2, default=str)
        highlighted = mark_safe(highlight(pretty, JsonLexer(), _JSON_FORMATTER))
        return format_html("{}", highlighted)

    @admin.display(description="Port count", boolean=False)
    def port_count(self, obj: ScanResult) -> int:
        return obj.port_count

    @admin.display(description="Is up", boolean=True)
    def is_up(self, obj: ScanResult) -> bool:
        return obj.is_up

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False


class ScanResultAdmin(ScanDataAdmin):
    fieldsets = [
        ("Scan", {"fields": ["id", "target", "agent"]}),
        ("Timestamps", {"fields": ["scanned_at", "scan_start", "scan_stop"]}),
        ("Results", {"fields": ["port_count", "is_up", "raw_nmap"]}),
        ("Raw Data", {"fields": ["raw_data_pretty"], "classes": ["collapse"]}),
    ]
    readonly_fields = [*ScanDataAdmin.readonly_fields, "raw_nmap"]


@admin.register(SSLCertificate)
class SSLCertificateAdmin(DjangoQLAdminMixin, admin.ModelAdmin[SSLCertificate]):
    list_display = [
        "subject_cn",
        "issuer_cn",
        "not_valid_before",
        "not_valid_after",
        "is_expired",
        "public_key_type",
        "public_key_bits",
        "fingerprint_sha1",
        "first_seen",
        "last_seen",
    ]
    search_fields = ["subject_cn", "issuer_cn", "fingerprint_sha1", "subject_alt_names"]
    list_filter = ["public_key_type"]
    readonly_fields = [
        "fingerprint_sha1",
        "subject",
        "issuer",
        "subject_alt_names",
        "pem",
        "first_seen",
        "last_seen",
        "is_expired",
    ]
    fieldsets = [
        (
            "Certificate",
            {
                "fields": [
                    "fingerprint_sha1",
                    "subject_cn",
                    "subject",
                    "issuer_cn",
                    "issuer",
                    "subject_alt_names",
                ]
            },
        ),
        (
            "Validity",
            {"fields": ["not_valid_before", "not_valid_after", "is_expired"]},
        ),
        (
            "Public Key",
            {"fields": ["public_key_type", "public_key_bits"]},
        ),
        (
            "Raw",
            {"fields": ["pem"], "classes": ["collapse"]},
        ),
        (
            "Observations",
            {"fields": ["ports", "first_seen", "last_seen"]},
        ),
    ]

    @admin.display(description="Expired", boolean=True)
    def is_expired(self, obj: SSLCertificate) -> bool:
        return obj.is_expired

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
