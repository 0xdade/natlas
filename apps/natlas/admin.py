from __future__ import annotations

from django import forms
from django.contrib import admin
from django.http import HttpRequest

from apps.core.admin import DjangoQLAdminMixin
from apps.natlas.models import LatestScanResult, ScanCycle, ScanResult, ScopeItem, Tag
from apps.natlas.models.agent import Agent
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
    list_display = ["friendly_name", "agent_id", "is_active", "last_seen", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["friendly_name", "agent_id"]
    readonly_fields = [
        "agent_id",
        "token_hash",
        "created_at",
        "updated_at",
        "last_seen",
    ]


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


class ScanDataAdmin(DjangoQLAdminMixin, admin.ModelAdmin):  # type: ignore[type-arg]
    """Shared read-only config for ScanResult and LatestScanResult."""

    list_display = ["scan_id", "target", "agent", "scanned_at"]
    list_filter = ["agent"]
    readonly_fields = ["scan_id", "target", "agent", "scanned_at", "raw_data"]
    fields = ["scan_id", "target", "agent", "scanned_at", "raw_data"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: object = None) -> bool:
        return False


@admin.register(ScanResult)
class ScanResultAdmin(ScanDataAdmin):
    pass


@admin.register(LatestScanResult)
class LatestScanResultAdmin(ScanDataAdmin):
    pass
