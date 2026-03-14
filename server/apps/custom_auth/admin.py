from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.http import HttpRequest, HttpResponse
from django.utils.translation import gettext_lazy as _

from apps.core.admin import DjangoQLAdminMixin
from apps.custom_auth.models import ServiceApiKey, User, UserApiKey


@admin.register(User)
class UserAdmin(DjangoQLAdminMixin, BaseUserAdmin):
    ordering = ["email"]
    list_display = ["email", "is_staff", "is_active", "date_joined"]
    search_fields = ["email"]
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("email", "password1", "password2")}),
    )
    filter_horizontal = ("groups", "user_permissions")
    list_filter = ("is_staff", "is_active", "groups")


@admin.register(UserApiKey)
class UserApiKeyAdmin(DjangoQLAdminMixin, admin.ModelAdmin[UserApiKey]):
    list_display = ["name", "user", "id", "is_active", "last_used", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["name", "id", "user__email"]
    readonly_fields = ["id", "token_hash", "last_used", "created_at", "updated_at"]
    fields = [
        "user",
        "name",
        "is_active",
        "id",
        "token_hash",
        "last_used",
        "created_at",
        "updated_at",
    ]
    actions = ["regenerate_token"]

    def save_model(
        self, request: HttpRequest, obj: UserApiKey, form: object, change: bool
    ) -> None:
        if not change:
            token = UserApiKey.generate_token()
            obj.set_token(token)
            request._user_key_token = token  # type: ignore[attr-defined]
        super().save_model(request, obj, form, change)

    def response_add(
        self,
        request: HttpRequest,
        obj: UserApiKey,
        post_url_continue: str | None = None,
    ) -> HttpResponse:
        token: str | None = getattr(request, "_user_key_token", None)
        if token:
            self.message_user(
                request,
                f"API key created. Copy this token now — it will not be shown again: "
                f"{obj.make_token_string(token)}",
                level=messages.WARNING,
            )
        return super().response_add(request, obj, post_url_continue)

    @admin.action(description="Regenerate token")
    def regenerate_token(self, request: HttpRequest, queryset: object) -> None:
        for key in queryset:  # type: ignore[union-attr]
            token = UserApiKey.generate_token()
            key.set_token(token)
            key.save(update_fields=["token_hash", "updated_at"])
            self.message_user(
                request,
                f"New token for {key} — copy now, will not be shown again: "
                f"{key.make_token_string(token)}",
                level=messages.WARNING,
            )


@admin.register(ServiceApiKey)
class ServiceApiKeyAdmin(DjangoQLAdminMixin, admin.ModelAdmin[ServiceApiKey]):
    list_display = ["name", "id", "is_active", "last_used", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["name", "id"]
    readonly_fields = ["id", "token_hash", "last_used", "created_at", "updated_at"]
    fields = [
        "name",
        "is_active",
        "id",
        "token_hash",
        "last_used",
        "created_at",
        "updated_at",
    ]
    actions = ["regenerate_token"]

    def save_model(
        self, request: HttpRequest, obj: ServiceApiKey, form: object, change: bool
    ) -> None:
        if not change:
            token = ServiceApiKey.generate_token()
            obj.set_token(token)
            request._service_key_token = token  # type: ignore[attr-defined]
        super().save_model(request, obj, form, change)

    def response_add(
        self,
        request: HttpRequest,
        obj: ServiceApiKey,
        post_url_continue: str | None = None,
    ) -> HttpResponse:
        token: str | None = getattr(request, "_service_key_token", None)
        if token:
            self.message_user(
                request,
                f"Service API key created. Copy this token now — it will not be shown again: "
                f"{obj.make_token_string(token)}",
                level=messages.WARNING,
            )
        return super().response_add(request, obj, post_url_continue)

    @admin.action(description="Regenerate token")
    def regenerate_token(self, request: HttpRequest, queryset: object) -> None:
        for key in queryset:  # type: ignore[union-attr]
            token = ServiceApiKey.generate_token()
            key.set_token(token)
            key.save(update_fields=["token_hash", "updated_at"])
            self.message_user(
                request,
                f"New token for {key} — copy now, will not be shown again: "
                f"{key.make_token_string(token)}",
                level=messages.WARNING,
            )
