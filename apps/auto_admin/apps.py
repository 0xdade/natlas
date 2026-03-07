from django.apps import AppConfig, apps
from django.contrib import admin

from apps.core.admin import DjangoQLAdminMixin


class AutoAdminConfig(AppConfig):
    name = "apps.auto_admin"

    def ready(self) -> None:
        admin.site.site_header = "Natlas Administration"
        admin.site.site_title = "Natlas Administration"
        admin.site.index_title = "Natlas Administration"

        class ReadOnlyAdmin(DjangoQLAdminMixin, admin.ModelAdmin):
            def has_add_permission(self, request: object) -> bool:
                return False

            def has_change_permission(
                self, request: object, obj: object = None
            ) -> bool:
                return False

            def has_delete_permission(
                self, request: object, obj: object = None
            ) -> bool:
                return False

        for model in apps.get_models():
            if not admin.site.is_registered(model):
                admin.site.register(model, ReadOnlyAdmin)
