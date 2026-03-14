from django.apps import AppConfig


class CustomAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.custom_auth"
    verbose_name = "Authentication"
