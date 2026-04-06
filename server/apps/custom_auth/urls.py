from __future__ import annotations

from django.urls import URLPattern, path

from apps.custom_auth.views import login_view, logout_view

app_name = "natlas_auth"

urlpatterns: list[URLPattern] = [
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
]
