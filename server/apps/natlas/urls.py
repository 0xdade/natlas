from __future__ import annotations

from django.urls import URLPattern, path

from apps.natlas.web.auth import login_view, logout_view

app_name = "natlas_auth"

urlpatterns: list[URLPattern] = [
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
]
