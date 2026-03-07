from __future__ import annotations

from django.urls import URLPattern, path

from apps.natlas import views

urlpatterns: list[URLPattern] = [
    path("hosts/", views.hosts, name="hosts"),
]
