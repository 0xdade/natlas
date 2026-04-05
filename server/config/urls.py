from __future__ import annotations

from urllib.parse import urlencode

from apps.core.ninja_auth import SessionNotAuthenticated, WebSessionAuth
from apps.core.renderers import DjangoTemplateRenderer
from apps.natlas.web import router as natlas_router
from django.conf import settings
from django.contrib import admin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import URLPattern, URLResolver, include, path
from ninja import NinjaAPI

from config.api import api

web = NinjaAPI(
    title="Natlas Web App",
    renderer=DjangoTemplateRenderer(),
    urls_namespace="web",
    auth=WebSessionAuth(),
    openapi_url=None,
    docs_url=None,
)
web.add_router("", natlas_router)


@web.exception_handler(SessionNotAuthenticated)
def on_session_not_authenticated(
    request: HttpRequest, exc: SessionNotAuthenticated
) -> HttpResponse:
    login_url = settings.LOGIN_URL
    next_url = request.get_full_path()
    return redirect(f"{login_url}?{urlencode({'next': next_url})}")


urlpatterns: list[URLPattern | URLResolver] = [
    path("admin/", admin.site.urls),
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("auth/", include("apps.natlas.urls")),
    path("api/", api.urls),
    path("", web.urls),
]

if settings.DEBUG:
    import debug_toolbar

    urlpatterns += [path("__debug__/", include(debug_toolbar.urls))]
