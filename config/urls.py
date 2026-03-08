from django.conf import settings
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path
from ninja import NinjaAPI

from apps.core.renderers import DjangoTemplateRenderer
from apps.natlas.web import router as natlas_router
from config.api import api

web = NinjaAPI(
    title="Natlas Web App",
    renderer=DjangoTemplateRenderer(),
    urls_namespace="web",
    openapi_url=None,
    docs_url=None,
)
web.add_router("", natlas_router)

urlpatterns: list[URLPattern | URLResolver] = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("", web.urls),
]

if settings.DEBUG:
    import debug_toolbar

    urlpatterns += [path("__debug__/", include(debug_toolbar.urls))]
