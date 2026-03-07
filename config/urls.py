from django.conf import settings
from django.contrib import admin
from django.urls import URLPattern, URLResolver, include, path

from config.api import api

urlpatterns: list[URLPattern | URLResolver] = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("", include("apps.natlas.urls")),
]

if settings.DEBUG:
    import debug_toolbar

    urlpatterns += [path("__debug__/", include(debug_toolbar.urls))]
