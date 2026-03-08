from django.http import HttpRequest, HttpResponse
from django.shortcuts import render as django_render
from ninja.renderers import BaseRenderer


class DjangoTemplateRenderer(BaseRenderer):
    """
    Django ninja provides a lot of niceties that we can use for more than just our API.
    Things like having query params and path params defined in function signatures, defining
    schemas for our form bodies, defining schemas for our return values.

    Unfortunately where it falls flat is that it only wants to render to json by default. The Natlas
    web app relies primarily on hypermedia rather than a REST API, so we need a way to take a schema of output
    and turn that into a call to django's template renderer, passing the schema data as context.
    """

    media_type = "text/html"
    charset = "utf-8"

    def render(
        self, request: HttpRequest, data: object, *, response_status: int
    ) -> HttpResponse:
        if not isinstance(data, dict) or "template_name" not in data:
            raise RuntimeError("This renderer requires data with a template_name key")
        return django_render(
            request, template_name=data.get("template_name"), context=data
        )
