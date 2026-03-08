from __future__ import annotations

from ninja import Schema


class TemplateSchema(Schema):
    """
    Base schema for views rendering Django templates.
    The `template_name` field is required and specifies the template to render.
    Additional fields can be added to the schema as needed,
    and will be passed as context to the template.

    Arbitrary types are allowed in TemplateSchemas because the consumer of a TemplateSchema is the django template
    and we don't generate docs for the web app.
    """

    template_name: str

    class Config:
        arbitrary_types_allowed = True
