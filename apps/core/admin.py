from djangoql.admin import DjangoQLSearchMixin
from djangoql.schema import DjangoQLSchema


class IndexedFieldsSchema(DjangoQLSchema):
    """Restrict DjangoQL to fields that have a database index.

    Prevents accidental full-table-scan queries on non-indexed columns.
    Relational fields (FK, M2M, O2O) are always included because they
    carry implicit FK indexes on their join columns.
    """

    def get_fields(self, model):  # type: ignore[override]
        result = []
        for name in super().get_fields(model):
            try:
                field = model._meta.get_field(name)
            except Exception:
                continue
            if (
                getattr(field, "is_relation", False)
                or getattr(field, "primary_key", False)
                or getattr(field, "unique", False)
                or getattr(field, "db_index", False)
            ):
                result.append(name)
        return result


class DjangoQLAdminMixin(DjangoQLSearchMixin):
    djangoql_schema = IndexedFieldsSchema
