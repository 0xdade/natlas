from __future__ import annotations

from django.db.models import Q
from djangoql.schema import DateTimeField as DjangoQLDateTimeField
from djangoql.schema import DjangoQLSchema, IntField, RelationField, StrField
from netfields import InetAddressField

from apps.natlas.models.scan import ScanResult
from apps.natlas.models.ssl_certificate import SSLCertificate


class PortNumberField(IntField):
    model = ScanResult
    name = "port"

    def get_lookup_name(self) -> str:
        return "ports__port_number"


class ProtocolField(StrField):
    model = ScanResult
    name = "protocol"
    suggest_options = True

    def get_lookup_name(self) -> str:
        return "ports__protocol"

    def get_options(self, search: str) -> list[str]:
        return [p for p in ("tcp", "udp") if search.lower() in p]


class ServiceField(StrField):
    model = ScanResult
    name = "service"

    def get_lookup_name(self) -> str:
        return "ports__service_name"


class ProductField(StrField):
    model = ScanResult
    name = "product"

    def get_lookup_name(self) -> str:
        return "ports__service_product"


class VersionField(StrField):
    model = ScanResult
    name = "version"

    def get_lookup_name(self) -> str:
        return "ports__service_version"


class ScriptField(StrField):
    model = ScanResult
    name = "script"

    def get_lookup_name(self) -> str:
        return "ports__scripts__name"


class NmapField(StrField):
    model = ScanResult
    name = "nmap"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        invert = operator in ("!=", "!~", "not in", "not startswith", "not endswith")
        q = Q(raw_nmap__search=value)
        return ~q if invert else q


class _AbsoluteLookup:
    """Mixin: use get_lookup_name() as an absolute ORM path, ignoring the
    DjangoQL relation-traversal prefix that is normally prepended to it."""

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        search = self.get_lookup_name()  # type: ignore[attr-defined]
        op, invert = self.get_operator(operator)  # type: ignore[attr-defined]
        val = value if operator in ("~", "!~") else self.get_lookup_value(value)  # type: ignore[attr-defined]
        q = Q(**{f"{search}{op}": val})
        return ~q if invert else q


class _SSLSubjectField(_AbsoluteLookup, StrField):
    model = SSLCertificate
    name = "subject"

    def get_lookup_name(self) -> str:
        return "ports__certificates__subject_cn"


class _SSLIssuerField(_AbsoluteLookup, StrField):
    model = SSLCertificate
    name = "issuer"

    def get_lookup_name(self) -> str:
        return "ports__certificates__issuer_cn"


class _SSLSha1Field(_AbsoluteLookup, StrField):
    model = SSLCertificate
    name = "sha1"

    def get_lookup_name(self) -> str:
        return "ports__certificates__fingerprint_sha1"


class _SSLSanField(StrField):
    """Exact element match against the subject_alt_names array."""

    model = SSLCertificate
    name = "san"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        invert = operator in ("!=", "not in")
        q = Q(ports__certificates__subject_alt_names__contains=[value])
        return ~q if invert else q


class _SSLExpiresField(_AbsoluteLookup, DjangoQLDateTimeField):
    model = SSLCertificate
    name = "expires"

    def get_lookup_name(self) -> str:
        return "ports__certificates__not_valid_after"


class AgentField(StrField):
    model = ScanResult
    name = "agent"

    def get_lookup_name(self) -> str:
        return "agent__id"


class SubnetField(StrField):
    """Match hosts whose IP falls within a CIDR, e.g. subnet = "10.0.0.0/8"."""

    model = ScanResult
    name = "subnet"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        invert = operator == "!="
        q = Q(target__net_contained_or_equal=value)
        return ~q if invert else q


class HostSearchSchema(DjangoQLSchema):
    def get_fields(self, model: type) -> list:
        if model == ScanResult:
            return [
                "target",
                "scanned_at",
                PortNumberField(),
                ProtocolField(),
                ServiceField(),
                ProductField(),
                VersionField(),
                ScriptField(),
                AgentField(),
                SubnetField(),
                NmapField(),
                RelationField(ScanResult, "ssl", SSLCertificate),
            ]
        if model == SSLCertificate:
            return [
                _SSLSubjectField(),
                _SSLIssuerField(),
                _SSLSha1Field(),
                _SSLSanField(),
                _SSLExpiresField(),
            ]
        return []

    def get_field_cls(self, field: object) -> type:
        if isinstance(field, InetAddressField):
            return StrField
        return super().get_field_cls(field)  # type: ignore[misc]
