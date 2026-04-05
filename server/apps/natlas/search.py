from __future__ import annotations

from django.db.models import Exists, OuterRef, Q
from djangoql.schema import DateTimeField as DjangoQLDateTimeField
from djangoql.schema import DjangoQLSchema, IntField, RelationField, StrField
from netfields import InetAddressField

from apps.natlas.models.dns import DNSRecord
from apps.natlas.models.port import Port, Script
from apps.natlas.models.scan import ScanResult
from apps.natlas.models.scope import Tag
from apps.natlas.models.ssl_certificate import SSLCertificate


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


# ── Port fields (port.num, port.proto, port.svc, port.product, port.ver) ──────


class _PortNumField(_AbsoluteLookup, IntField):
    model = Port
    name = "num"

    def get_lookup_name(self) -> str:
        return "ports__port_number"


class _PortProtoField(_AbsoluteLookup, StrField):
    model = Port
    name = "proto"
    suggest_options = True

    def get_lookup_name(self) -> str:
        return "ports__protocol"

    def get_options(self, search: str) -> list[str]:
        return [p for p in ("tcp", "udp") if search.lower() in p]


class _PortSvcField(_AbsoluteLookup, StrField):
    model = Port
    name = "svc"

    def get_lookup_name(self) -> str:
        return "ports__service_name"


class _PortProductField(_AbsoluteLookup, StrField):
    model = Port
    name = "product"

    def get_lookup_name(self) -> str:
        return "ports__service_product"


class _PortVerField(_AbsoluteLookup, StrField):
    model = Port
    name = "ver"

    def get_lookup_name(self) -> str:
        return "ports__service_version"


# ── Script fields (script.name, script.content, script.matches) ───────────────


class _ScriptNameField(_AbsoluteLookup, StrField):
    model = Script
    name = "name"

    def get_lookup_name(self) -> str:
        return "ports__scripts__name"


class _ScriptContentField(_AbsoluteLookup, StrField):
    model = Script
    name = "content"

    def get_lookup_name(self) -> str:
        return "ports__scripts__output"


class _ScriptMatchesField(StrField):
    """
    Correlated EXISTS lookup that tests name and content on the *same* script row.

    Syntax:  script.matches = "http-title:Login"
               └ name part ┘  └ content part ┘

    The content part is matched case-insensitively (operator =, !=) or as a
    regex (operator ~, !~).  Either part may be omitted:
        script.matches = ":Apache"      → any script whose output contains "Apache"
        script.matches = "http-title:"  → any script named "http-title"
    """

    model = Script
    name = "matches"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        name_part, _, content_part = str(value).partition(":")

        script_filters: dict[str, object] = {"port__scan_result": OuterRef("pk")}
        if name_part:
            script_filters["name"] = name_part
        if content_part:
            if operator in ("~", "!~"):
                script_filters["output__iregex"] = content_part
            else:
                script_filters["output__icontains"] = content_part

        exists_q = Q(Exists(Script.objects.filter(**script_filters)))
        invert = operator in ("!=", "!~")
        return ~exists_q if invert else exists_q


# ── DNS fields (dns.name, dns.domain) ─────────────────────────────────────────


class _DNSNameField(StrField):
    """Exact/regex match on a DNS record name pointing at this host."""

    model = DNSRecord
    name = "name"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        op, invert = self.get_operator(operator)
        val = value if operator in ("~", "!~") else self.get_lookup_value(value)
        exists_q = Q(
            Exists(
                DNSRecord.objects.filter(
                    **{"resolved_ip": OuterRef("target"), f"name{op}": val}
                )
            )
        )
        return ~exists_q if invert else exists_q


class _DNSDomainField(StrField):
    """Match this host if any DNS record falls at or under the given domain.

    ``dns.domain = "example.com"`` matches ``example.com`` itself as well as
    any subdomain (``www.example.com``, ``mail.example.com``, …).  Uses the
    ``name_reversed`` generated column so the lookup hits the prefix index.
    """

    model = DNSRecord
    name = "domain"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        reversed_val = ".".join(reversed(str(value).split(".")))
        invert = operator in ("!=", "not in")
        exists_q = Q(
            Exists(
                DNSRecord.objects.filter(
                    resolved_ip=OuterRef("target"),
                    name_reversed__startswith=reversed_val,
                )
            )
        )
        return ~exists_q if invert else exists_q


# ── SSL fields (ssl.subject, ssl.issuer, ssl.sha1, ssl.san, ssl.expires) ──────


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


# ── Host-level fields ──────────────────────────────────────────────────────────


class TagField(StrField):
    model = ScanResult
    name = "tag"
    suggest_options = True

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        if operator in ("in", "not in"):
            combined = Q()
            for v in value:  # type: ignore[union-attr]
                combined |= Q(tags__contains=[v])
            return ~combined if operator == "not in" else combined
        invert = operator == "!="
        return ~Q(tags__contains=[value]) if invert else Q(tags__contains=[value])

    def get_options(self, search: str) -> list[str]:
        return list(
            Tag.objects.filter(name__icontains=search).values_list("name", flat=True)[
                :20
            ]
        )


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


# ── Schema ─────────────────────────────────────────────────────────────────────


class HostSearchSchema(DjangoQLSchema):
    def get_fields(self, model: type) -> list:
        if model == ScanResult:
            return [
                "target",
                "scanned_at",
                TagField(),
                AgentField(),
                SubnetField(),
                NmapField(),
                RelationField(ScanResult, "port", Port),
                RelationField(ScanResult, "dns", DNSRecord),
                RelationField(ScanResult, "script", Script),
                RelationField(ScanResult, "ssl", SSLCertificate),
            ]
        if model == Port:
            return [
                _PortNumField(),
                _PortProtoField(),
                _PortSvcField(),
                _PortProductField(),
                _PortVerField(),
            ]
        if model == DNSRecord:
            return [
                _DNSNameField(),
                _DNSDomainField(),
            ]
        if model == Script:
            return [
                _ScriptNameField(),
                _ScriptContentField(),
                _ScriptMatchesField(),
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
