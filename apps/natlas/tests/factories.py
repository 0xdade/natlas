from __future__ import annotations

import random

import factory
import factory.fuzzy
from django.contrib.auth.hashers import make_password
from django.utils.timezone import now

from apps.natlas.models.agent import Agent
from apps.natlas.models.port import Port, Script
from apps.natlas.models.scan import LatestScanResult, ScanResult

# Common service profiles: (port, protocol, service, product, version)
_COMMON_SERVICES: list[tuple[int, str, str, str, str]] = [
    (22, "tcp", "ssh", "OpenSSH", "8.9p1"),
    (80, "tcp", "http", "nginx", "1.24.0"),
    (443, "tcp", "https", "nginx", "1.24.0"),
    (3306, "tcp", "mysql", "MySQL", "8.0.35"),
    (5432, "tcp", "postgresql", "PostgreSQL", "15.4"),
    (6379, "tcp", "redis", "Redis", "7.2.3"),
    (8080, "tcp", "http", "Apache Tomcat", "10.1.16"),
    (8443, "tcp", "https", "Apache Tomcat", "10.1.16"),
    (9200, "tcp", "http", "Elasticsearch REST API", "8.11.0"),
    (27017, "tcp", "mongodb", "MongoDB", "7.0.4"),
    (21, "tcp", "ftp", "vsftpd", "3.0.5"),
    (25, "tcp", "smtp", "Postfix smtpd", "3.7.4"),
    (53, "udp", "domain", "ISC BIND", "9.18.19"),
    (110, "tcp", "pop3", "Dovecot pop3d", "2.3.21"),
    (143, "tcp", "imap", "Dovecot imapd", "2.3.21"),
    (2222, "tcp", "ssh", "OpenSSH", "9.4p1"),
    (3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", ""),
    (5900, "tcp", "vnc", "RealVNC", "6.11.0"),
    (8888, "tcp", "http", "Jupyter Notebook", "6.5.6"),
    (9090, "tcp", "http", "Prometheus", "2.47.2"),
]

# Scripts that may appear per service
_SCRIPTS_BY_SERVICE: dict[str, list[tuple[str, str]]] = {
    "ssh": [
        ("ssh-hostkey", "2048 SHA256:abc123 (RSA)\n  256 SHA256:def456 (ECDSA)"),
        ("ssh-auth-methods", "publickey,password"),
    ],
    "http": [
        ("http-title", "Site doesn't have a title (text/html)."),
        ("http-server-header", "nginx/1.24.0"),
    ],
    "https": [
        (
            "ssl-cert",
            "Subject: commonName=example.com\nNot valid after: 2025-12-31T00:00:00",
        ),
        ("http-title", "Welcome to nginx!"),
    ],
    "mysql": [
        (
            "mysql-info",
            "Protocol: 10\nVersion: 8.0.35\nCapabilities: LONg flag, CONNECT WITH DB",
        ),
    ],
    "redis": [
        ("redis-info", "version:7.2.3\nmode:standalone\nos:Linux"),
    ],
    "mongodb": [
        ("mongodb-info", "MongoDB server information\nBuild info: version: 7.0.4"),
    ],
}


def _make_nmap_output(target: str, ports: list[Port]) -> str:
    lines = [
        f"Nmap scan report for {target}",
        "Host is up (0.0012s latency).",
        "",
        "PORT      STATE SERVICE  VERSION",
    ]
    for port in ports:
        port_str = f"{port.port_number}/{port.protocol}"
        svc = f"{port.service_name:<12}" if port.service_name else " " * 12
        prod = f"{port.service_product} {port.service_version}".strip()
        lines.append(f"{port_str:<10} open  {svc} {prod}")
    lines += [
        "",
        "Service detection performed.",
        "Nmap done: 1 IP address (1 host up) scanned",
    ]
    return "\n".join(lines)


class AgentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Agent

    agent_id = factory.LazyFunction(Agent.generate_token)
    friendly_name = factory.Faker("hostname")
    is_active = True
    token_hash = factory.LazyFunction(lambda: make_password(Agent.generate_token()))


class ScanResultFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = ScanResult

    target = factory.Faker("ipv4_private")
    agent = factory.SubFactory(AgentFactory)
    scanned_at = factory.LazyFunction(now)
    raw_data = factory.LazyAttribute(
        lambda o: {"ip": str(o.target), "is_up": True, "mock": True}
    )
    raw_nmap = ""


class PortFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Port

    scan_result = factory.SubFactory(ScanResultFactory)
    port_number = factory.fuzzy.FuzzyChoice([s[0] for s in _COMMON_SERVICES])
    protocol = "tcp"
    state = "open"
    service_name = ""
    service_product = ""
    service_version = ""
    service_extra = ""


class ScriptFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Script

    port = factory.SubFactory(PortFactory)
    name = factory.Faker("word")
    output = factory.Faker("sentence")


class LatestScanResultFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LatestScanResult
        django_get_or_create = ("target",)

    target = factory.Faker("ipv4_private")
    agent = factory.SubFactory(AgentFactory)
    scanned_at = factory.LazyFunction(now)
    raw_data = factory.LazyAttribute(
        lambda o: {"ip": str(o.target), "is_up": True, "mock": True}
    )
    scan_result = factory.SubFactory(ScanResultFactory)


def build_realistic_scan(scan_result: ScanResult) -> list[Port]:
    """Create Port (and optional Script) rows for a realistic mock scan.

    Picks a random subset of common services, creates Port rows linked to
    scan_result, attaches scripts where applicable, and returns the ports.
    """
    chosen = random.sample(_COMMON_SERVICES, k=random.randint(1, 6))
    seen: set[tuple[int, str]] = set()
    ports: list[Port] = []

    for port_number, protocol, service, product, version in chosen:
        key = (port_number, protocol)
        if key in seen:
            continue
        seen.add(key)

        port = Port.objects.create(
            scan_result=scan_result,
            port_number=port_number,
            protocol=protocol,
            state="open",
            service_name=service,
            service_product=product,
            service_version=version,
        )
        ports.append(port)

        for script_name, script_output in _SCRIPTS_BY_SERVICE.get(service, []):
            if random.random() < 0.7:
                Script.objects.create(port=port, name=script_name, output=script_output)

    return ports


def generate_raw_nmap(target: str, ports: list[Port]) -> str:
    return _make_nmap_output(target, ports)
