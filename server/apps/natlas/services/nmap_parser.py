from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class ParsedScript:
    name: str
    output: str


@dataclass
class ParsedPort:
    port_number: int
    protocol: str
    state: str
    service_name: str
    service_product: str
    service_version: str
    service_extra: str
    scripts: list[ParsedScript] = field(default_factory=list)


def parse_xml(raw_xml: str) -> list[ParsedPort]:
    """Parse nmap XML output into structured port/script data.

    Only open ports are returned. Returns an empty list on parse failure
    so a malformed or empty result never aborts a submission.
    """
    if not raw_xml:
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []

    ports: list[ParsedPort] = []

    for host in root.findall("host"):
        for port_elem in host.findall("ports/port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            svc = port_elem.find("service")
            parsed = ParsedPort(
                port_number=int(port_elem.get("portid", "0")),
                protocol=port_elem.get("protocol", "tcp"),
                state="open",
                service_name=svc.get("name", "") if svc is not None else "",
                service_product=svc.get("product", "") if svc is not None else "",
                service_version=svc.get("version", "") if svc is not None else "",
                service_extra=svc.get("extrainfo", "") if svc is not None else "",
            )

            for script_elem in port_elem.findall("script"):
                name = script_elem.get("id", "")
                output = script_elem.get("output", "")
                if name:
                    parsed.scripts.append(ParsedScript(name=name, output=output))

            ports.append(parsed)

    return ports
