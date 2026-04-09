from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from collections.abc import Iterator

from playwright.sync_api import sync_playwright

from agent.context import ScanContext, ScreenshotResult
from agent.plugins import Plugin

log = logging.getLogger(__name__)


def _http_targets(xml: str) -> Iterator[tuple[int, str]]:
    """Yield (port, scheme) for open HTTP/HTTPS ports from nmap XML."""
    if not xml:
        return
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return
    for host in root.findall("host"):
        for port_elem in host.findall("ports/port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_num = int(port_elem.get("portid", "0"))
            svc = port_elem.find("service")
            if svc is None:
                continue
            name = svc.get("name", "")
            tunnel = svc.get("tunnel", "")
            if "http" not in name:
                continue
            scheme = "https" if (name == "https" or tunnel == "ssl") else "http"
            yield port_num, scheme


def _url(target: str, scheme: str, port: int) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{target}"
    return f"{scheme}://{target}:{port}"


class ScreenshotsPlugin(Plugin):
    name = "screenshots"
    depends_on = ["nmap"]

    def enabled(self) -> bool:
        return True

    def run(self, ctx: ScanContext) -> None:
        http_ports = list(_http_targets(ctx.nmap.xml))
        if not http_ports:
            log.info("No HTTP/HTTPS ports on %s — skipping screenshots", ctx.target)
            return

        # Screenshot the raw IP plus every A/AAAA hostname — each may serve
        # different content via virtual hosting.
        seen: set[str] = set()
        hosts: list[str] = []
        for h in [ctx.target] + [
            d.name for d in ctx.dns_names if d.record_type in ("A", "AAAA")
        ]:
            if h not in seen:
                seen.add(h)
                hosts.append(h)

        urls = [
            (port, scheme, _url(host, scheme, port))
            for port, scheme in http_ports
            for host in hosts
        ]

        cfg = ctx.screenshot_config

        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox"])
            try:
                for port, scheme, url in urls:
                    log.debug("Screenshotting %s", url)
                    try:
                        page = browser.new_page(ignore_https_errors=True)
                        try:
                            page.goto(
                                url,
                                timeout=cfg.timeout * 1000,
                                wait_until="domcontentloaded",
                            )
                            data = page.screenshot(full_page=cfg.full_page)
                        finally:
                            page.close()
                        ctx.screenshots.taken.append(
                            ScreenshotResult(
                                port=port, scheme=scheme, url=url, data=data
                            )
                        )
                        log.info("Screenshot taken for %s (%d bytes)", url, len(data))
                    except Exception:
                        log.warning("Screenshot failed for %s", url, exc_info=True)
            finally:
                browser.close()

        log.info(
            "%d/%d screenshot(s) taken for %s",
            len(ctx.screenshots.taken),
            len(urls),
            ctx.target,
        )
