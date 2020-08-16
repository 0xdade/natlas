import json
import os
from logging import Logger

from urllib.parse import urlparse

from natlas.fs.validators import is_valid_image
from natlas.fs.encoders import base64_file


def parse_url(url: str) -> tuple:
    urlp = urlparse(url)
    if not urlp.port:
        port = 80 if urlp.scheme == "http" else 443
    else:
        port = urlp.port

    return urlp.scheme.upper(), port


def parse_aquatone_page(page: dict, file_path: str) -> dict:
    if not (page["hasScreenshot"] and is_valid_image(file_path)):
        return {}
    scheme, port = parse_url(page["url"])
    return {
        "host": page["hostname"],
        "port": port,
        "service": scheme,
        "data": base64_file(file_path),
    }


def get_aquatone_session(base_dir: str) -> dict:
    session_path = os.path.join(base_dir, "aquatone_session.json")
    if not os.path.isfile(session_path):
        return {}

    with open(session_path) as f:
        session = json.load(f)

    if session["stats"]["screenshotSuccessful"] == 0:
        return {}
    return session


def parse_aquatone_session(base_dir: str, logger: Logger) -> list:
    session = get_aquatone_session(base_dir)
    if not session:
        return []

    output = []
    for _, page in session["pages"].items():
        fqScreenshotPath = os.path.join(base_dir, page["screenshotPath"])
        parsed_page = parse_aquatone_page(page, fqScreenshotPath)
        if not parsed_page:
            continue
        logger.info(
            f"{parsed_page['service']} screenshot acquired for {parsed_page['host']} on port {parsed_page['port']}"
        )
        output.append(parsed_page)

    return output
