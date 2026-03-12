from __future__ import annotations

import os

# Base URL of the natlas Django server, no trailing slash.
SERVER_ADDRESS: str = os.environ.get(
    "NATLAS_SERVER_ADDRESS", "http://localhost:8000"
).rstrip("/")

# Agent credentials in the form "<agent_id>:<token>".
AGENT_TOKEN: str = os.environ.get("NATLAS_AGENT_TOKEN", "")

# Seconds to wait between poll attempts when no work is available.
POLL_INTERVAL: float = float(os.environ.get("NATLAS_POLL_INTERVAL", "5"))

# When true, run masscan for port discovery before handing off to nmap.
# Defaults to false; nmap handles the full scan on its own.
USE_MASSCAN: bool = os.environ.get("NATLAS_USE_MASSCAN", "0") == "1"

DEBUG: bool = os.environ.get("NATLAS_DEBUG", "0") == "1"
