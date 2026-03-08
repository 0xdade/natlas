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
