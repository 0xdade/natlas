from datetime import datetime, timezone
from typing import Dict
import json


class ScanResult:
    def __init__(self, target_data, config):
        self.result = {
            "agent": {
                "id": config.agent_id if config.agent_id else "anonymous",
                "version": config.NATLAS_VERSION,
            },
            "host": {"ip": target_data["target"], "tags": target_data["tags"]},
            "plugins": {},
            "timing": {},
            "scan": {
                "id": target_data["scan_id"],
                "reason": target_data["scan_reason"],
            },
        }

    def __str__(self):
        return json.dumps(self.result, indent=2)

    def add_plugin(self, name: str, plugin_data: Dict):
        self.result["plugins"][name] = plugin_data

    def start_scan(self):
        self.result["timing"]["scan_start"] = datetime.now(timezone.utc).isoformat()

    def stop_scan(self):
        self.result["timing"]["scan_stop"] = datetime.now(timezone.utc).isoformat()
