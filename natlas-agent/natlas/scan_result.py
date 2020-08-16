from datetime import datetime, timezone
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
            "timing": {
                "elapsed": None,
                "scan_start": None,
                "scan_stop": None,
                "timed_out": False,
            },
            "scan": {
                "id": target_data["scan_id"],
                "reason": target_data["scan_reason"],
            },
        }
        self.finished = False

    def __str__(self):
        self.result["timing"]["scan_start"] = self.result["timing"][
            "scan_start"
        ].isoformat()
        self.result["timing"]["scan_stop"] = self.result["timing"][
            "scan_stop"
        ].isoformat()
        return json.dumps(self.result, indent=2)

    def add_plugin(self, name: str, plugin_data: dict):
        self.result["plugins"][name] = plugin_data

    def get_plugin(self, name: str) -> dict:
        return self.result["plugins"].get(name, None)

    def start_scan(self):
        self.result["timing"]["scan_start"] = datetime.now(timezone.utc)

    def stop_scan(self):
        self.result["timing"]["scan_stop"] = datetime.now(timezone.utc)
        self.result["timing"]["elapsed"] = (
            self.result["timing"]["scan_stop"] - self.result["timing"]["scan_start"]
        ).seconds
        self.finished = True

    def time_out(self):
        self.result["timing"]["timed_out"] = True
        self.stop_scan()
