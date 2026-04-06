from __future__ import annotations

from apps.natlas.models.scan_config import ScanConfig


def get_default_scan_config() -> ScanConfig:
    """Return the config to assign to a newly created agent.

    Prefers the user default if one has been configured; falls back to the
    immutable system default that is always present.
    """
    return ScanConfig.objects.filter(
        tier=ScanConfig.Tier.USER_DEFAULT
    ).first() or ScanConfig.objects.get(tier=ScanConfig.Tier.SYSTEM_DEFAULT)
