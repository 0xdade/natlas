from __future__ import annotations

from django.db import migrations

SYSTEM_DEFAULT_PLUGINS = ["nmap"]

SYSTEM_DEFAULT_NMAP_CONFIG = {
    "ports": "top-100",
    "timing_template": 4,
    "max_rate": None,
    "scripts": [],
}


def seed_system_default(apps: object, schema_editor: object) -> None:
    ScanConfig = apps.get_model("natlas", "ScanConfig")  # type: ignore[attr-defined]
    Agent = apps.get_model("natlas", "Agent")  # type: ignore[attr-defined]

    config = ScanConfig.objects.create(
        name="System Default",
        description=(
            "Immutable system default configuration shipped with Natlas. "
            "Create a User Default to override it."
        ),
        tier="system_default",
        enabled_plugins=SYSTEM_DEFAULT_PLUGINS,
        nmap_config=SYSTEM_DEFAULT_NMAP_CONFIG,
    )

    # Assign all existing agents to the system default.
    Agent.objects.filter(scan_config__isnull=True).update(scan_config=config)


def unseed_system_default(apps: object, schema_editor: object) -> None:
    ScanConfig = apps.get_model("natlas", "ScanConfig")  # type: ignore[attr-defined]
    Agent = apps.get_model("natlas", "Agent")  # type: ignore[attr-defined]

    Agent.objects.update(scan_config=None)
    ScanConfig.objects.filter(tier="system_default").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("natlas", "0005_scanconfig_agent_scan_config"),
    ]

    operations = [
        migrations.RunPython(seed_system_default, reverse_code=unseed_system_default),
    ]
