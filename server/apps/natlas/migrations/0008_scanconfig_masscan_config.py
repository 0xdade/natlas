from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("natlas", "0007_agent_scan_config_notnull"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanconfig",
            name="masscan_config",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
