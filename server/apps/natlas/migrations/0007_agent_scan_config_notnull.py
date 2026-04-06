from __future__ import annotations

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("natlas", "0006_seed_system_scan_config"),
    ]

    operations = [
        migrations.AlterField(
            model_name="agent",
            name="scan_config",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="agents",
                to="natlas.scanconfig",
            ),
        ),
    ]
