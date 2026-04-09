from __future__ import annotations

import django.db.models.deletion
import uuid6
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("natlas", "0008_scanconfig_masscan_config"),
    ]

    operations = [
        migrations.CreateModel(
            name="Screenshot",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid6.uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("port", models.IntegerField()),
                ("scheme", models.CharField(max_length=8)),
                ("url", models.CharField(max_length=2048)),
                ("s3_key", models.CharField(max_length=512)),
                ("taken_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan_result",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="screenshots",
                        to="natlas.scanresult",
                    ),
                ),
            ],
        ),
    ]
