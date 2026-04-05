from __future__ import annotations

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("natlas", "0003_dnsrecord_name_reversed_alter_dnsrecord_name_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanresult",
            name="tags",
            field=django.contrib.postgres.fields.ArrayField(
                base_field=models.CharField(max_length=128),
                blank=True,
                default=list,
                size=None,
            ),
        ),
    ]
