# Generated by Django 4.2.2 on 2023-12-06 18:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0058_cyberphascenario_snapshot_exposed_system_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='raworksheetscenario',
            name='exposed_system',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='raworksheetscenario',
            name='weak_credentials',
            field=models.BooleanField(default=False),
        ),
    ]
