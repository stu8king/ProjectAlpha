# Generated by Django 4.2.2 on 2024-02-03 17:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0085_pha_safeguard'),
    ]

    operations = [
        migrations.AddField(
            model_name='scenariobuilder',
            name='cost_projection',
            field=models.TextField(null=True),
        ),
    ]