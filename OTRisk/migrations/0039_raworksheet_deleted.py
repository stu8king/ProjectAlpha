# Generated by Django 4.2.2 on 2023-11-09 12:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0038_raworksheetscenario_impact'),
    ]

    operations = [
        migrations.AddField(
            model_name='raworksheet',
            name='deleted',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]