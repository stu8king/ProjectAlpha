# Generated by Django 4.2.2 on 2023-12-03 13:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0054_tblcyberphaheader_coho_tblcyberphaheader_npm'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblcyberphascenario',
            name='exposed_system',
            field=models.BooleanField(default=False),
        ),
    ]