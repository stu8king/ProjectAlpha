# Generated by Django 4.2.2 on 2023-09-26 14:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblcyberphascenario',
            name='sle_high',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='tblcyberphascenario',
            name='sle_low',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]
