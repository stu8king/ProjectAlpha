# Generated by Django 4.2.2 on 2023-10-12 13:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0016_cyberphascenario_snapshot_control_effectiveness_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='complianceSummary',
            field=models.TextField(default=' '),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='cyberphascenario_snapshot',
            name='ID',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]
