# Generated by Django 4.2.2 on 2024-01-29 18:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0079_worksheetactivity_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='raworksheetscenario',
            name='scenario_damage',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='raworksheet',
            name='StatusFlag',
            field=models.CharField(choices=[('Open', 'Open'), ('Closed', 'Closed'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Open', max_length=8),
        ),
    ]