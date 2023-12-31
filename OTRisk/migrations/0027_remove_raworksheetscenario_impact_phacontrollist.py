# Generated by Django 4.2.2 on 2023-10-26 13:00

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0026_remove_raworksheetscenario_impact_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='raworksheetscenario',
            name='impact',
        ),
        migrations.CreateModel(
            name='PHAControlList',
            fields=[
                ('ID', models.AutoField(primary_key=True, serialize=False)),
                ('control', models.TextField()),
                ('reference', models.TextField()),
                ('score', models.IntegerField(validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('scenarioID', models.ForeignKey(db_column='scenarioID', on_delete=django.db.models.deletion.CASCADE, related_name='controls', to='OTRisk.tblcyberphascenario')),
            ],
            options={
                'verbose_name': 'PHA Control List',
                'verbose_name_plural': 'PHA Control Lists',
                'db_table': 'tblPHAControlList',
            },
        ),
    ]
