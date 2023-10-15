# Generated by Django 4.2.2 on 2023-10-07 19:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0014_cyberphascenario_snapshot_id_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CyberPHAScenario_snapshot',
            fields=[
                ('ID', models.AutoField(primary_key=True)),
                ('CyberPHA', models.IntegerField()),
                ('ScenarioID', models.IntegerField()),
                ('Scenario', models.CharField(max_length=255)),
                ('ThreatClass', models.CharField(max_length=100)),
                ('ThreatAgent', models.CharField(max_length=100)),
                ('ThreatAction', models.CharField(max_length=100)),
                ('Countermeasures', models.CharField(max_length=500)),
                ('RiskCategory', models.CharField(max_length=100)),
                ('Consequence', models.CharField(max_length=1000)),
                ('impactSafety', models.IntegerField()),
                ('impactDanger', models.IntegerField()),
                ('impactProduction', models.IntegerField()),
                ('impactFinance', models.IntegerField()),
                ('impactReputation', models.IntegerField()),
                ('impactEnvironment', models.IntegerField()),
                ('impactRegulation', models.IntegerField()),
                ('impactData', models.IntegerField()),
                ('impactSupply', models.IntegerField()),
                ('UEL', models.IntegerField()),
                ('uel_threat', models.IntegerField()),
                ('uel_vuln', models.IntegerField()),
                ('uel_exposure', models.IntegerField()),
                ('RRU', models.IntegerField()),
                ('SM', models.IntegerField()),
                ('MEL', models.IntegerField()),
                ('RRM', models.IntegerField()),
                ('SA', models.IntegerField()),
                ('MELA', models.IntegerField()),
                ('RRa', models.TextField()),
                ('sl', models.IntegerField()),
                ('recommendations', models.CharField(max_length=1000)),
                ('Deleted', models.IntegerField()),
                ('timestamp', models.DateTimeField()),
                ('aro', models.IntegerField()),
                ('sle', models.IntegerField()),
                ('ale', models.IntegerField()),
                ('countermeasureCosts', models.IntegerField()),
                ('control_recommendations', models.TextField()),
                ('justifySafety', models.TextField()),
                ('justifyLife', models.TextField()),
                ('justifyProduction', models.TextField()),
                ('justifyFinancial', models.TextField()),
                ('justifyReputation', models.TextField()),
                ('justifyEnvironment', models.TextField()),
                ('justifyRegulation', models.TextField()),
                ('justifyData', models.TextField()),
                ('justifySupply', models.TextField()),
                ('userID', models.IntegerField()),
                ('organizationID', models.IntegerField()),
                ('standards', models.TextField()),
                ('outage', models.TextField()),
                ('outageDuration', models.IntegerField()),
                ('outageCost', models.IntegerField()),
                ('probability', models.TextField()),
                ('sle_low', models.IntegerField()),
                ('sle_high', models.IntegerField()),
                ('risk_register', models.BooleanField(default=False)),
                ('safety_hazard', models.TextField()),
                ('sis_outage', models.BooleanField(default=False)),
                ('sis_compromise', models.BooleanField(default=False)),
                ('risk_owner', models.TextField()),
                ('risk_priority', models.CharField(max_length=50, choices=[
                    ('Low', 'Low'),
                    ('Medium', 'Medium'),
                    ('High', 'High'),
                    ('Critical', 'Critical'),
                ])),
                ('risk_response', models.CharField(max_length=50, choices=[
                    ('Manage', 'Manage'),
                    ('Mitigate', 'Mitigate'),
                    ('Transfer', 'Transfer'),
                    ('Accept', 'Accept')
                ])),
                ('risk_status', models.CharField(max_length=50, choices=[
                    ('Open', 'Open'),
                    ('Closed', 'Closed')
                ])),
                ('risk_open_date', models.DateField()),
                ('risk_close_date', models.DateField()),
                ('snapshot_date', models.DateField()),
            ],
        ),
    ]