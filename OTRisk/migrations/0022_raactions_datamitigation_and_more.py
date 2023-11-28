# Generated by Django 4.2.2 on 2023-10-16 20:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0021_raworksheetscenario_impact'),
    ]

    operations = [
        migrations.AddField(
            model_name='raactions',
            name='dataMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='environmentMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='financeMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='lifeMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='productionMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='regulationMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='reputationMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='safetyMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='supplyMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='threatMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='raactions',
            name='vulnerabilityMitigation',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]