# Generated by Django 4.2.2 on 2023-09-27 19:40

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0004_alter_tblcyberphascenario_cyberpha'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tblcyberphascenario',
            name='CyberPHA',
            field=models.ForeignKey(db_column='CyberPHA', on_delete=django.db.models.deletion.CASCADE, to='OTRisk.tblcyberphaheader'),
        ),
    ]
