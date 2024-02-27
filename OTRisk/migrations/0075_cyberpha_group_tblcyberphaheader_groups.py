# Generated by Django 4.2.2 on 2024-01-03 02:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0074_raworksheetscenario_raw_consequences'),
    ]

    operations = [
        migrations.CreateModel(
            name='CyberPHA_Group',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('group_type', models.CharField(choices=[('Industry', 'Industry'), ('Facility_type', 'Facility Type'), ('Country', 'Country'), ('Organization', 'Organization')], max_length=50)),
            ],
        ),
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='groups',
            field=models.ManyToManyField(blank=True, to='OTRisk.cyberpha_group'),
        ),
    ]