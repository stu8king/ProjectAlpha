# Generated by Django 4.2.2 on 2024-02-11 19:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0087_cybersecurityinvestment'),
    ]

    operations = [
        migrations.AddField(
            model_name='scenariobuilder',
            name='investment_projection',
            field=models.TextField(null=True),
        ),
    ]
