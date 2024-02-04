# Generated by Django 4.2.2 on 2023-12-10 14:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0060_scenarioconsequences'),
    ]

    operations = [
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='insightSummary',
            field=models.TextField(default='No Summary Saved', null=True),
        ),
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='strategySummary',
            field=models.TextField(default='No Summary Saved', null=True),
        ),
        migrations.AddField(
            model_name='tblcyberphaheader',
            name='threatSummary',
            field=models.TextField(default='No Summary Saved', null=True),
        ),
    ]