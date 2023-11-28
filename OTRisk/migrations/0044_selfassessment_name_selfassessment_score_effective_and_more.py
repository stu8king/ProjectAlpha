# Generated by Django 4.2.2 on 2023-11-14 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('OTRisk', '0043_alter_assessmentanswer_response'),
    ]

    operations = [
        migrations.AddField(
            model_name='selfassessment',
            name='name',
            field=models.CharField(max_length=20, null=True),
        ),
        migrations.AddField(
            model_name='selfassessment',
            name='score_effective',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='selfassessment',
            name='score_number',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='selfassessment',
            name='score_percent',
            field=models.IntegerField(default=0),
        ),
    ]