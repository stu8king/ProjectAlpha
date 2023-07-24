from django.db import models


class MitreICSTactics(models.Model):
    id = models.AutoField(primary_key=True)
    tactic = models.TextField()
    description = models.TextField()

    class Meta:
        db_table = 'tblMitreICSTactics'
        managed = False
