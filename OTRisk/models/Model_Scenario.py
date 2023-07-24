from django.db import models


class tblConsequence(models.Model):
    Consequence = models.TextField()

    class Meta:
        db_table = 'tblConsequences'
        managed = False
