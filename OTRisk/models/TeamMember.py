from django.db import models
from OTRisk.models.post import Post


class TeamMember(models.Model):
    FirstName = models.CharField(max_length=100)
    LastName = models.CharField(max_length=100)
    Title = models.CharField(max_length=100)
    Organization = models.CharField(max_length=100)
    Department = models.CharField(max_length=100)
    Notes = models.CharField(max_length=500)
    RiskID = models.IntegerField()

    class Meta:
        db_table = 'OTRisk_AssessmentTeam'

    def __str__(self):
        return f"{self.FirstName} {self.LastName}"

