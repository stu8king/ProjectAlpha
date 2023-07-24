from django.db import models


class ThreatAssessment(models.Model):
    ThreatAssessmentID = models.IntegerField(primary_key=True)
    post_id = models.IntegerField()
    ThreatType = models.CharField(max_length=255)
    ThreatImpactDescription = models.CharField(max_length=255)
    ThreatImpactScore = models.IntegerField()
    ThreatLikelihoodDescription = models.CharField(max_length=255)
    ThreatLikelihoodScore = models.IntegerField()
    IndustryAttackHistory = models.CharField(max_length=255)
    HasAttackedYesNo = models.CharField(max_length=255)
    HasBusinessImpactYesNo = models.CharField(max_length=255)
    AttackExpectedYesNo = models.CharField(max_length=255)
    KnownExposureYesNo = models.CharField(max_length=255)
    Comments = models.CharField(max_length=255)
    OverallThreatRatingHML = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblThreatAssessment'
