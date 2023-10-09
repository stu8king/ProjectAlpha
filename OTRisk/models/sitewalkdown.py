from django.db import models


class SiteWalkdown(models.Model):
    ID = models.AutoField(primary_key=True)
    WalkdownDate = models.CharField(max_length=10)
    OrganizationName = models.CharField(max_length=100)
    LocationAddress = models.CharField(max_length=255)
    LocationCountry = models.CharField(max_length=20)
    LocationType = models.CharField(max_length=20)
    PeopleOnSite = models.IntegerField()
    WalkdownLeader = models.CharField(max_length=100)
    OrgContact = models.CharField(max_length=100)
    WalkdownStartTime = models.CharField(max_length=10)
    WalkdownEndTime = models.CharField(max_length=10)
    DisallowedZones = models.CharField(max_length=255)
    SafetyBriefingGiven = models.CharField(max_length=3)

    class Meta:
        db_table = 'tblWalkdown'


class SiteWalkdownQuestionnaire(models.Model):
    ID = models.AutoField(primary_key=True)
    Category = models.CharField(max_length=100)
    WalkdownQuestion = models.CharField(max_length=255)
    WalkdownGuidance = models.CharField(max_length=255)
    QNumber = models.IntegerField()

    class Meta:
        db_table = 'tblWalkdownQuestions'


class WalkdownAnswers(models.Model):
    ID = models.AutoField(primary_key=True)
    WalkdownID = models.IntegerField()
    WalkdownQuestionID = models.IntegerField()
    CyberPHA_ID = models.IntegerField()
    UserResponse = models.TextField(max_length=3)
    Details = models.CharField(max_length=255)
    RANeeded = models.IntegerField()
    questiontext = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblWalkdownAnswers'
