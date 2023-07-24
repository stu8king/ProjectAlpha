from django.db import models


class tblWorkshopNarrative(models.Model):
    TopSection = models.CharField(max_length=255)  # or models.TextField() if the strings can be very long
    SubSection = models.TextField()
    WorkshopQuestion = models.TextField()
    ID = models.IntegerField(primary_key=True)
    QuestionNumber = models.IntegerField()

    class Meta:
        db_table = 'tblWorkshopNarrative'

class tblWorkshopInformation(models.Model):
    ID = models.AutoField(primary_key=True)
    WorkshopStartDate = models.TextField()
    WorkshopEndDate = models.TextField()
    WorkshopName = models.TextField()
    WorkshopObjectives = models.TextField()
    WorkshopStatus = models.TextField()
    OrganizationID = models.IntegerField()
    WorkshopType = models.TextField()

    class Meta:
        db_table = 'tblWorkshopInformation'