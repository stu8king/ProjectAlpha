from django.db import models
from django.contrib.auth.models import User
from django.shortcuts import render


class FacilityType(models.Model):
    ID = models.AutoField(primary_key=True)
    FacilityType = models.CharField(max_length=50)
    Description = models.CharField(max_length=255)
    RiskWeighting = models.IntegerField()

    class Meta:
        db_table = 'tblFacilityTypes'

    def __str__(self):
        return self.FacilityType


class tblFacility(models.Model):
    ID = models.AutoField(primary_key=True)
    FacilityName = models.CharField(max_length=25)
    FacilityTypeID = models.ForeignKey(FacilityType, on_delete=models.CASCADE)

    class Meta:
        db_table = 'tblFacility'


class Questionnaire(models.Model):
    title = models.TextField()
    description = models.TextField()
    fkFacilityType = models.ForeignKey(FacilityType, on_delete=models.CASCADE, db_column='fkFacilityType_id')

    class Meta:
        db_table = 'tblQuestionnaire'

    def __str__(self):
        return self.title


class QuestionThemes(models.Model):
    id = models.AutoField(primary_key=True)
    QuestionTheme = models.TextField()
    fkQuestionnaireID = models.ForeignKey(Questionnaire, on_delete=models.CASCADE, db_column='fkQuestionnaireID')

    class Meta:
        db_table = 'tblQuestionThemes'


class Questions(models.Model):
    ID = models.IntegerField(primary_key=True)
    ThemeID = models.ForeignKey('QuestionThemes', on_delete=models.CASCADE, db_column='ThemeID')
    QuestionnaireID = models.ForeignKey(Questionnaire, on_delete=models.CASCADE, db_column='QuestionnaireID')
    questiontext = models.TextField()
    guidancenotes = models.TextField()
    questionnumber = models.IntegerField()

    class Meta:
        db_table = 'tblQuestions'


class QuestionResponses(models.Model):
    id = models.IntegerField(primary_key=True)
    QuestionID = models.ForeignKey(Questions, on_delete=models.CASCADE, db_column='QuestionID')
    UserResponse = models.TextField()
    UserNotes = models.TextField()
    fkQuestionnaireInstance = models.IntegerField()
    fkRiskAssessmentID = models.IntegerField()

    class Meta:
        db_table = 'tblQuestionResponses'


def walkthrough(request):
    query_results = Questionnaire.objects \
        .values('id', 'title', 'description', 'questiontheme__question_theme',
                'questiontheme__question__question_number', 'questiontheme__question__question_text') \
        .filter(questiontheme__isnull=False, questiontheme__question__isnull=False)

    return render(request, 'OTRisk/walkthrough.html', {'query_results': query_results})
