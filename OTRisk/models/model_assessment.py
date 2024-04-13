from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario
from accounts.models import Organization


class AssessmentFramework(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    version = models.CharField(max_length=50)
    owner_organization = models.IntegerField()
    # Further fields to describe the framework


class AssessmentQuestion(models.Model):
    framework = models.ForeignKey(AssessmentFramework, on_delete=models.CASCADE)
    text = models.TextField()
    guidance = models.TextField(null=True, blank=True)
    section_reference = models.CharField(max_length=255)  # Field to reference the section of the framework
    category = models.TextField(null=True, blank=True)

    # Additional fields and methods as necessary


class AssessmentAnswer(models.Model):
    question = models.ForeignKey(AssessmentQuestion, on_delete=models.CASCADE)
    response = models.BooleanField(null=True)  # True for 'Yes', False for 'No'
    effectiveness = models.IntegerField(null=True,
                                        blank=True)  # Percentage of effectiveness, applicable if response is True
    weighting = models.IntegerField(default=1, validators=[MinValueValidator(1),
                                                           MaxValueValidator(10)])  # Weighting of the control
    remarks = models.CharField(null=True, blank=True, max_length=250)

    def save(self, *args, **kwargs):
        if not self.response:
            self.effectiveness = None  # Set effectiveness to None if response is 'No'
        super(AssessmentAnswer, self).save(*args, **kwargs)


class SelfAssessment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    framework = models.ForeignKey(AssessmentFramework, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    answers = models.ManyToManyField(AssessmentAnswer)
    name = models.CharField(max_length=20, null=True)
    score_number = models.IntegerField(default=0)
    score_percent = models.IntegerField(default=0)
    score_effective = models.IntegerField(default=0)

    # Relationships to other models in the application
    cyber_pha_header = models.ForeignKey(tblCyberPHAHeader, null=True, blank=True, on_delete=models.SET_NULL)
    cyber_pha_scenario = models.ManyToManyField(tblCyberPHAScenario, blank=True)
    organization = models.ForeignKey(Organization, null=True, blank=True, on_delete=models.SET_NULL)

    def add_answer(self, question, text):
        answer = AssessmentAnswer.objects.create(question=question, text=text)
        self.answers.add(answer)

    def get_answers(self):
        return self.answers.all()

    # Further methods to handle assessments
