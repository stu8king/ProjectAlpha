from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.urls import reverse


class AssessmentTeam(models.Model):
    FirstName = models.TextField()
    LastName = models.TextField()
    Title = models.TextField()
    Organization = models.TextField()
    Department = models.TextField()
    Notes = models.TextField()
    RiskID = models.ForeignKey('Post', on_delete=models.CASCADE, db_column='RiskID')


class PublishedManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset() \
            .filter(submit_status=Post.SubmitStatus.PUBLISHED)


class Post(models.Model):
    class SubmitStatus(models.TextChoices):
        STARTED = 'S', 'Started'
        INPROGRESS = 'P', 'In Progress'
        REVIEW = 'R', 'Under Review'
        ACTIONS = 'A', 'Action Items'
        COMPLETE = 'C', 'Completed'

    process_description = models.TextField(unique_for_date='startdate', default='na')
    hazardous_events = models.TextField(default='na')
    causes = models.TextField(default='na')
    consequences = models.TextField(default='na')
    trigger_event = models.TextField(default='na')
    layers_of_protection = models.TextField(default='na')
    RISK_RANKING_CHOICES = [
        ('H', 'High'),
        ('M', 'Medium'),
        ('L', 'Low'),
    ]
    risk_ranking = models.CharField(max_length=1, choices=RISK_RANKING_CHOICES, default='')
    risk_reduction_measures = models.TextField(default='na')
    risk_residual_level = models.CharField(max_length=100, default='na')
    acceptability_criteria = models.CharField(max_length=100, default='na')
    risk_evaluation = models.TextField(default='na')
    threats = models.TextField(default='na')
    vulnerabilities = models.TextField(default='na')
    IMPACT_ANALYSIS_CHOICES = [
        ('H', 'High'),
        ('M', 'Medium'),
        ('L', 'Low'),
    ]
    impact_analysis = models.CharField(max_length=1, choices=IMPACT_ANALYSIS_CHOICES, default='L')
    likelihood_assessment = models.TextField(default='na')
    risk_evaluation = models.TextField(default='na')
    risk_mitigation = models.TextField(default='na')
    riskauthor_id = models.IntegerField(default=1)
    submit_status = models.CharField(max_length=1, choices=SubmitStatus.choices, default=SubmitStatus.STARTED)
    startdate = models.DateTimeField(default=timezone.now)
    enddate = models.DateTimeField(auto_now_add=True)
    updateddate = models.DateTimeField(auto_now=True)
    facility = models.TextField(default='na')
    business_unit = models.TextField(default='na')
    project_name = models.TextField(default='na')
    scope = models.TextField(default='na')
    objective = models.TextField(default='na')
    assumptions = models.TextField(default='na')
    SystemName = models.TextField(default='na')
    SystemDescription = models.TextField(default='na')
    SystemOwner = models.TextField(default='na')
    SystemScope = models.TextField(default='na')

    objects = models.Manager()
    published = PublishedManager()

    class Meta:
        ordering = ['-startdate']
        indexes = [
            models.Index(fields=['-startdate']),
        ]

    def __str__(self):
        return self.process_description

    def get_absolute_url(self):
        return reverse('OTRisk:post_detail', args=[self.id])