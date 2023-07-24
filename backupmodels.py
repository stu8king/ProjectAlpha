from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


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

    process_description = models.TextField()
    hazardous_events = models.TextField()
    causes = models.TextField()
    consequences = models.TextField()
    trigger_event = models.TextField()
    layers_of_protection = models.TextField()
    RISK_RANKING_CHOICES = [
        ('H', 'High'),
        ('M', 'Medium'),
        ('L', 'Low'),
    ]
    risk_ranking = models.CharField(max_length=1, choices=RISK_RANKING_CHOICES)
    risk_reduction_measures = models.TextField()
    risk_residual_level = models.CharField(max_length=100)
    acceptability_criteria = models.CharField(max_length=100)
    risk_evaluation = models.TextField()
    threats = models.TextField()
    vulnerabilities = models.TextField()
    IMPACT_ANALYSIS_CHOICES = [
        ('H', 'High'),
        ('M', 'Medium'),
        ('L', 'Low'),
    ]
    impact_analysis = models.CharField(max_length=1, choices=IMPACT_ANALYSIS_CHOICES)
    likelihood_assessment = models.TextField()
    risk_evaluation = models.TextField()
    risk_mitigation = models.TextField()
    riskauthor = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='ra_posts')
    submit_status = models.CharField(max_length=1, choices=SubmitStatus.choices, default=SubmitStatus.STARTED)
    startdate = models.DateTimeField(default=timezone.now)
    enddate = models.DateTimeField(auto_now_add=True)
    updateddate = models.DateTimeField(auto_now=True)

    objects = models.Manager()
    published = PublishedManager()

    class Meta:
        ordering = ['-startdate']
        indexes = [
            models.Index(fields=['-startdate']),
        ]

    def __str__(self):
        return self.process_description

    # Asset Class


class Asset(models.Model):
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='assets')
    title = models.CharField(max_length=100)
    version = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()

    def __str__(self):
        return f"{self.title} ({self.version}) - {self.ip_address}"