from django.db import models
from OTRisk.models.post import Post


class Asset(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='assets')
    name = models.CharField(max_length=100, default='na')
    vendor = models.CharField(max_length=100, default='na')
    description = models.TextField(default='na')
    asset_type = models.CharField(max_length=100, default='na')
    location = models.CharField(max_length=100, default='na')
    ip_address = models.CharField(max_length=100, default='na')
    owner = models.CharField(max_length=100, default='na')
    criticality = models.CharField(max_length=100, default='na')
    configuration = models.TextField(default='na')
    operational_conditions = models.TextField(default='na')
    maintenance_requirements = models.TextField(default='na')
    interdependencies = models.TextField(default='na')
    vulnerabilities = models.TextField(default='na')
    risk_factors = models.TextField(default='na')
    mitigation_measures = models.TextField(default='na')
    monitoring_inspection = models.TextField(default='na')
    historical_performance = models.TextField(default='na')

    def __str__(self):
        return f"{self.name} {self.vendor}({self.location}) - {self.ip_address}"
