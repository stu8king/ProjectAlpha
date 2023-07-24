from django.db import models


class tblScenarioRecommendations(models.Model):
    ID = models.AutoField(primary_key=True)
    RiskPostID = models.IntegerField()
    Recommendation = models.TextField()

    class Meta:
        db_table = 'tblScenarioRecommendations'

    def __str__(self):
        return f"Recommendation ID: {self.ID}, Risk Post ID: {self.RiskPostID}"


class RiskScenario(models.Model):
    post_id = models.IntegerField()
    ScenarioDescription = models.TextField()
    ConsequenceAnalysis = models.TextField()
    ThreatScore = models.TextField()
    ThreatAction = models.TextField()
    Countermeasures = models.TextField()
    Severity = models.TextField()
    Frequency = models.TextField()
    Exposure = models.TextField()
    Resilience = models.TextField()
    RRu = models.TextField()
    UEL = models.TextField()
    SI = models.TextField()
    Sm = models.TextField()
    MEL = models.TextField()
    RRm = models.TextField()
    Sa = models.TextField()
    MELa = models.TextField()
    RRa = models.TextField()

    class Meta:
        db_table = 'OTRisk_scenario'

    def __str__(self):
        return f"Risk Scenario ID: {self.post_id}"
