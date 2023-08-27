from django.db import models
from django.contrib.auth.models import User




class tblStandards(models.Model):
    id = models.AutoField(primary_key=True)
    standard = models.TextField()

    class Meta:
        db_table = 'tblStandards'


class auditlog(models.Model):
    id = models.AutoField(primary_key=True)
    userID = models.IntegerField()
    timestamp = models.DateTimeField()
    user_action = models.CharField(max_length=100)
    user_ipaddress = models.CharField(max_length=20)

    class Meta:
        db_table = 'tblAuditLog'


class tblDeviations(models.Model):
    ID = models.AutoField(primary_key=True)
    Deviation = models.CharField(max_length=25)
    Description = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblDeviations'


class tblUnits(models.Model):
    id = models.AutoField(primary_key=True)
    PlantUnits = models.CharField(max_length=50)

    class Meta:
        db_table = 'tblUnits'


class tblZones(models.Model):
    id = models.AutoField(primary_key=True)
    PlantZone = models.CharField(max_length=50)

    class Meta:
        db_table = 'tblZones'


class tblNodes(models.Model):
    ID = models.AutoField(primary_key=True)
    NodeType = models.CharField(max_length=50)

    class Meta:
        db_table = 'tblNodes'


class tblThreatSources(models.Model):
    id = models.AutoField(primary_key=True)
    ThreatSource = models.CharField(max_length=100)

    class Meta:
        db_table = 'tblThreatSources'


class tblThreatActions(models.Model):
    id = models.AutoField(primary_key=True)
    ThreatAction = models.CharField(max_length=100)

    class Meta:
        db_table = 'tblThreatActions'


class tblIndustry(models.Model):
    id = models.AutoField(primary_key=True)
    Industry = models.CharField(max_length=100)
    safetyWeight = models.IntegerField()
    lifeWeight = models.IntegerField()
    productionWeight = models.IntegerField()
    financeWeight = models.IntegerField()
    reputationWeight = models.IntegerField()
    environmentWeight = models.IntegerField()
    regulatoryWeight = models.IntegerField()
    dataWeight = models.IntegerField()

    class Meta:
        db_table = 'tblIndustry'


class tblCyberPHAHeader(models.Model):
    ID = models.AutoField(primary_key=True)
    PHALeader = models.CharField(max_length=30)
    PHALeaderEmail = models.CharField(max_length=50)
    FacilityID = models.IntegerField()
    FacilityName = models.CharField(max_length=50)
    FacilityOwner = models.CharField(max_length=50)
    FacilityScope = models.CharField(max_length=255)
    Description = models.CharField(max_length=255)
    Notes = models.TextField(max_length=255)
    Date = models.DateTimeField()
    AssessmentUnit = models.CharField(max_length=100)
    AssessmentNode = models.CharField(max_length=100)
    AssessmentZone = models.CharField(max_length=100)
    FacilityType = models.CharField(max_length=100)
    Industry = models.TextField(max_length=30)
    EmployeesOnSite = models.IntegerField()
    AssessmentStartDate = models.DateField()
    AssessmentEndDate = models.DateField()
    AssessmentStatus = models.CharField(max_length=10)
    UserID = models.CharField(max_length=10)
    Timestamp = models.DateField
    Deleted = models.IntegerField()
    facilityAddress = models.CharField(max_length=255)
    title = models.TextField()
    safetySummary = models.TextField()
    chemicalSummary = models.TextField()
    physicalSummary = models.TextField()
    otherSummary = models.TextField()
    country = models.TextField()

    class Meta:
        db_table = 'tblCyberPHAHeader'


class tblControlObjectives(models.Model):
    ID = models.AutoField(primary_key=True)
    ControlObjective = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblControlObjectives'


class tblMitigationMeasures(models.Model):
    ID = models.AutoField(primary_key=True)
    ControlObjective = models.CharField(max_length=255)
    ControlDescription = models.CharField(max_length=255)
    ImplementationGuidelines = models.TextField(max_length=255)
    ResponsibleParty = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblMitigationMeasures'


class tblScenarios(models.Model):
    ID = models.AutoField(primary_key=True)
    Scenario = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblScenarios'


class tblThreatIntelligence(models.Model):
    ID = models.AutoField(primary_key=True)
    ThreatDescription = models.CharField(max_length=255)
    AttackVectors = models.CharField(max_length=255)
    Motivations = models.TextField(max_length=255)
    PotentialImpacts = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblThreatIntelligence'


class tblCompliance(models.Model):
    id = models.AutoField(primary_key=True)
    regulationName = models.CharField(max_length=255)
    regulationCountry = models.CharField(max_length=50)
    industry = models.TextField(max_length=100)
    acronym = models.CharField(max_length=10)

    class Meta:
        db_table = 'tblCompliance'


class tblCyberPHAEntry(models.Model):
    ID = models.AutoField(primary_key=True)
    AssessmentName = models.CharField(max_length=255)
    Scenario = models.CharField(max_length=255)
    ControlObjective = models.CharField(max_length=255)
    RiskCategory = models.CharField(max_length=255)
    AssessmentCriteria = models.CharField(max_length=255)
    MitigationMeasures = models.CharField(max_length=255)
    Likelihood = models.IntegerField()
    Impact = models.IntegerField()
    RiskLevel = models.CharField(max_length=255)
    ThreatIntelligence = models.CharField(max_length=255)
    CyberPHAID = models.IntegerField()
    Consequences = models.TextField()

    class Meta:
        db_table = 'tblCyberPHAEntry'


class tblCyberPHAScenario(models.Model):
    ID = models.AutoField(primary_key=True)
    CyberPHA = models.IntegerField()
    Scenario = models.CharField(max_length=255)
    ThreatClass = models.CharField(max_length=100)
    ThreatAgent = models.CharField(max_length=100)
    ThreatAction = models.CharField(max_length=100)
    Countermeasures = models.CharField(max_length=500)
    RiskCategory = models.CharField(max_length=100)
    Consequence = models.CharField(max_length=1000)
    impactSafety = models.IntegerField()
    impactDanger = models.IntegerField()
    impactProduction = models.IntegerField()
    impactFinance = models.IntegerField()
    impactReputation = models.IntegerField()
    impactEnvironment = models.IntegerField()
    impactRegulation = models.IntegerField()
    impactData = models.IntegerField()
    UEL = models.IntegerField()
    RRU = models.IntegerField()
    SM = models.IntegerField()
    MEL = models.IntegerField()
    RRM = models.IntegerField()
    SA = models.IntegerField()
    MELA = models.IntegerField()
    RRa = models.TextField()
    recommendations = models.CharField(max_length=1000)
    Deleted = models.IntegerField()
    timestamp = models.DateTimeField()
    aro = models.IntegerField()
    sle = models.IntegerField()
    ale = models.IntegerField()
    countermeasureCosts = models.IntegerField()
    control_recommendations = models.TextField()
    justifySafety = models.TextField()
    justifyLife = models.TextField()
    justifyProduction = models.TextField()
    justifyFinancial = models.TextField()
    justifyReputation = models.TextField()
    justifyEnvironment = models.TextField()
    justifyRegulation = models.TextField()
    justifyData = models.TextField()
    userID = models.ForeignKey(User, on_delete=models.CASCADE, db_column='userID')

    class Meta:
        db_table = 'tblCyberPHAScenario'

    def save(self, *args, **kwargs):
        # If the record is being created and there's a user available, set the userID
        if not self.pk and hasattr(self, '_current_user'):
            self.userID = self._current_user

        super(tblCyberPHAScenario, self).save(*args, **kwargs)

    @classmethod
    def set_current_user(cls, user):
        cls._current_user = user


class tblCyberPHAControlObjective(models.Model):
    ID = models.AutoField(primary_key=True)
    CyberPHAEntry = models.ForeignKey(tblCyberPHAEntry, on_delete=models.CASCADE)
    ControlObjective = models.ForeignKey(tblControlObjectives, on_delete=models.CASCADE)

    class Meta:
        db_table = 'tblCyberPHAControlObjective'


class tblCyberPHAMitigationMeasure(models.Model):
    ID = models.AutoField(primary_key=True)
    CyberPHAEntry = models.ForeignKey(tblCyberPHAEntry, on_delete=models.CASCADE)
    MitigationMeasure = models.ForeignKey(tblMitigationMeasures, on_delete=models.CASCADE)

    class Meta:
        db_table = 'tblCyberPHAMitigationMeasure'


class tblCyberPHA_key(models.Model):
    ID = models.AutoField(primary_key=True)
    Entry = models.ForeignKey(tblCyberPHAEntry, on_delete=models.CASCADE)

    class Meta:
        db_table = 'tblCyberPHA_key'


class tblSafeguards(models.Model):
    ID = models.AutoField(primary_key=True)
    Safeguard = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblSafeguards'


class tblAssessmentCriteria(models.Model):
    ID = models.AutoField(primary_key=True)
    Criterion = models.CharField(max_length=100)
    Scale = models.CharField(max_length=100)
    Formula = models.CharField(max_length=100)
    Algorithm = models.CharField(max_length=100)

    class Meta:
        db_table = 'tblAssessmentCriteria'


class tblRiskCategories(models.Model):
    ID = models.AutoField(primary_key=True)
    CategoryName = models.CharField(max_length=100)
    Description = models.CharField(max_length=255)

    class Meta:
        db_table = 'tblRiskCategories'
