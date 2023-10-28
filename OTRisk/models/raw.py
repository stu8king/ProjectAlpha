from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from accounts.models import Organization

from django.contrib.auth.models import User


# risk assessment worksheet
# risk assessment worksheet scenarios
# risk assessment worksheet action items

class MitreICSMitigations(models.Model):
    id = models.TextField(primary_key=True)
    name = models.TextField()
    description = models.TextField()

    class Meta:
        db_table = 'tblMitreMitigations'


class MitreICSTechniques(models.Model):
    ID = models.IntegerField(primary_key=True)
    SourceID = models.ForeignKey(MitreICSMitigations, on_delete=models.CASCADE, related_name='mitigations',
                                 db_column='SourceID')
    SourceName = models.TextField()
    TargetID = models.TextField()
    TargetName = models.TextField()
    Description = models.TextField()

    class Meta:
        db_table = 'tblMitreTechniques'


class RAWorksheet(models.Model):
    ID = models.AutoField(primary_key=True)
    RATitle = models.CharField(max_length=255)
    RADescription = models.CharField(max_length=255)
    RADate = models.CharField(max_length=255)
    RASynopsis = models.CharField(max_length=255)
    UserID = models.IntegerField()
    STATUS_CHOICES = [
        ("Open", "Open"),
        ("Closed", "Closed"),
    ]
    StatusFlag = models.CharField(max_length=5, choices=STATUS_CHOICES, default='Open')
    RATrigger = models.CharField(max_length=25)
    AssessorName = models.CharField(max_length=50)
    BusinessUnit = models.CharField(max_length=50)
    BusinessUnitType = models.CharField(max_length=50)
    EmployeeCount = models.IntegerField(null=True, default=0)
    RegulatoryOversight = models.CharField(max_length=5)
    WalkdownID = models.IntegerField()
    industry = models.CharField(max_length=30)
    cyberPHAID = models.IntegerField(default=0)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    revenue = models.IntegerField()
    insurance = models.IntegerField()
    deductable = models.IntegerField()

    class Meta:
        db_table = 'tblRAWorksheet'


class RAWorksheetScenario(models.Model):
    ID = models.AutoField(primary_key=True)
    RAWorksheetID = models.ForeignKey(RAWorksheet, on_delete=models.CASCADE, db_column='RAWorksheetID')
    ScenarioDescription = models.CharField(max_length=255)
    ThreatCode = models.CharField(max_length=3)
    VulnCode = models.CharField(max_length=3)
    ReputationCode = models.CharField(max_length=3)
    FinancialCode = models.CharField(max_length=3)
    OperationalCode = models.CharField(max_length=3)
    SafetyCode = models.CharField(max_length=3)
    RiskScore = models.IntegerField()
    Comments = models.CharField(max_length=255)
    ScenarioPriority = models.CharField(max_length=5)
    ThreatScore = models.IntegerField()
    VulnScore = models.IntegerField()
    ReputationScore = models.IntegerField()
    OperationScore = models.IntegerField()
    FinancialScore = models.IntegerField()
    SafetyScore = models.IntegerField()
    DataScore = models.IntegerField()
    SupplyChainScore = models.IntegerField()
    ScenarioType = models.CharField(max_length=25)
    RiskStatus = models.CharField(max_length=25)
    threatSource = models.CharField(max_length=50)
    threatTactic = models.CharField(max_length=50)
    notes = models.TextField()
    lifeScore = models.IntegerField()
    productionScore = models.IntegerField()
    environmentScore = models.IntegerField()
    regulatoryScore = models.IntegerField()
    riskSummary = models.TextField()
    scenarioCost = models.IntegerField()
    justifySafety = models.TextField()
    justifyLife = models.TextField()
    justifyProduction = models.TextField()
    justifyFinancial = models.TextField()
    justifyReputation = models.TextField()
    justifyEnvironment = models.TextField()
    justifyRegulation = models.TextField()
    justifyData = models.TextField()
    justifySupply = models.TextField()
    event_cost_low = models.IntegerField()
    event_cost_high = models.IntegerField()
    event_cost_median = models.IntegerField()
    OUTAGE_CHOICES = [
        ("Yes", "Yes"),
        ("No", "No"),
        ("N/A", "N/A"),
    ]
    outage = models.CharField(max_length=3, choices=OUTAGE_CHOICES, default='N/A')
    outageLength = models.IntegerField(default=0)
    risk_register = models.BooleanField(default=False)
    IMPACT_CHOICES = [
        ("N/A", "N/A"),
        ("Damage to Property", "Damage to Property"),
        ("Denial of Control", "Denial of Control"),
        ("Denial of View", "Denial of View"),
        ("Loss of Availability", "Loss of Availability"),
        ("Loss of Control", "Loss of Control"),
        ("Loss of Productivity and Revenue", "Loss of Productivity and Revenue"),
        ("Loss of Protection", "Loss of Protection"),
        ("Loss of Safety", "Loss of Safety"),
        ("Loss of View", "Loss of View"),
        ("Manipulation of Control", "Manipulation of Control"),
        ("Manipulation of View", "Manipulation of View"),
        ("Theft of Operational Information", "Theft of Operational Information"),
    ]
    impact = models.CharField(max_length=30, choices=IMPACT_CHOICES, default='N/A'),
    residual_risk = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(10)])

    class Meta:
        db_table = 'tblRAWorksheetScenario'


class RAActions(models.Model):
    ID = models.AutoField(primary_key=True)
    RAWorksheetID = models.ForeignKey(RAWorksheet, on_delete=models.CASCADE, db_column='RAWorksheetID')
    phaID = models.IntegerField()
    actionTitle = models.CharField(max_length=255)
    actionOwner = models.CharField(max_length=255)
    actionDate = models.CharField(max_length=255)
    actionEffort = models.CharField(max_length=255)
    actionDifficulty = models.CharField(max_length=1)
    actionCost = models.CharField(max_length=1)
    actionStatus = models.CharField(max_length=50)
    actionDescription = models.CharField(max_length=255)
    actionDueDate = models.DateField()
    actionPriority = models.IntegerField()
    actionAssets = models.TextField()
    actionAffinity = models.TextField()
    safetyMitigation = models.IntegerField()
    lifeMitigation = models.IntegerField()
    productionMitigation = models.IntegerField()
    financeMitigation = models.IntegerField()
    reputationMitigation = models.IntegerField()
    environmentMitigation = models.IntegerField()
    regulationMitigation = models.IntegerField()
    dataMitigation = models.IntegerField()
    supplyMitigation = models.IntegerField()
    threatMitigation = models.IntegerField()
    vulnerabilityMitigation = models.IntegerField()
    outageWWW = models.CharField(max_length=3)
    outagePS = models.CharField(max_length=3)
    outageIT = models.CharField(max_length=3)
    outageEMS = models.CharField(max_length=3)
    outageICS = models.CharField(max_length=3)
    outageSIS = models.CharField(max_length=3)
    organizationid = models.ForeignKey(Organization, on_delete=models.CASCADE, verbose_name="Organization",
                                       related_name="ra_actions")
    userid = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="User", related_name="ra_actions")
    history = models.TextField()

    class Meta:
        db_table = 'tblRawActions'


class SecurityControls(models.Model):
    ID = models.AutoField(primary_key=True)
    Control = models.CharField(max_length=50)
    ControlTypeDescription = models.CharField(max_length=255)
    ControlCategory = models.CharField(max_length=25)

    class Meta:
        db_table = 'tblControls'


class ControlRiskAffinity(models.Model):
    ID = models.AutoField(primary_key=True)
    RAWorksheetID = models.IntegerField()
    ControlID = models.IntegerField()
    ControlAffinity = models.CharField(max_length=3)
    ControlAssetID = models.IntegerField()
    Description = models.CharField(max_length=255)
    RiskReduction = models.CharField(max_length=3)

    class Meta:
        db_table = 'tblControlRiskAffinity'


class RawControlList(models.Model):
    ID = models.AutoField(primary_key=True)
    scenarioID = models.ForeignKey(RAWorksheetScenario, on_delete=models.CASCADE, db_column='scenarioID',
                                   related_name='controls')
    control = models.TextField()
    score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])

    class Meta:
        db_table = 'tblRawControlList'
        verbose_name = 'Control List'
        verbose_name_plural = 'Control Lists'

    def __str__(self):
        return self.control
