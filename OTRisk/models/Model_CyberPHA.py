from django.db import models
from django.contrib.auth.models import User
from accounts.models import Organization
from OTRisk.models.raw import MitreICSMitigations


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


class tblAssetType(models.Model):
    AssetType = models.TextField()
    Description = models.TextField()

    def __str__(self):
        return self.AssetType

SECURITY_LEVELS = [
    (0, 'SL 0: No security requirements or security protection necessary'),
    (1, 'SL 1: Protection against casual or coincidental violation'),
    (2, 'SL 2: Protection against intentional violation using simple means with low resources, generic skills and low motivation'),
    (3, 'SL 3: Protection against intentional violation using sophisticated means with moderate resources, IACS specific skills and moderate motivation'),
    (4, 'SL 4: Protection against intentional violation using sophisticated means with extended resources, IACS specific skills and high motivation'),
]
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
    complianceSummary = models.TextField()
    country = models.TextField()
    SHIFT_MODELS = [
        ('Single Shift Model', 'Single Shift Model'),
        ('Double Shift Model', 'Double Shift Model'),
        ('Three-Shift (24/7) Model', 'Three-Shift (24/7) Model'),
        ('Rotating Shift Model', 'Rotating Shift Model'),
        ('Fixed Shift Model', 'Fixed Shift Model'),
        ('Split Shift Model', 'Split Shift Model'),
        ('On-Call or Flex Shift Model', 'On-Call or Flex Shift Model'),
        ('Compressed Workweek Model', 'Compressed Workweek Model'),
        ('Part-Time or Seasonal Model', 'Part-Time or Seasonal Model'),
        ('Hybrid Shift Models', 'Hybrid Shift Models'),
    ]

    shift_model = models.CharField(max_length=50, choices=SHIFT_MODELS)
    annual_revenue = models.DecimalField(max_digits=10, decimal_places=0)
    cyber_insurance = models.BooleanField(default=False)
    pha_score = models.IntegerField()
    sl_t = models.PositiveSmallIntegerField(choices=SECURITY_LEVELS, default=0)
    class Meta:
        db_table = 'tblCyberPHAHeader'

    def __str__(self):
        return self.FacilityName


class cyberpha_safety(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    rating = models.IntegerField()
    validated = models.BooleanField(default=False)
    cyberphaID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='cyberphaID')

    class Meta:
        db_table = 'cyberpha_safety'

class cyberpha_chemical(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    rating = models.IntegerField()
    validated = models.BooleanField(default=False)
    cyberphaID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='cyberphaID')

    class Meta:
        db_table = 'cyberpha_chemical'

class cyberpha_physicalsecurity(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    rating = models.IntegerField()
    validated = models.BooleanField(default=False)
    cyberphaID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='cyberphaID')

    class Meta:
        db_table = 'cyberpha_physicalsecurity'

class cyberpha_compliance(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    rating = models.IntegerField()
    validated = models.BooleanField(default=False)
    cyberphaID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='cyberphaID')

    class Meta:
        db_table = 'cyberpha_compliance'


class cyberpha_ot(models.Model):
    id = models.AutoField(primary_key=True)
    description = models.TextField()
    rating = models.IntegerField()
    validated = models.BooleanField(default=False)
    cyberphaID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='cyberphaID')

    class Meta:
        db_table = 'cyberpha_ot'

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
    industry = models.ForeignKey(tblIndustry, on_delete=models.SET_NULL, null=True, blank=True)

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
    CyberPHA = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, db_column='CyberPHA')
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
    impactSupply = models.IntegerField()
    UEL = models.IntegerField()
    uel_threat = models.IntegerField()
    uel_vuln = models.IntegerField()
    uel_exposure = models.IntegerField()
    RRU = models.IntegerField()
    SM = models.IntegerField()
    MEL = models.IntegerField()
    RRM = models.IntegerField()
    SA = models.IntegerField()
    MELA = models.IntegerField()
    RRa = models.TextField()
    sl = models.IntegerField()
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
    justifySupply = models.TextField()
    userID = models.ForeignKey(User, on_delete=models.CASCADE, db_column='userID')
    standards = models.TextField()
    outage = models.TextField()
    outageDuration = models.IntegerField()
    outageCost = models.IntegerField()
    probability = models.TextField()
    likelihood = models.IntegerField()
    sle_low = models.IntegerField()
    sle_high = models.IntegerField()
    risk_register = models.BooleanField(default=False)
    safety_hazard = models.TextField()
    sis_outage = models.BooleanField(default=False)
    sis_compromise = models.BooleanField(default=False)
    risk_owner = models.TextField()
    RISK_PRIORITIES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    risk_priority = models.CharField(max_length=50, choices=RISK_PRIORITIES)
    RISK_RESPONSES = [
        ('Manage', 'Manage'),
        ('Mitigate', 'Mitigate'),
        ('Transfer', 'Transfer'),
        ('Accept', 'Accept')
    ]
    risk_response = models.CharField(max_length=50, choices=RISK_RESPONSES)
    RISK_STATUSES = [
        ('Open', 'Open'),
        ('Closed', 'Closed')
    ]
    risk_status = models.CharField(max_length=50, choices=RISK_STATUSES)
    risk_open_date = models.DateField()
    risk_close_date = models.DateField()
    control_effectiveness = models.IntegerField()
    frequency = models.DecimalField(max_digits=4, decimal_places=1)
    sl_a = models.PositiveSmallIntegerField(choices=SECURITY_LEVELS, default=0)


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


class vulnerability_analysis(models.Model):
    description = models.TextField()
    asset_name = models.TextField()
    asset_type = models.ForeignKey(tblAssetType, on_delete=models.CASCADE)  # Foreign key to tblAssetType
    cve = models.TextField()
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE)  # Foreign key to tblCyberPHAScenario
    cve_detail = models.TextField()

    def __str__(self):
        return self.description


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


from django.core.validators import MinValueValidator, MaxValueValidator


class MitreControlAssessment(models.Model):
    # Foreign key to the MitreICSMitigations model
    control = models.ForeignKey(MitreICSMitigations, on_delete=models.CASCADE)

    # Foreign key to the tblCyberPHAHeader model
    cyberPHA = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE)

    # Field to store user input regarding the effectiveness of the control as a percentage
    effectiveness_percentage = models.DecimalField(
        max_digits=3, decimal_places=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    weighting = models.IntegerField()
    # Optional: Additional notes or comments about the assessment
    notes = models.TextField(blank=True, null=True)

    # Timestamps for creation and modification
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Ensure that a control can only be assessed once for a given facility
        unique_together = ['control', 'cyberPHA']


class CyberPHAScenario_snapshot(models.Model):
    ID = models.AutoField(primary_key=True)
    CyberPHA = models.IntegerField()
    ScenarioID = models.IntegerField()
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
    impactSupply = models.IntegerField()
    UEL = models.IntegerField()
    uel_threat = models.IntegerField()
    uel_vuln = models.IntegerField()
    uel_exposure = models.IntegerField()
    RRU = models.IntegerField()
    SM = models.IntegerField()
    MEL = models.IntegerField()
    RRM = models.IntegerField()
    SA = models.IntegerField()
    MELA = models.IntegerField()
    RRa = models.TextField()
    sl = models.IntegerField()
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
    justifySupply = models.TextField()
    userID = models.IntegerField()
    organizationID = models.IntegerField()
    standards = models.TextField()
    outage = models.TextField()
    outageDuration = models.IntegerField()
    outageCost = models.IntegerField()
    probability = models.TextField()
    sle_low = models.IntegerField()
    sle_high = models.IntegerField()
    risk_register = models.BooleanField(default=False)
    safety_hazard = models.TextField()
    sis_outage = models.BooleanField(default=False)
    sis_compromise = models.BooleanField(default=False)
    risk_owner = models.TextField()
    RISK_PRIORITIES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    risk_priority = models.CharField(max_length=50, choices=RISK_PRIORITIES)
    RISK_RESPONSES = [
        ('Manage', 'Manage'),
        ('Mitigate', 'Mitigate'),
        ('Transfer', 'Transfer'),
        ('Accept', 'Accept')
    ]
    risk_response = models.CharField(max_length=50, choices=RISK_RESPONSES)
    RISK_STATUSES = [
        ('Open', 'Open'),
        ('Closed', 'Closed')
    ]
    risk_status = models.CharField(max_length=50, choices=RISK_STATUSES)
    risk_open_date = models.DateField()
    risk_close_date = models.DateField()
    snapshot_date = models.DateField()
    control_effectiveness = models.IntegerField()
    likelihood = models.IntegerField()
    frequency = models.DecimalField(max_digits=4, decimal_places=1)
    sl_a = models.PositiveSmallIntegerField(choices=SECURITY_LEVELS, default=0)


class Audit(models.Model):
    USER_ACTIONS = [
        ("Edit", "Edit"),
        ("Add New", "Add New"),
        ("Delete", "Delete"),
        ("Login", "Login"),
        ("Logout", "Logout"),
        ("Create Profile", "Create Profile"),
        ("Generate Risk Assessment", "Generate Risk Assessment")
    ]

    RECORD_TYPES = [
        ("Application", "Application"),
        ("QRAW", "QRAW"),
        ("CyberPHA", "CyberPHA"),
        ("RiskRegister", "RiskRegister"),
        ("ActionItem", "ActionItem")
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization_id = models.PositiveIntegerField()
    ip_address = models.GenericIPAddressField()
    session_id = models.CharField(max_length=256)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_action = models.CharField(choices=USER_ACTIONS, max_length=50)
    record_type = models.CharField(choices=RECORD_TYPES, max_length=50)
    record_id = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        db_table = 'audit'
        managed = True


class PHAControlList(models.Model):
    ID = models.AutoField(primary_key=True)
    scenarioID = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE, db_column='scenarioID',
                                   related_name='controls')
    control = models.TextField()
    reference = models.TextField()
    score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])

    class Meta:
        db_table = 'tblPHAControlList'
        verbose_name = 'PHA Control List'
        verbose_name_plural = 'PHA Control Lists'

    def __str__(self):
        return self.control
