import random

from django.conf import settings
from django.db import models, IntegrityError
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from decimal import Decimal
from django.db.models import URLField

import OTRisk.models.model_assessment
from accounts.models import Organization, UserProfile
from OTRisk.models.raw import MitreICSMitigations, RAWorksheet


class user_scenario_audit(models.Model):
    # model that records the text entered into the scenario text box
    scenario_text = models.TextField()
    entered_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization_id = models.PositiveIntegerField()
    ip_address = models.GenericIPAddressField()
    session_id = models.CharField(max_length=256)


class CybersecurityDefaults(models.Model):
    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='cybersecurity_defaults'
    )
    overall_aggregate_limit = models.DecimalField(max_digits=12, decimal_places=2, default=1000000.00)
    per_claim_limit = models.DecimalField(max_digits=12, decimal_places=2, default=500000.00)
    deductible_amount = models.DecimalField(max_digits=12, decimal_places=2, default=10000.00)
    first_party_coverage = models.BooleanField(default=True)
    third_party_coverage = models.BooleanField(default=True)
    security_event_liability = models.BooleanField(default=True)
    privacy_regulatory_actions = models.BooleanField(default=True)
    cyber_extortion_coverage = models.BooleanField(default=True)
    data_breach_response_coverage = models.BooleanField(default=True)
    business_interruption_coverage = models.BooleanField(default=True)
    dependent_business_coverage = models.BooleanField(default=True)
    data_recovery = models.BooleanField(default=True)
    hardware_replacement = models.BooleanField(default=True)
    reputation_harm = models.BooleanField(default=True)
    media_liability = models.BooleanField(default=True)
    pci_dss = models.BooleanField(default=True)
    premium_base = models.DecimalField(max_digits=12, decimal_places=2, default=5000.00)
    notification_period_days = models.IntegerField(default=30)
    cancellation_terms_days = models.IntegerField(default=30)

    class Meta:
        db_table = 'cybersecurity_defaults'
        managed = True

    def __str__(self):
        return f"{self.organization.name} Cybersecurity Defaults"


class OrganizationDefaults(models.Model):
    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('de', 'German'),
        ('es', 'Spanish'),
        ('ar', 'Arabic'),
        ('ja', 'Japanese'),
        ('zh', 'Mandarin'),
    ]

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='defaults'
    )
    industry = models.ForeignKey(
        'tblIndustry',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    language = models.CharField(
        max_length=30,
        choices=LANGUAGE_CHOICES,  # Add the choices here
        null=True,
        blank=True
    )
    annual_revenue = models.IntegerField(
        null=True,
        blank=True
    )
    cyber_insurance = models.IntegerField(
        null=True,
        blank=True
    )
    insurance_deductible = models.IntegerField(
        null=True,
        blank=True
    )
    employees = models.IntegerField(
        null=True,
        blank=True
    )
    impact_weight_safety = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_danger = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_environment = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_production = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_finance = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_reputation = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_regulation = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_data = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    impact_weight_supply = models.IntegerField(
        default=1,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
    )
    exalens_api_key = models.TextField(null=True)
    exalens_client_id = models.TextField(null=True)
    exalens_ip_address = models.TextField(null=True)
    business_unit_name = models.CharField(null=True, max_length=100)
    business_unit_address_line1 = models.CharField(null=True, max_length=100)
    business_unit_address_line2 = models.CharField(null=True, max_length=100)
    business_unit_address_line3 = models.CharField(null=True, max_length=100)
    business_unit_country = models.CharField(null=True, max_length=20)
    business_unit_postcode = models.CharField(null=True, max_length=12)
    business_unit_city = models.CharField(null=True, max_length=20)
    business_unit_state = models.CharField(null=True, max_length=20)
    business_unit_lat = models.CharField(null=True, max_length=20)
    business_unit_lon = models.CharField(null=True, max_length=20)

    def __str__(self):
        return f"{self.organization.name} Defaults"


class tblStandards(models.Model):
    id = models.AutoField(primary_key=True)
    standard = models.TextField()

    class Meta:
        db_table = 'tblStandards'


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
    (2,
     'SL 2: Protection against intentional violation using simple means with low resources, generic skills and low motivation'),
    (3,
     'SL 3: Protection against intentional violation using sophisticated means with moderate resources, IACS specific skills and moderate motivation'),
    (4,
     'SL 4: Protection against intentional violation using sophisticated means with extended resources, IACS specific skills and high motivation'),
]


class CyberPHA_Group(models.Model):
    GROUP_TYPES = [
        ('Industry', 'Industry'),
        ('Facility_type', 'Facility Type'),
        ('Country', 'Country'),
        ('Organization', 'Organization'),
    ]
    organization = models.ForeignKey('accounts.Organization', on_delete=models.CASCADE, related_name='cyberpha_groups')
    name = models.CharField(max_length=100)
    group_type = models.CharField(max_length=50, choices=GROUP_TYPES)

    class Meta:
        unique_together = ('name', 'group_type', 'organization')  # Ensure uniqueness across these fields

    def __str__(self):
        return f"{self.name} ({self.group_type}) - {self.organization.name}"


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
    facilityCity = models.CharField(max_length=100, null=True)
    facilityState = models.CharField(max_length=100, null=True)
    facilityCode = models.CharField(max_length=20, null=True)
    facilityLat = models.CharField(max_length=10, null=True)
    facilityLong = models.CharField(max_length=10, null=True)
    facilityAQI = models.IntegerField(null=True)
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
    assessment = models.IntegerField(null=True, blank=True)
    last_assessment_score = models.IntegerField(null=True, blank=True)
    last_assessment_summary = models.TextField(default="No Summary Saved", null=True)
    bia_scenarios = models.IntegerField(null=True, blank=True)  # overall bia score based on all scenarios
    risk_scenarios = models.IntegerField(null=True, blank=True)  # overall cyberPHA risk score based on all scenarios
    coho = models.IntegerField(default=0)  # facility cost per operating hour
    npm = models.IntegerField(default=0)  # net profit margin
    threatSummary = models.TextField(default="No Summary Saved", null=True)
    insightSummary = models.TextField(default="No Summary Saved", null=True)
    strategySummary = models.TextField(default="No Summary Saved", null=True)
    groups = models.ManyToManyField(CyberPHA_Group, blank=True)
    has_incident_response_plan = models.BooleanField(default=False, verbose_name="Has Incident Response Plan")
    plan_last_tested_date = models.DateField(default=timezone.now, verbose_name="Plan Last Tested Date", null=True,
                                             blank=True)
    plan_never_tested = models.BooleanField(default=True, verbose_name="Plan Never Tested")
    is_default = models.BooleanField(default=False)
    exalens_api = models.TextField(null=True)
    exalens_client = models.TextField(null=True)
    exalens_ip = models.TextField(null=True)
    exalens_status = models.TextField(null=True)
    exalens_risk = models.TextField(null=True)
    exalens_score = models.IntegerField(null=True)

    def set_workflow_status(self, status):
        WorkflowStatus.objects.create(cyber_pha_header=self, status=status)

    class Meta:
        db_table = 'tblCyberPHAHeader'

    def __str__(self):
        return self.FacilityName


from django.db import models


class CyberPHACybersecurityDefaults(models.Model):
    cyber_pha = models.OneToOneField(tblCyberPHAHeader, on_delete=models.CASCADE, related_name='cybersecurity_defaults')
    overall_aggregate_limit = models.DecimalField(max_digits=12, decimal_places=2, default=1000000.00)
    per_claim_limit = models.DecimalField(max_digits=12, decimal_places=2, default=500000.00)
    deductible_amount = models.DecimalField(max_digits=12, decimal_places=2, default=10000.00)
    first_party_coverage = models.BooleanField(default=True)
    third_party_coverage = models.BooleanField(default=True)
    security_event_liability = models.BooleanField(default=True)
    privacy_regulatory_actions = models.BooleanField(default=True)
    cyber_extortion_coverage = models.BooleanField(default=True)
    data_breach_response_coverage = models.BooleanField(default=True)
    business_interruption_coverage = models.BooleanField(default=True)
    dependent_business_coverage = models.BooleanField(default=True)
    data_recovery = models.BooleanField(default=True)
    hardware_replacement = models.BooleanField(default=True)
    reputation_harm = models.BooleanField(default=True)
    media_liability = models.BooleanField(default=True)
    pci_dss = models.BooleanField(default=True)
    premium_base = models.DecimalField(max_digits=12, decimal_places=2, default=5000.00)
    notification_period_days = models.IntegerField(default=30)
    cancellation_terms_days = models.IntegerField(default=30)

    class Meta:
        db_table = 'cyber_pha_cybersecurity_defaults'

    def __str__(self):
        return f"{self.cyber_pha.FacilityName} Cybersecurity Defaults"


class CyberPHARiskTolerance(models.Model):
    cyber_pha_header = models.OneToOneField(tblCyberPHAHeader, on_delete=models.CASCADE, primary_key=True)
    negligible_low = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    negligible_high = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    minor_low = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    minor_high = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    moderate_low = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    moderate_high = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    significant_low = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    significant_high = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    severe_low = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))
    severe_high = models.DecimalField(max_digits=14, decimal_places=2, default=Decimal('0.00'))

    class Meta:
        db_table = 'cyberpha_risk_tolerance'

    def __str__(self):
        return f"{self.cyber_pha_header.FacilityName} Risk Tolerance"


class CyberSecurityInvestment(models.Model):
    TYPE_CHOICES = [
        ('Software', 'Software'),
        ('Hardware', 'Hardware'),
        ('People', 'People'),
    ]
    cyber_pha_header = models.ForeignKey('tblCyberPHAHeader', on_delete=models.CASCADE, related_name='investments')
    investment_type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    vendor_name = models.CharField(max_length=255)
    product_name = models.CharField(max_length=255)
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()

    class Meta:
        db_table = 'tblCyberSecurityInvestment'

    def __str__(self):
        return f"{self.product_name} by {self.vendor_name} - {self.investment_type}"


class WorkflowStatus(models.Model):
    STATUS_CHOICES = [
        ('Started', 'Started'),
        ('In Progress', 'In Progress'),
        ('Waiting for Moderation', 'Waiting for Moderation'),
        ('Complete', 'Complete'),
    ]

    cyber_pha_header = models.ForeignKey('tblCyberPHAHeader', on_delete=models.CASCADE,
                                         related_name='workflow_statuses')
    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cyber_pha_header.FacilityName} - {self.status}"


class CyberPHAModerators(models.Model):
    pha_header = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, related_name='moderators')
    moderator = models.ForeignKey(User, on_delete=models.CASCADE)
    target_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'cyberpha_moderators'
        unique_together = ('pha_header', 'moderator')  # Ensure each moderator is unique per PHA header

    def __str__(self):
        return f"{self.moderator.username} for {self.pha_header.FacilityName} ({self.pha_header.ID})"


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


def generate_unique_id():
    # Generate a random 9-digit number
    return random.randint(1, 999999999)


class tblCyberPHAScenario(models.Model):
    ID = models.IntegerField(primary_key=True)
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
    recommendations = models.TextField(null=True)
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
    env_contaminant = models.TextField(null=True)
    env_ecosystem = models.TextField(null=True)
    env_contamination = models.TextField(null=True)
    env_population = models.TextField(null=True)
    env_wildlife = models.TextField(null=True)

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
    risk_status = models.CharField(max_length=6, choices=RISK_STATUSES)
    SCENARIO_STATUSES = [
        ('Draft', 'Draft'),  # status is draft until all moderators have finished moderation
        ('Final', 'Final'),
        ('Started', 'Started')
    ]
    scenario_status = models.CharField(max_length=7, choices=SCENARIO_STATUSES)
    risk_open_date = models.DateField()
    risk_close_date = models.DateField()
    control_effectiveness = models.IntegerField()
    frequency = models.DecimalField(max_digits=4, decimal_places=1)
    sl_a = models.TextField(null=True)
    dangerScope = models.TextField()
    ai_bia_score = models.IntegerField()
    ale_low = models.IntegerField()
    ale_high = models.IntegerField()
    ale_median = models.IntegerField()
    exposed_system = models.BooleanField(
        default=False)  # flag set by the user to define if the scenario relates to publicly exposed systems
    weak_credentials = models.BooleanField(
        default=False)  # flag set by the user to define if the scenario has systems that are configured with weak or default credentials
    compliance_map = models.TextField(default="No Compliance Map Saved", null=True)
    attack_tree_text = models.TextField(null=True)
    executive_summary = models.TextField(null=True)
    cost_projection = models.TextField(null=True)
    risk_rationale = models.TextField(null=True)
    risk_recommendation = models.TextField(null=True)
    cost_justification = models.TextField(null=True)
    risk_treatment_plan = models.TextField(null=True, blank=True)
    asset_name = models.TextField(null=True)
    asset_purpose = models.TextField(null=True)

    class Meta:
        db_table = 'tblCyberPHAScenario'

    def save(self, *args, **kwargs):
        if not self.pk:  # If the record is new
            # If the record is being created and there's a user available, set the userID
            if hasattr(self, '_current_user'):
                self.userID = self._current_user

            # Ensure a unique ID is generated
            unique = False
            max_attempts = 10
            attempts = 0
            while not unique and attempts < max_attempts:
                attempts += 1
                new_id = generate_unique_id()
                if not tblCyberPHAScenario.objects.filter(ID=new_id).exists():
                    self.ID = new_id
                    unique = True
                if attempts == max_attempts:
                    raise IntegrityError("Unable to generate a unique ID after several attempts.")

        super(tblCyberPHAScenario, self).save(*args, **kwargs)

    @classmethod
    def set_current_user(cls, user):
        cls._current_user = user


class ScenarioModeration(models.Model):
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE)
    moderator = models.ForeignKey(User, on_delete=models.CASCADE)
    impactSafety = models.IntegerField()
    impactDanger = models.IntegerField()
    impactProduction = models.IntegerField()
    impactFinance = models.IntegerField()
    impactReputation = models.IntegerField()
    impactEnvironment = models.IntegerField()
    impactRegulation = models.IntegerField()
    impactData = models.IntegerField()
    impactSupply = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('scenario', 'moderator')  # Ensure one entry per moderator per scenario

    def __str__(self):
        return f"Moderation for {self.scenario.Scenario} by {self.moderator.username}"


class scenario_compliance(models.Model):
    # Foreign key to tblCyberPHAScenario.ID (no need to specify db_column='ID')
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE)

    # Other fields
    compliance_issue = models.CharField(max_length=200)
    regulation = models.CharField(max_length=100)
    url = models.URLField(max_length=200)  # Use URLField for URLs

    def __str__(self):
        return f"{self.scenario.Scenario} - {self.regulation}"


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
    env_contaminant = models.TextField(null=True)
    env_ecosystem = models.TextField(null=True)
    env_contamination = models.TextField(null=True)
    env_population = models.TextField(null=True)
    env_wildlife = models.TextField(null=True)
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
    ale_low = models.IntegerField()
    ale_high = models.IntegerField()
    ale_median = models.IntegerField()
    dangerScope = models.TextField()
    exposed_system = models.BooleanField(
        default=False)  # flag set by the user to define if the scenario relates to publicly exposed systems
    weak_credentials = models.BooleanField(
        default=False)  # flag set by the user to define if the scenario has systems that are configured with weak or default credentials
    compliance_map = models.TextField(default="No Compliance Map Saved", null=True)
    attack_tree_text = models.TextField(null=True)
    executive_summary = models.TextField(null=True)
    cost_projection = models.TextField(null=True)
    risk_rationale = models.TextField(null=True)
    risk_recommendation = models.TextField(null=True)
    cost_justification = models.TextField(null=True)
    asset_name = models.TextField(null=True)
    asset_purpose = models.TextField(null=True)


class PHA_Safeguard(models.Model):
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE, related_name='safeguards')
    safeguard_description = models.TextField(max_length=255)
    safeguard_type = models.CharField(max_length=100)

    class Meta:
        db_table = 'tblPHASafeguard'


class PHA_Observations(models.Model):
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE, related_name='observations')
    observation_description = models.TextField(max_length=255)

    class Meta:
        db_table = 'tblPHAObservations'


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


from django.db import models


class ScenarioConsequences(models.Model):
    scenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE, db_column='Scenario')
    consequence_text = models.CharField(max_length=1000)
    is_validated = models.BooleanField(default=False)

    class Meta:
        db_table = 'scenario_consequences'

    def __str__(self):
        return f"Consequence for {self.scenario.Scenario}: {self.consequence_text}"


class APIKey(models.Model):
    service_name = models.CharField(max_length=100, unique=True)
    key = models.TextField()

    def __str__(self):
        return self.service_name


class ScenarioBuilder(models.Model):
    # User who created the scenario
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # Name assigned to the scenario by the user
    scenario_name = models.CharField(max_length=255)

    # JSON field to store the scenario data
    scenario_data = models.JSONField()
    cost_projection = models.TextField(null=True)
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Soft deletion flag
    is_deleted = models.BooleanField(default=False)

    @property
    def organization_id(self):
        """Get the organization ID from the user's profile."""
        return self.user.userprofile.organization_id

    def __str__(self):
        return self.scenario_name


class attack_motivation(models.Model):
    attack_motivation = models.TextField(null=False)


class attack_effect(models.Model):
    attack_effect = models.TextField(null=False)


class attack_impact(models.Model):
    attack_impact = models.TextField(null=False)


class attack_motive(models.Model):
    attack_motive = models.TextField(null=False)


class ScenarioBuilder_AnalysisResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scenario = models.TextField()
    consequences = models.TextField()
    investment_impact = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class OpenAIAPILog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    datetime = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=45)
    prompt = models.TextField()
    model_used = models.CharField(max_length=30)
    temperature = models.FloatField()
    tokens_used_query = models.IntegerField()
    tokens_used_response = models.IntegerField()
    total_tokens_used = models.IntegerField()
    error_message = models.TextField(blank=True, null=True)
    status_code = models.CharField(max_length=10, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.datetime.strftime('%Y-%m-%d %H:%M:%S')}"


class UserScenarioHash(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    cyberphaID = models.IntegerField()
    hash_value = models.CharField(max_length=64)  # Assuming SHA-256 hash
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'cyberphaID', 'hash_value')


class auditlog(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_action = models.CharField(max_length=100)
    user_ipaddress = models.CharField(max_length=20)
    # Add a foreign key to UserProfile to access organization information
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    cyberPHAID = models.ForeignKey(tblCyberPHAHeader, on_delete=models.CASCADE, null=True)
    cyberPHAScenario = models.ForeignKey(tblCyberPHAScenario, on_delete=models.CASCADE, null=True)
    qraw = models.ForeignKey(RAWorksheet, on_delete=models.CASCADE, null=True)

    @property
    def organization_id(self):
        return self.user_profile.organization_id

    class Meta:
        db_table = 'tblAuditLog'

class Country(models.Model):
    id = models.AutoField(primary_key=True)
    country = models.CharField(max_length=100)

    class Meta:
        db_table = 'tblCountries'
        ordering = ['country']

    def __str__(self):
        return self.country