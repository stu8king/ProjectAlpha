from django.db import models


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
    SourceID = models.ForeignKey(MitreICSMitigations, on_delete=models.CASCADE, related_name='mitigations', db_column='SourceID')
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
    StatusFlag = models.CharField(max_length=25)
    RATrigger = models.CharField(max_length=25)
    AssessorName = models.CharField(max_length=50)
    BusinessUnit = models.CharField(max_length=50)
    BusinessUnitType = models.CharField(max_length=50)
    EmployeeCount = models.IntegerField()
    RegulatoryOversight = models.CharField(max_length=5)
    WalkdownID = models.IntegerField()
    industry = models.CharField(max_length=30)

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

    class Meta:
        db_table = 'tblRAWorksheetScenario'


class RAActions(models.Model):
    ID = models.AutoField(primary_key=True)
    RAWorksheetID = models.ForeignKey(RAWorksheet, on_delete=models.CASCADE, db_column='RAWorksheetID')
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
    ScenarioID = models.ForeignKey(RAWorksheetScenario, on_delete=models.CASCADE, db_column='ScenarioID')
    outageRequired = models.TextField()
    safetyPrecautions = models.TextField()
    environmentPrecautions = models.TextField()
    regulatoryNotifications = models.TextField()
    actionAffinity = models.TextField()

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
