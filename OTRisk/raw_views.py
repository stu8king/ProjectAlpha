import openai
import os

from django.forms import model_to_dict

from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions, MitreICSMitigations, MitreICSTechniques, \
    RawControlList
from django.contrib.auth.decorators import login_required
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.Model_CyberPHA import tblIndustry, tblThreatSources, auditlog, tblScenarios, tblCyberPHAHeader, \
    OrganizationDefaults, user_scenario_audit
from OTRisk.models.Model_Mitre import MitreICSTactics
from accounts.models import Organization, UserProfile
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from datetime import date
from django.views import View
from django.db.models import Sum, Max
from django.http import JsonResponse, HttpResponse, FileResponse
from django.shortcuts import get_object_or_404
from django.core import serializers
from django.template.loader import get_template
from django.conf import settings
import tempfile

from accounts.views import get_client_ip
from OTRisk.pha_views import get_api_key, is_inappropriate
from .forms import RAActionsForm
from xhtml2pdf import pisa
import json
import re
import requests
from .dashboard_views import get_user_organization_id
from django.http import HttpResponseForbidden
from django.contrib.auth.models import User
from .forms import RAWorksheetScenarioForm


class UpdateRAAction(View):
    def put(self, request, *args, **kwargs):
        # try:
        print(request.body)
        data = json.loads(request.body.decode('utf-8'))
        action_id = data.get('action_id')
        action_due_date = data.get('actionDueDate')
        action_status = data.get('actionStatus')
        action_title = data.get('actionTitle')
        action_description = data.get('actionDescription')
        dataMitigation = data.get('dataMitigation')
        environmentMitigation = data.get('environmentMitigation')
        financeMitigation = data.get('financeMitigation')
        lifeMitigation = data.get('lifeMitigation')
        productionMitigation = data.get('productionMitigation')
        regulationMitigation = data.get('regulationMitigation')
        reputationMitigation = data.get('reputationMitigation')
        safetyMitigation = data.get('safetyMitigation')
        supplyMitigation = data.get('supplyMitigation')
        threatMitigation = data.get('threatMitigation')
        vulnerabilityMitigation = data.get('vulnerabilityMitigation')
        closeAction = data.get('closeAction')

        ra_action = RAActions.objects.get(ID=action_id)
        ra_action.actionDueDate = action_due_date
        ra_action.actionStatus = action_status
        ra_action.actionDescription = action_description
        ra_action.actionTitle = action_title
        ra_action.dataMitigation = dataMitigation
        ra_action.environmentMitigation = environmentMitigation
        ra_action.financeMitigation = financeMitigation
        ra_action.lifeMitigation = lifeMitigation
        ra_action.productionMitigation = productionMitigation
        ra_action.regulationMitigation = regulationMitigation
        ra_action.reputationMitigation = reputationMitigation
        ra_action.safetyMitigation = safetyMitigation
        ra_action.supplyMitigation = supplyMitigation
        ra_action.threatMitigation = threatMitigation
        ra_action.vulnerabilityMitigation = vulnerabilityMitigation
        current_user_name = request.user.first_name + " " + request.user.last_name
        history_update = f"\n\n{timezone.now()}: {current_user_name} updated the record "
        ra_action.history += history_update
        ra_action.save()

        return JsonResponse({'success': True})

    # except Exception as e:
    #    return JsonResponse({'success': False, 'error': str(e)})


@login_required()
def ra_actions_view(request, qraw_id=None, pha_id=None):
    selected_action = None
    ra_title = None  # This will store the RATitle or the record from tblCyberPHAHeader

    if request.method == 'POST':
        action_id = request.POST.get('action_id')
        if action_id:
            try:
                selected_action = RAActions.objects.get(ID=action_id)

                # Check RAWorksheetID and retrieve RATitle
                if selected_action.RAWorksheetID_id != 0:
                    ra_worksheet = RAWorksheet.objects.get(ID=selected_action.RAWorksheetID_id)
                    ra_title = ra_worksheet.RATitle

                # Check phaID and retrieve the record from tblCyberPHAHeader
                elif selected_action.phaID != 0:
                    ra_title = tblCyberPHAHeader.objects.get(ID=selected_action.phaID)

            except (RAActions.DoesNotExist, RAWorksheet.DoesNotExist, tblCyberPHAHeader.DoesNotExist):
                pass

    # Get the organization_id of the current user
    current_user_organization_id = request.user.userprofile.organization_id

    # Filter RAActions based on the provided parameters
    if qraw_id and isinstance(qraw_id, int) and qraw_id > 0:
        ra_actions = RAActions.objects.filter(organizationid=current_user_organization_id, RAWorksheetID=qraw_id)
    elif pha_id and isinstance(pha_id, int) and pha_id > 0:
        ra_actions = RAActions.objects.filter(organizationid=current_user_organization_id, phaID=pha_id)
    else:
        ra_actions = RAActions.objects.filter(organizationid=current_user_organization_id)

    context = {
        'ra_actions': ra_actions,
        'selected_action': selected_action,
        'ra_title': ra_title
        # This will be passed to the template to display the RATitle or the record from tblCyberPHAHeader
    }
    return render(request, 'OTRisk/ra_actions_template.html', context)


def get_rawactions(request):
    raw_id = request.GET.get('raw_id', None)
    rawactions = RAActions.objects.filter(RAWorksheetID=raw_id)

    # Convert the QuerySet to a list of dictionaries
    rawactions_list = [{
        'ID': action.ID,
        'actionTitle': action.actionTitle,
        'actionDescription': action.actionDescription,
        'actionStatus': action.actionStatus,
        'actionPriority': action.actionPriority,
        'actionOwner': action.actionOwner,
        # Add more fields as needed
    } for action in rawactions]

    return JsonResponse(rawactions_list, safe=False)


def save_ra_action(request):
    if request.method == "POST":
        # Extract data from POST request
        action_title = request.POST.get('actionTitle')
        action_owner = request.POST.get('actionOwner')
        action_date = request.POST.get('actionDate')
        action_effort = request.POST.get('actionEffort')
        action_difficulty = request.POST.get('actionDifficulty')
        action_cost = request.POST.get('actionCost')
        action_affinity = request.POST.get('actionAffinity')
        action_status = request.POST.get('actionStatus')
        action_description = request.POST.get('actionDescription')
        action_due_date = request.POST.get('actionDueDate')
        action_priority = request.POST.get('actionPriority')
        outageSIS = request.POST.get('outageSIS')
        outageICS = request.POST.get('outageICS')
        outageEMS = request.POST.get('outageEMS')
        outageIT = request.POST.get('outageIT')
        outagePS = request.POST.get('outagePS')
        outageWWW = request.POST.get('outageWWW')
        environmentMitigation = request.POST.get('environmentMitigation')
        financeMitigation = request.POST.get('financeMitigation')
        lifeMitigation = request.POST.get('lifeMitigation')
        productionMitigation = request.POST.get('productionMitigation')
        regulationMitigation = request.POST.get('regulationMitigation')
        reputationMitigation = request.POST.get('reputationMitigation')
        dataMitigation = request.POST.get('dataMitigation')
        safetyMitigation = request.POST.get('safetyMitigation')
        supplyMitigation = request.POST.get('supplyMitigation')
        threatMitigation = request.POST.get('threatMitigation')
        vulnerabilityMitigation = request.POST.get('vulnerabilityMitigation')
        phaID = int(request.POST.get('hdnphaID'))
        RAWorksheetID = int(request.POST.get('hdntxtModalRAW'))
        current_user_organization_id = request.user.userprofile.organization_id
        current_user = request.user
        organization_instance = Organization.objects.get(pk=current_user_organization_id)

        # create a history record
        history = f"User {request.user} saved {action_title} at {timezone.now()}"

        ra_worksheet_instance = RAWorksheet.objects.get(pk=RAWorksheetID)
        # Create a new RAActions record
        ra_action = RAActions(
            actionTitle=action_title,
            actionOwner=action_owner,
            actionDate=action_date,
            actionEffort=action_effort,
            actionDifficulty=action_difficulty,
            actionCost=action_cost,
            actionStatus=action_status,
            actionDescription=action_description,
            actionDueDate=action_due_date,
            actionPriority=action_priority,
            actionAssets='',
            actionAffinity=action_affinity,
            outageSIS=outageSIS,
            outageICS=outageICS,
            outageEMS=outageEMS,
            outageIT=outageIT,
            outagePS=outagePS,
            outageWWW=outageWWW,
            RAWorksheetID=ra_worksheet_instance,
            phaID=phaID,
            userid=request.user,
            organizationid=organization_instance,
            history=history,
            dataMitigation=dataMitigation,
            environmentMitigation=environmentMitigation,
            financeMitigation=financeMitigation,
            lifeMitigation=lifeMitigation,
            regulationMitigation=regulationMitigation,
            productionMitigation=productionMitigation,
            reputationMitigation=reputationMitigation,
            safetyMitigation=safetyMitigation,
            supplyMitigation=supplyMitigation,
            threatMitigation=threatMitigation,
            vulnerabilityMitigation=vulnerabilityMitigation
        )
        ra_action.save()

        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error"})


@csrf_exempt
def raw_from_walkdown(request):
    if request.method == 'POST':
        cyberPHAID = request.POST.get('cyberPHAID')
        questionID = request.POST.get('questionID')
        walkdownQuestion = request.POST.get('walkdownQuestion')
        facility = request.POST.get('facility')
        facilityType = request.POST.get('facilityType')
        facilityIndustry = request.POST.get('facilityIndustry')

        # Create a new record
        ra_worksheet = RAWorksheet(
            cyberPHAID=cyberPHAID,
            RATitle=f'WALKDOWN - Q: {questionID}: {walkdownQuestion}',
            StatusFlag='Open',
            RATrigger='Site Visit/Walkdown',
            RADescription=walkdownQuestion,
            AssessorName=request.user,
            BusinessUnit=facility,
            BusinessUnitType=facilityType,
            industry=facilityIndustry
        )
        ra_worksheet.save()

        return JsonResponse({'status': 'success', 'message': 'Record created successfully'})


@login_required()
def rawreport(request, raworksheet_id):
    # Fetch the RAWorksheet and associated scenarios
    org_id = get_user_organization_id(request)

    raworksheet = get_object_or_404(RAWorksheet, pk=raworksheet_id)
    # if the user is attempting to access a report that belongs to a different organization by changing the url value then exit with a generic warning
    if org_id != raworksheet.organization_id:
        return HttpResponseForbidden("Unauthorized Action.")

    scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=raworksheet)

    total_scenario_cost = scenarios.aggregate(Sum('scenarioCost'))['scenarioCost__sum']
    if total_scenario_cost is None:
        total_scenario_cost = 0
    formatted_cost = "${:,.2f}".format(total_scenario_cost)

    total_event_cost_high = scenarios.aggregate(Sum('event_cost_high'))['event_cost_high__sum']
    if total_event_cost_high is None:
        total_event_cost_high = 0
    formatted_total_event_cost_high = "${:,.2f}".format(total_event_cost_high)

    total_event_cost_low = scenarios.aggregate(Sum('event_cost_low'))['event_cost_low__sum']
    if total_event_cost_low is None:
        total_event_cost_low = 0
    formatted_total_event_cost_low = "${:,.2f}".format(total_event_cost_low)

    total_event_cost_median = scenarios.aggregate(Sum('event_cost_median'))['event_cost_median__sum']
    if total_event_cost_median is None:
        total_event_cost_median = 0
    formatted_total_event_cost_median = "${:,.2f}".format(total_event_cost_median)

    # Get the highest riskScore
    highest_risk_score = scenarios.aggregate(Max('RiskScore'))['RiskScore__max']

    risk_status = get_risk_status(highest_risk_score)

    safety_status = get_risk_status(scenarios.aggregate(Max('SafetyScore'))['SafetyScore__max'])
    life_status = get_risk_status(scenarios.aggregate(Max('lifeScore'))['lifeScore__max'])
    environment_status = get_risk_status(scenarios.aggregate(Max('environmentScore'))['environmentScore__max'])
    operational_status = get_risk_status(scenarios.aggregate(Max('productionScore'))['productionScore__max'])
    regulatory_status = get_risk_status(scenarios.aggregate(Max('regulatoryScore'))['regulatoryScore__max'])
    financial_status = get_risk_status(scenarios.aggregate(Max('FinancialScore'))['FinancialScore__max'])
    data_status = get_risk_status(scenarios.aggregate(Max('DataScore'))['DataScore__max'])
    reputation_status = get_risk_status(scenarios.aggregate(Max('ReputationScore'))['ReputationScore__max'])
    supplychain_status = get_risk_status(scenarios.aggregate(Max('SupplyChainScore'))['SupplyChainScore__max'])

    safety_score_total = scenarios.aggregate(Max('SafetyScore'))['SafetyScore__max']
    life_score_total = scenarios.aggregate(Max('lifeScore'))['lifeScore__max']
    environment_score_total = scenarios.aggregate(Max('environmentScore'))['environmentScore__max']
    operational_score_total = scenarios.aggregate(Max('productionScore'))['productionScore__max']
    regulatory_score_total = scenarios.aggregate(Max('regulatoryScore'))['regulatoryScore__max']
    financial_score_total = scenarios.aggregate(Max('FinancialScore'))['FinancialScore__max']
    data_score_total = scenarios.aggregate(Max('DataScore'))['DataScore__max']
    reputation_score_total = scenarios.aggregate(Max('ReputationScore'))['ReputationScore__max']
    supplychain_score_total = scenarios.aggregate(Max('SupplyChainScore'))['SupplyChainScore__max']

    referer = request.META.get('HTTP_REFERER', '')

    if 'reports' in referer:
        # If the calling template is report.html, return a JsonResponse
        return JsonResponse({
            'safety_score_total': safety_score_total,
            'life_score_total': life_score_total,
            'environment_score_total': environment_score_total,
            'operational_score_total': operational_score_total,
            'regulatory_score_total': regulatory_score_total,
            'financial_score_total': financial_score_total,
            'data_score_total': data_score_total,
            'reputation_score_total': reputation_score_total,
            'supplychain_score_total': supplychain_score_total,
            'raworksheet': model_to_dict(raworksheet),
            'scenarios': list(scenarios.values()),
            'formatted_cost': formatted_cost,
            'risk_status': risk_status,
            'safety_status': safety_status,
            'life_status': life_status,
            'environment_status': environment_status,
            'operational_status': operational_status,
            'regulatory_status': regulatory_status,
            'financial_status': financial_status,
            'data_status': data_status,
            'reputation_status': reputation_status,
            'supplychain_status': supplychain_status,
            'total_event_cost_high': total_event_cost_high,
            'total_event_cost_low': total_event_cost_low,
            'total_event_cost_median': total_event_cost_median
        })
    else:
        return render(request, 'rawreport.html',
                      {'raworksheet': raworksheet,
                       'scenarios': scenarios,
                       'formatted_cost': formatted_cost,
                       'risk_status': risk_status,
                       'safety_status': safety_status,
                       'life_status': life_status,
                       'environment_status': environment_status,
                       'operational_status': operational_status,
                       'regulatory_status': regulatory_status,
                       'financial_status': financial_status,
                       'data_status': data_status,
                       'reputation_status': reputation_status,
                       'supplychain_status': supplychain_status,
                       'total_event_cost_high': total_event_cost_high,
                       'total_event_cost_low': total_event_cost_low,
                       'total_event_cost_median': total_event_cost_median})


def get_risk_status(risk_score):
    if risk_score in [1, 2]:
        return "Low"
    elif risk_score in [3, 4]:
        return "Low/Medium"
    elif risk_score in [5, 6]:
        return "Medium"
    elif risk_score in [7, 8]:
        return "Medium/High"
    elif risk_score == 9:
        return "High"
    elif risk_score == 10:
        return "Very High"
    else:
        return "Unknown"


def parse_currency(currency_string):
    """Parse a currency string and return its integer value."""
    # Remove any non-digit characters
    sanitized_string = re.sub(r'[^\d]', '', currency_string)

    # Check if the sanitized string is empty
    if not sanitized_string:
        return 0

    # Convert the sanitized string to an integer
    return int(sanitized_string)


def ensure_non_empty(value):
    """Return the value if non-empty, otherwise return 0."""
    return value if value != '' else 0


def ensure_non_null(value):
    """Return the value if non-empty, otherwise return 0."""
    return value if value != '' else '.'


@login_required()
def reports(request):
    referrer = request.META.get('HTTP_REFERER')
    if not referrer or 'expected_referrer_path' not in referrer:
        return HttpResponseForbidden()
    org_id = get_user_organization_id(request)
    qraw_reports = RAWorksheet.objects.filter(organization_id=org_id)
    organization_id_from_session = request.session.get('user_organization')
    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)
    pha_reports = tblCyberPHAHeader.objects.filter(UserID__in=users_in_organization)

    return render(request, 'report.html',
                  {'qraw_reports': qraw_reports,
                   'pha_reports': pha_reports})


@login_required()
def reports_pha(request):
    org_id = get_user_organization_id(request)
    organization_id_from_session = request.session.get('user_organization')
    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)
    pha_reports = tblCyberPHAHeader.objects.filter(UserID__in=users_in_organization, Deleted=0)

    return render(request, 'report_pha.html',
                  {'pha_reports': pha_reports})


def calculate_business_impact_score(ra_worksheet_id):
    try:
        # Retrieve the RAWorksheet with the given ID
        ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)
        organization = ra_worksheet.organization_id
        org_defaults = OrganizationDefaults.objects.get(organization=organization)

        # Define the weights for each field
        field_weights = {
            'ReputationScore': org_defaults.impact_weight_reputation,
            'SafetyScore': org_defaults.impact_weight_safety,
            'lifeScore': org_defaults.impact_weight_danger,
            'FinancialScore': org_defaults.impact_weight_finance,
            'DataScore': org_defaults.impact_weight_data,
            'SupplyChainScore': org_defaults.impact_weight_supply,
            'productionScore': org_defaults.impact_weight_production,
            'environmentScore': org_defaults.impact_weight_environment,
            'regulatoryScore': org_defaults.impact_weight_regulation,
        }

        # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
        scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=ra_worksheet)

        # Initialize variables for total weighted score
        total_weighted_score = 0
        total_scenarios = 0

        # Calculate the total weighted score for each scenario
        for scenario in scenarios:
            scenario_weighted_score = 0
            for field, weight in field_weights.items():
                # Get the value of the field from the scenario
                field_value = getattr(scenario, field, 0)
                # Convert it to a numeric score (assuming it's an integer out of 10)
                numeric_score = int(field_value)
                # Add the weighted score to the scenario weighted score
                scenario_weighted_score += numeric_score * weight

            # Add the scenario weighted score to the total weighted score
            total_weighted_score += scenario_weighted_score
            total_scenarios += 1

        # Calculate the average weighted score per scenario
        if total_scenarios > 0:
            average_weighted_score_per_scenario = total_weighted_score / total_scenarios
        else:
            return 0

        # Normalize the average weighted score out of 100
        max_weighted_score = 10 * sum(field_weights.values())
        normalized_total_score = (average_weighted_score_per_scenario / max_weighted_score) * 100

        return normalized_total_score

    except RAWorksheet.DoesNotExist:
        return None


def calculate_total_risk_score(ra_worksheet_id):
    try:
        # Retrieve the RAWorksheet with the given ID
        ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)

        # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
        scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=ra_worksheet)

        # Initialize variables for total risk score and scenario count
        total_risk_score = 0
        scenario_count = 0

        # Sum the risk score of each scenario and count the scenarios
        for scenario in scenarios:
            total_risk_score += getattr(scenario, 'RiskScore', 0)
            scenario_count += 1

        # Calculate the average risk score
        if scenario_count > 0:
            average_risk_score = total_risk_score / scenario_count
        else:
            return 0

        # Ensure the average risk score does not exceed 10
        total_risk_score = min(average_risk_score, 10)

        return total_risk_score

    except RAWorksheet.DoesNotExist:
        return None


def map_score_to_text(score):
    if score < 20:
        return 'Low'
    elif score < 40:
        return 'Low/Medium'
    elif score < 60:
        return 'Medium'
    elif score < 80:
        return 'Medium/High'
    elif score < 95:
        return 'High'
    else:
        return 'Very High'


def map_riskscore_to_text(score):
    if score < 2:
        return 'Low'
    elif score < 4:
        return 'Low/Medium'
    elif score < 6:
        return 'Medium'
    elif score < 8:
        return 'Medium/High'
    elif score < 9:
        return 'High'
    else:
        return 'Very High'


@login_required
def qraw(request):
    # check the organization that the user belong to
    org_id = get_user_organization_id(request)
    saved_worksheet_id = None
    # get organization defaults
    try:
        # Assuming org_id is already defined
        org_defaults = OrganizationDefaults.objects.get(organization_id=org_id)
        industry_id = org_defaults.industry_id  # Access the industry_id field
    except OrganizationDefaults.DoesNotExist:
        # Handle the case where no OrganizationDefaults is found for the given org_id
        industry_id = None

    if request.method == 'POST':

        # Check for duplicate records
        is_duplicate = RAWorksheet.objects.filter(
            organization_id=org_id,
            RATitle=request.POST.get('txtTitle'),
            BusinessUnit=request.POST.get('txtBU'),
            AssessorName=request.POST.get('txtLeader'),
            industry=request.POST.get('selectIndustry'),
            BusinessUnitType=request.POST.get('selectFacility'),
            RATrigger=request.POST.get('selectTrigger'),
        ).exists()

        edit_mode_value = request.POST.get('edit_mode', 0)
        edit_mode = 1 if edit_mode_value == '' else int(edit_mode_value)

        hdnRawID_value = request.POST.get('hdnRawID', ['0'])[0]  # Take the first value if list, default to '0'
        hdnRawID = int(hdnRawID_value)

        if edit_mode == 0 or hdnRawID == 0:

            if not is_duplicate:
                # adding new records
                revenue_str = ensure_non_empty(request.POST.get('txtRevenue'))
                revenue_cleaned = revenue_str.replace(',', '').replace('$', '')
                revenue_int = int(revenue_cleaned)

                insurance_str = ensure_non_empty(request.POST.get('txtInsurance'))
                insurance_cleaned = insurance_str.replace(',', '').replace('$', '')
                insurance_int = int(insurance_cleaned)

                deductable_str = ensure_non_empty(request.POST.get('txtDeductable'))
                deductable_cleaned = deductable_str.replace(',', '').replace('$', '')
                deductable_int = int(deductable_cleaned)

                ra_worksheet = RAWorksheet(
                    RATitle=request.POST.get('txtTitle'),
                    BusinessUnit=request.POST.get('txtBU'),
                    AssessorName=request.POST.get('txtLeader'),
                    industry=request.POST.get('selectIndustry'),
                    BusinessUnitType=request.POST.get('selectFacility'),
                    RATrigger=request.POST.get('selectTrigger'),
                    revenue=revenue_int,
                    insurance=insurance_int,
                    deductable=deductable_int,
                    UserID=request.user.id,
                    organization_id=org_id,
                    WalkdownID=0,
                    StatusFlag="Open",
                    RADate=date.today(),
                    deleted=0
                )
                ra_worksheet.save()
                saved_worksheet_id = ra_worksheet.ID

        elif edit_mode == 1:

            ra_worksheet_id = int(request.POST.get('hdnRawID'))
            ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)
            ra_worksheet.RATitle = request.POST.get('txtTitle')
            ra_worksheet.BusinessUnit = request.POST.get('txtBU')
            ra_worksheet.AssessorName = request.POST.get('txtLeader')
            ra_worksheet.industry = request.POST.get('selectIndustry')
            ra_worksheet.BusinessUnitType = request.POST.get('selectFacility')
            ra_worksheet.RATrigger = request.POST.get('selectTrigger')
            ra_worksheet.insurance = parse_currency(request.POST.get('txtInsurance'))
            ra_worksheet.revenue = parse_currency(request.POST.get('txtRevenue'))
            ra_worksheet.deductable = parse_currency(request.POST.get('txtDeductable'))
            ra_worksheet.save()
            saved_worksheet_id = ra_worksheet.ID

    raws = RAWorksheet.objects.filter(organization_id=org_id, deleted=0)

    # Loop through the raws queryset and calculate business impact scores
    for raw in raws:
        # Assuming the RAWorksheet ID is stored in the 'ID' attribute of the raw object
        worksheet_id = raw.ID

        # Calculate the business impact score for the current RAWorksheet
        business_impact_score = calculate_business_impact_score(worksheet_id)
        total_risk_score = calculate_total_risk_score(worksheet_id)

        # Add the business_impact_score to the raw object as a new attribute
        raw.business_impact_score = business_impact_score
        raw.total_risk_score = total_risk_score

        # Loop through the raws queryset and calculate business impact scores
    for raw in raws:
        # Assuming the business impact score is stored in the 'business_impact_score' attribute
        business_impact_score = raw.business_impact_score
        total_risk_score = raw.total_risk_score
        # Map the numeric score to the corresponding text value
        bia_text = map_score_to_text(business_impact_score)
        risk_text = map_riskscore_to_text(total_risk_score)
        # Add the 'bia_text' field to the raw object
        raw.bia_text = bia_text
        raw.risk_text = risk_text

    facilities = FacilityType.objects.all().order_by('FacilityType')
    industries = tblIndustry.objects.all().order_by('Industry')
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    mitreTactics = MitreICSTactics.objects.all().order_by('tactic')
    mitreMitigations = MitreICSMitigations.objects.all().order_by('id')

    # scenarios = tblScenarios.objects.filter(industry_id=industry_id).order_by('Scenario')
    scenario_form = RAWorksheetScenarioForm()

    return render(request, 'qraw.html',
                  {'raws': raws,
                   'facilities': facilities,
                   'industries': industries,
                   'threatsources': threatsources,
                   'mitreTactics': mitreTactics,
                   'mitreMitigations': mitreMitigations,
                   # 'scenarios': scenarios,
                   'scenario_form': scenario_form,
                   'saved_worksheet_id': saved_worksheet_id,
                   'org_defaults': org_defaults})


class GetTechniquesView(View):
    def get(self, request, *args, **kwargs):
        mitigation_ids = request.GET.getlist('mitigation_id[]', None)

        if mitigation_ids:
            techniques = MitreICSTechniques.objects.filter(SourceID__in=mitigation_ids).values('ID', 'TargetName')
            techniques_list = list(techniques)
            return JsonResponse(techniques_list, safe=False)
        else:
            return JsonResponse({"error": "No mitigation ID provided"}, status=400)


# Function to assess the risk using the OpenAI GPT-3 API
def openai_assess_risk(request):
    language = request.session.get('organization_defaults', {}).get('language', 'en')  # 'en' is the default value
    if request.method == 'GET':
        openai.api_key = get_api_key('openai')

        # Extracting the input variables from the request
        safety_impact = int(request.GET.get('safety_impact'))
        life_impact = int(request.GET.get('life_impact'))
        production_impact = int(request.GET.get('production_impact'))
        financial_impact = int(request.GET.get('financial_impact'))
        reputation_impact = int(request.GET.get('reputation_impact'))
        environment_impact = int(request.GET.get('environment_impact'))
        regulatory_impact = int(request.GET.get('regulatory_impact'))
        data_impact = int(request.GET.get('data_impact'))
        supply_impact = int(request.GET.get('supply_impact'))
        threat_source = request.GET.get('threat_source')
        threat_tactic = request.GET.get('threat_tactic')
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        asset_status = int(request.GET.get('assetStatus'))
        vulnerability = int(request.GET.get('vulnerability_exposure'))
        revenue = parse_currency(request.GET.get('revenue'))
        insurance = parse_currency(request.GET.get('insurance'))
        deductable = parse_currency(request.GET.get('deductable'))
        outage = request.GET.get('outage')
        outageLength = request.GET.get('outageLength')
        exposed_system = request.GET.get('exposed_system')
        weak_credentials = request.GET.get('weak_credentials')
        consequences = request.GET.get('consequences')

        if outageLength and outageLength.isdigit():
            outageLength = int(outageLength)
        else:
            outageLength = 0

        impact = request.GET.get('impact')
        controlScore = request.GET.get('controlScore')

        ASSET_STATUS_MAPPING = {
            1: "New / Hardened",
            2: "New / Hardened",
            3: "Current / Managed",
            4: "Current / Managed",
            5: "Aging / Supported",
            6: "Aging / Supported",
            7: "Legacy / Unmanaged",
            8: "Legacy / Unmanaged",
            9: "Obsolete",
            10: "Obsolete"
        }

        asset_lc = ASSET_STATUS_MAPPING.get(asset_status, "Unknown status")

        # Assuming all the variables (threat_source, threat_tactic, scenario, etc.) are already defined
        content = "Outage information not provided."

        if outage == "Yes":
            content = f"The scenario is expected to result in a production outage of {outageLength}."
        elif outage == "No":
            content = "The scenario is not expected to result in a production outage."

        system_message = {
            "role": "system",
            "content": f"You are an OT Cybersecurity Risk expert and an expert in industrial system engineering. Make a risk assessment for {scenario} in a {facility_type} in the {industry} industry. Vulnerability has been rated as {vulnerability}. Annual revenue for the business is {revenue}. Cyber insurance cover to the value of {insurance} and the cyber insurance deductible is {deductable}. {content}"
        }

        def query_openai(user_message_content):

            # Convert dictionary content to string format if necessary
            if isinstance(user_message_content, dict):
                prompt_parts = []
                for key, value in user_message_content.items():
                    if isinstance(value, dict):
                        sub_parts = [f"{sub_key}: {sub_value}" for sub_key, sub_value in value.items()]
                        prompt_parts.append(f"{key} - {'; '.join(sub_parts)}")
                    else:
                        prompt_parts.append(f"{key}: {value}")
                formatted_content = ". ".join(prompt_parts)
            else:
                formatted_content = user_message_content

            user_message = {
                "role": "user",
                "content": formatted_content
            }
            messages = [system_message, user_message]
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=messages,
                temperature=0.1,
                max_tokens=250
            )
            return response['choices'][0]['message']['content'].strip()

        # 1. Query for risk rating

        # Message to query the overall risk rating
        risk_rating_message = {
            "role": "user",
            "content": (
                f"Threat source - {threat_source}, Threat tactic - {threat_tactic}, vulnerability exposure rating -{vulnerability}/10, "
                f"Safety impact - {safety_impact}/10, Life impact - {life_impact}/10, Production impact - {production_impact}/10, "
                f"Financial impact - {financial_impact}/10, Environmental impact - {environment_impact}/10, Regulatory impact - {regulatory_impact}/10, "
                f"Reputation impact - {reputation_impact}/10, Data impact - {data_impact}/10, Supply Chain Impact- {supply_impact}/10, "
                f"Weak credentials: {weak_credentials}, Internet exposed IP address: {exposed_system}."
                f"The probable consequences of the scenario are: {consequences}."
                f"Provide a rating for the risk from one of the following possible responses: Low, Low/Medium, Medium, Medium/High, or High. The response must be only the single response with no additional text or explanation. The user must only see the final response without any other detail  ")
        }

        # 2. Query for risk score
        risk_score_message = {
            "role": "user",
            "content": (
                f"Considering the detailed factors about a cybersecurity incident scenario: Threat source - {threat_source}, Threat tactic - {threat_tactic}, vulnerability exposure rated as {vulnerability}/10 "
                f"Safety impact - {safety_impact}/10, Life impact - {life_impact}/10, Production impact - {production_impact}/10, "
                f"Financial impact - {financial_impact}/10, Reputation impact - {reputation_impact}/10, Environmental impact - {environment_impact}/10, "
                f"Regulatory impact - {regulatory_impact}/10, Data impact - {data_impact}/10, , Supply Chain - {supply_impact}/10 and the scenario of {scenario} "
                f"in a {facility_type} within the {industry} industry, provide a risk score between 1 and 10 where 1 indicates a very low overall risk with a very low likelihood of occurrence and 10 means catastrophic consequences and almost certain to occur. The response must be only the single number with no additional text or explanation. The user must only see the final risk score number without any other detail")
        }

        # 3. Query for low estimate
        # Base content for both low and high estimates

        event_cost_estimate_message = {
            "role": "user",
            "content": (
                f" Estimate the DIRECT COSTS of a single loss event (SLE) in US dollars for the scenario: {scenario}. Provide figures as lowest|highest|median. Business impact assessment as follows:"
                f"- Operations impact : {production_impact} out of 10."
                f" - Production outage: {outage}."
                f" - Length of production outage: {outageLength} hours."
                f"- Safety impact: {safety_impact} out of 10."
                f"- Supply Chain Impact: {supply_impact} out of 10."
                f"- Financial Impact: {financial_impact} out of 10."
                f"- Data Impact: {data_impact} out of 10."
                f"- Reputation Impact: {reputation_impact} out of 10."
                f"- Regulatory Impact: {regulatory_impact} out of 10."
                f"- Danger to life Impact: {life_impact} out of 10."
                f"If the estimates exceed the insurance deductable amount then deduct the insurance coverage amount from the estimates otherwise ignore the insurance amounts. "
                f"Guidelines: Give three estimates best case, worst case, and most likely case. Output as integers in the format low|medium|high where | is the delimiter between the three integer values. Your estimates should be realistic and specific to the scenario. Consider only the relevant Direct costs which can include all or some of the following depending on the incident: incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums."
                f"Give the answer in the format lowest|highest|median using | as the character to indicate the delimiter between the values."
                f"Provide only the dollar amount values in your response without any narrative or explanation because the response from this query will be used in a calculation."
            )
        }

        # 5. Query for risk summary
        # Structured Input for the Model
        risk_factors = {
            "vulnerability_score": {
                "value": vulnerability,
                "max_value": 10,
                "context": "A score indicating the level of system vulnerability, where 10 is the most vulnerable."
            },
            "industry_type": {
                "value": industry,
                "context": "The specific industry the system operates in, which can influence risk due to industry-specific threats."
            },
            "facility_type": facility_type,
            "threat_source": threat_source,
            "threat_tactic": threat_tactic,
            "Scenario to be evaluated": scenario,
            "impact_scores (1 is low and 10 is high)": {
                "safety": safety_impact,
                "life": life_impact,
                "production": production_impact,
                "financial": financial_impact,
                "reputation": reputation_impact,
                "environment": environment_impact,
                "regulatory": regulatory_impact,
                "data": data_impact,
                "supply_chain": supply_impact
            }
        }

        try:
            controlScoreValue = int(controlScore)
        except ValueError:  # This will catch if controlScore is not a valid integer (e.g., NaN)
            controlScoreValue = 0

        if controlScoreValue > 0:
            risk_summary = 'x'
        else:
            risk_summary_message = {
                "role": "user",
                "content": dict(
                    prompt=(
                        f"From the scenario {scenario} and following variables: Weak Credentials: {weak_credentials}, Internet exposed IP address {exposed_system}, threat source {threat_source}, threat tactics {threat_tactic} make a concise bullet point list of the most relevant and OT (operational technology) and ICS (industrial control system) technical and physical controls and configurations necessary to mitigate or avoid the risks:\n"
                        f"Controls should be technical and focused on mitigating risks most relevant to OT Cybersecurity. If a specific device, PLC, software, or equipment is named in the scenario, give controls specific to the device, PLC, software, or equipment. Controls must be pragmatic, practical and realistic to implement at a {facility_type}, should align to NIST 800-82 standards and/or vendor published controls for the specific device, plc, software, or equipment. Each control should be accompanied with the cited reference code for the related control in the standards or vendor material"
                    ),
                    additional_request={
                        "formatting": f"Place line breaks between lines. No more than 10 words per bullet point. No extra commentary or explanation. Give the response in language {language}"
                    }
                )
            }

            risk_summary = query_openai(risk_summary_message['content'])

        ###############################
        # risk rating
        system_content = system_message['content'] if isinstance(system_message['content'], str) else ""
        risk_rating_content = risk_rating_message['content'] if isinstance(
            risk_rating_message['content'], str) else ""

        combined_message = system_content + ' ' + risk_rating_content

        risk_rating = query_openai(combined_message)
        ###############################
        ###############################

        risk_score = query_openai(risk_score_message['content'])

        ###############################
        # event costs
        system_content = system_message['content'] if isinstance(system_message['content'], str) else ""
        event_cost_content = event_cost_estimate_message['content'] if isinstance(
            event_cost_estimate_message['content'], str) else ""

        combined_message = system_content + ' ' + event_cost_content

        event_cost_estimate = query_openai(combined_message)
        ###############################
        ###############################

        # risk_summary = query_openai(risk_summary_message['content'])
        risk_summary_array = parse_risk_summary(risk_summary) if risk_summary != 'x' else []
        values = event_cost_estimate.split('|')
        low_estimate, high_estimate, median_estimate = values

        # Return the results
        result_array = [risk_rating, risk_score, low_estimate, high_estimate, risk_summary, median_estimate,
                        risk_summary_array]
        return JsonResponse(result_array, safe=False)


def parse_risk_summary(risk_summary):
    # Split the string by newline
    lines = risk_summary.split('\n')

    # Remove the bullet symbol and any leading/trailing whitespace from each line
    parsed_lines = [line.replace('-', '').strip() for line in lines if line.strip() != '']

    return parsed_lines


def write_to_audit(user_id, user_action, user_ip):
    try:
        user_profile = UserProfile.objects.get(user=user_id)

        audit_log = auditlog(
            user=user_id,
            timestamp=timezone.now(),
            user_action=user_action,
            user_ipaddress=user_ip,
            user_profile=user_profile
        )
        audit_log.save()
    except UserProfile.DoesNotExist:
        # Handle the case where UserProfile does not exist for the user
        pass


def raw_action(request):
    if request.method == "POST":
        RAWorksheetID = request.POST.get('hdnRAWorksheetID')
        actionTitle = request.POST.get('actionTitle')
        if RAActions.objects.filter(RAWorksheetID=RAWorksheetID, actionTitle=actionTitle).exists():
            RAWorksheetID = RAWorksheet.objects.get(ID=RAWorksheetID)
            existing_action = RAActions.objects.get(RAWorksheetID=RAWorksheetID, actionTitle=actionTitle)
            existing_action.RAWorksheetID = RAWorksheetID
            existing_action.actionTitle = request.POST.get('actionTitle')
            existing_action.actionOwner = request.POST.get('actionOwner')
            existing_action.actionDate = request.POST.get('actionDate')
            existing_action.actionEffort = request.POST.get('actionEffort')
            existing_action.actionDifficulty = request.POST.get('actionDifficulty')
            existing_action.actionCost = request.POST.get('actionCost')
            existing_action.actionDescription = request.POST.get('actionDescription')
            existing_action.actionDueDate = request.POST.get('dueDate')
            existing_action.actionAssets = request.POST.get('actionAssets')
            existing_action.outageRequired = request.POST.get('actionOutageYesNo')
            existing_action.safetyPrecautions = request.POST.get('safetyPrecautions')
            existing_action.environmentPrecautions = request.POST.get('environmentPrecautions')
            existing_action.regulatoryNotifications = request.POST.get('actionRegsYesNo')
            existing_action.actionAffinity = request.POST.get('actionEffective')
            existing_action.save()

        else:
            RAWorksheetID = RAWorksheet.objects.get(ID=request.POST.get('hdnRAWorksheetID'))

            # add new
            new_action = RAActions(
                RAWorksheetID=RAWorksheetID,
                actionTitle=request.POST.get('actionTitle'),
                actionOwner=request.POST.get('actionOwner'),
                actionDate=request.POST.get('actionDate'),
                actionEffort=request.POST.get('actionEffort'),
                actionDifficulty=request.POST.get('actionDifficulty'),
                actionCost=request.POST.get('actionCost'),
                actionDescription=request.POST.get('actionDescription'),
                actionDueDate=request.POST.get('dueDate'),
                actionAssets=request.POST.get('actionAssets'),
                outageRequired=request.POST.get('actionOutageYesNo'),
                safetyPrecautions=request.POST.get('safetyPrecautions'),
                environmentPrecautions=request.POST.get('environmentPrecautions'),
                regulatoryNotifications=request.POST.get('actionRegsYesNo'),
                actionAffinity=request.POST.get('actionEffective'),
            )
            new_action.save()

    raw_actions = RAActions.objects.all()
    return render(request, 'raw_action.html', {
        'raw_actions': raw_actions
    })


def get_action(request):
    action_id = request.GET.get('action_id')
    action = get_object_or_404(RAActions, id=action_id)

    # create a dictionary with the action data
    action_data = {
        'actionTitle': action.actionTitle,
        # add other fields...
    }

    return JsonResponse(action_data)


def check_vulnerabilities(request):
    if request.method == 'POST':
        # Parse the JSON data from the request body
        body_unicode = request.body.decode('utf-8')
        body_data = json.loads(body_unicode)

        vendor = body_data.get('vendor')
        product = body_data.get('product')

        # Construct the keyword search string
        keyword_search = f"{vendor} {product}"

        # Query the NVD API using the keywordSearch parameter
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword_search,
            "resultsPerPage": 50  # You can adjust this as needed
        }
        response = requests.get(base_url, params=params)
        data = response.json()

        # Extract vulnerabilities from the response
        vulnerabilities = []
        for item in data.get('result', {}).get('CVE_Items', []):
            vulnerabilities.append({
                'id': item.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                'description': item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value',
                                                                                                               ''),
                'severity': item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', '')
            })

        # Return a structured JSON response
        return JsonResponse({
            'asset': f"{vendor} {product}",
            'vulnerabilities': vulnerabilities
        })


def safety_definition(input_number):
    safety_definitions = {
        1: "Minimal safety impact. Cybersecurity has a minor effect on safety, with small risks to people, well-being, or the environment. Little danger of significant harm",
        2: "Slight to manageable safety impact. Cybersecurity brings small safety concerns, handled by standard procedures. Risks not likely to become severe incidents.",
        3: "Moderate safety impact. Cybersecurity noticeably affects safety, risking harm to people or the environment. Mitigation needed, organized response for safety.",
        4: "Significant safety impact. Cybersecurity notably affects safety, risking personnel, operations, or the environment. Swift response to prevent escalation, comprehensive mitigation.",
        5: "High safety impact. Cybersecurity could seriously harm people, assets, or the environment. Urgent, thorough action needed to prevent/mirror harm.",
        6: "Very high safety impact. Cybersecurity greatly risks severe harm, life loss, damage, or contamination. Urgent, strong measures needed for safety.",
        7: "Severe safety impact. Cybersecurity may lead to severe harm, casualties, damage, or environmental harm. Immediate, extraordinary actions needed to prevent disaster.",
        8: "Extremely high safety impact. Cybersecurity very likely to cause extreme harm, mass casualties, irreversible damage. Unprecedented action required to avert catastrophe.",
        9: "Critical safety impact. Cybersecurity on edge of causing catastrophe. High risk to life, assets, environment. Immediate, unprecedented action required.",
        10: "Imminent catastrophic safety impact. Cybersecurity on brink of unparalleled disaster. Catastrophic harm, mass casualties, irreversible damage imminent. Swift, decisive action only hope."
    }

    input_number = int(input_number)
    definition = safety_definitions.get(input_number, "Invalid input number")

    return definition


def life_definition(input_number):
    life_definitions = {
        1: "Negligible Danger to Life - The situation poses minimal danger to human life. Any potential threats are easily manageable, with little to no risk of causing harm.",
        2: "Low, Manageable Danger to Life - There are slight risks to human life, but they can be effectively managed through standard procedures. The risks are not likely to escalate to critical levels.",
        3: "Moderate Danger to Life - The scenario presents noticeable risks to human life. Proper mitigation measures are required to minimize these risks and ensure the safety of individuals.",
        4: "Significant Danger to Life - The situation significantly endangers human life, potentially leading to injuries or fatalities. Immediate actions are necessary to prevent these dangers from worsening.",
        5: "High Danger to Life - The scenario carries a high potential for causing danger to human life. Urgent and comprehensive measures are needed to avert harm and ensure the safety of individuals..",
        6: "Very High Danger to Life - The danger to human life is very high, with a substantial risk of severe injuries or loss of life. Swift and robust actions are imperative to prevent or mitigate such dangers.",
        7: "Severe Danger to Life - The situation has the potential to cause severe danger to human life, including multiple casualties. Immediate and extraordinary measures are essential to prevent a catastrophic outcome.",
        8: "Extremely High Danger to Life - The danger to human life is at an extremely high level, nearing critical stages. Catastrophic consequences, such as mass casualties, are possible. Unprecedented actions are vital to prevent disaster.",
        9: "Critical Danger to Life - The scenario is at the brink of causing a catastrophic loss of life. The risk to human life is critical, requiring immediate, comprehensive, and extraordinary actions to prevent imminent disaster.",
        10: "Imminent Catastrophic Danger to Life - The situation is at the highest level of danger to human life. Catastrophic loss of life is imminent, with potential for widespread devastation. Only swift and decisive actions can avert this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = life_definitions.get(input_number, "Invalid input number")

    return definition


def environment_definition(input_number):
    environment_definitions = {
        1: "Minimal Environmental Impact - The scenario has negligible effects on the local environment. Any potential impacts are minor and easily manageable, with no significant harm expected.",
        2: "Low to Manageable Environmental Impact - There are slight environmental concerns, but they can be addressed using standard procedures. The impacts are not likely to escalate to a level that would cause substantial harm.",
        3: "Moderate Environmental Impact - The scenario noticeably affects the local environment, potentially causing minor harm. Mitigation measures are required to minimize these impacts and prevent further deterioration.",
        4: "Significant Environmental Impact - The situation significantly impacts the local environment, posing notable risks to its well-being. Swift actions are necessary to prevent further harm and ensure effective mitigation.",
        5: "High Environmental Impact - The scenario presents a high potential for causing substantial harm to the local environment. Urgent and comprehensive measures are essential to mitigate impacts and prevent lasting damage.",
        6: "Very High Environmental Impact - The impact on the local environment is very high, risking severe harm and degradation. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Environmental Impact - The scenario has the potential to cause severe environmental consequences, with lasting damage and potential harm to ecosystems. Immediate and extraordinary measures are necessary to avert disaster.",
        8: "Extremely High Environmental Impact - The situation poses an extremely high risk to the local environment, approaching critical levels. Catastrophic environmental consequences, such as irreversible damage, are possible. Unprecedented actions are crucial to prevent a catastrophe.",
        9: "Critical Environmental Impact - The scenario is on the edge of causing a catastrophic environmental event. The risk to the local environment is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent disaster.",
        10: "Imminent Catastrophic Environmental Impact - The scenario is at the highest level of environmental impact. Catastrophic environmental consequences are imminent, with the potential for widespread devastation. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = environment_definitions.get(input_number, "Invalid input number")

    return definition


def supply_definition(input_number):
    supply_definitions = {
        1: "Minimal Impact on Supply Chain - The scenario has negligible effects on the supply chain. Any potential impacts are minor and easily manageable, with no significant disruptions expected.",
        2: "Low to Manageable Impact on Supply Chain - There are slight concerns in the supply chain, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing significant disruption.",
        3: "Moderate Impact on Supply Chain - The scenario noticeably affects the supply chain, possibly causing moderate disruptions. Mitigation measures are necessary to minimize these impacts and ensure operational continuity.",
        4: "Moderate to High Impact on Supply Chain - Significant impact on the supply chain is observed, risking notable disruptions. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Impact on Supply Chain - The scenario presents a high potential for causing substantial disruption to the supply chain. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive disruptions.",
        6: "High to Severe Impact on Supply Chain - The impact on the supply chain is very high, risking severe disruptions and potential breakdowns. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Impact on Supply Chain - The scenario has the potential to cause severe disruptions in the supply chain, potentially leading to widespread breakdowns. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Impact on Supply Chain - An extremely high risk of supply chain disruption is present, nearing critical levels. Catastrophic consequences, such as widespread shortages, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Impact on Supply Chain - The scenario is on the verge of causing a catastrophic supply chain disruption. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent disaster.",
        10: "Extremely Critical Impact on Supply Chain - The scenario is at the highest level of impact on the supply chain. Catastrophic supply chain disruptions are imminent, with potential for widespread shortages. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = supply_definitions.get(input_number, "Invalid input number")

    return definition


def production_definition(input_number):
    production_definitions = {
        1: "Minimal Impact on Production - The scenario has negligible effects on production. Any potential impacts are minor and easily manageable, with no significant disruption expected.",
        2: "Low to Manageable Impact on Production - There are slight concerns in production, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing substantial disruption.",
        3: "Moderate Impact on Production - The scenario noticeably affects production, possibly causing moderate disruptions. Mitigation measures are necessary to minimize these impacts and ensure operational continuity.",
        4: "Moderate to High Impact on Production - Significant impact on production is observed, risking notable disruptions. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Impact on Production - The scenario presents a high potential for causing substantial disruption to production. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive disruptions.",
        6: "High to Severe Impact on Production - The impact on production is very high, risking severe disruptions and potential shutdowns. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Impact on Production - The scenario has the potential to cause severe disruptions in production, potentially leading to widespread shutdowns. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Impact on Production - An extremely high risk of production disruption is present, nearing critical levels. Catastrophic consequences, such as widespread shutdowns, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Impact on Production - The scenario is on the verge of causing a catastrophic production disruption. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent disaster.",
        10: "Extremely Critical Impact on Production - The scenario is at the highest level of impact on production. Catastrophic production disruptions are imminent, with potential for widespread shutdowns. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = production_definitions.get(input_number, "Invalid input number")

    return definition


def data_definition(input_number):
    data_definitions = {
        1: "Minimal Impact on Data and Intellectual Property - The scenario has negligible effects on data and intellectual property. Any potential impacts are minor and easily manageable, with no significant harm to assets or proprietary information.",
        2: "Low to Manageable Impact on Data and Intellectual Property - There are slight concerns regarding data and intellectual property, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing substantial harm.",
        3: "Moderate Impact on Data and Intellectual Property - The scenario noticeably affects data and intellectual property, possibly causing moderate loss or compromise. Mitigation measures are necessary to minimize these impacts and ensure data security.",
        4: "Moderate to High Impact on Data and Intellectual Property - Significant impact on data and intellectual property is observed, risking notable loss or compromise. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Impact on Data and Intellectual Property - The scenario presents a high potential for causing substantial loss or compromise of data and intellectual property. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive data breaches.",
        6: "High to Severe Impact on Data and Intellectual Property - The impact on data and intellectual property is very high, risking severe loss or compromise. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Impact on Data and Intellectual Property - The scenario has the potential to cause severe loss or compromise of data and intellectual property, potentially leading to significant breaches. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Impact on Data and Intellectual Property - An extremely high risk of data and intellectual property compromise is present, nearing critical levels. Catastrophic consequences, such as widespread breaches, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Impact on Data and Intellectual Property - The scenario is on the verge of causing catastrophic loss or compromise of data and intellectual property. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent disaster.",
        10: "Extremely Critical Impact on Data and Intellectual Property - The scenario is at the highest level of impact on data and intellectual property. Catastrophic loss or compromise of data and intellectual property is imminent, with potential for widespread breaches. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = data_definitions.get(input_number, "Invalid input number")

    return definition


def finance_definition(input_number):
    finance_definitions = {
        1: "Minimal Financial Impact - The scenario has negligible effects on finances. Any potential financial impacts are minor and easily manageable, with no significant loss expected.",
        2: "Low to Manageable Financial Impact - There are slight financial concerns, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing substantial financial loss.",
        3: "Moderate Financial Impact - The scenario noticeably affects finances, possibly causing moderate losses. Mitigation measures are necessary to minimize these impacts and ensure financial stability.",
        4: "Moderate to High Financial Impact - Significant financial impact is observed, risking notable losses. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Financial Impact - The scenario presents a high potential for causing substantial financial losses. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive financial setbacks.",
        6: "High to Severe Financial Impact - The financial impact is very high, risking severe losses. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Financial Impact - The scenario has the potential to cause severe financial consequences, potentially leading to significant setbacks. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Financial Impact - An extremely high risk of financial losses is present, nearing critical levels. Catastrophic consequences, such as widespread financial turmoil, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Financial Impact - The scenario is on the verge of causing catastrophic financial consequences. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent financial disaster.",
        10: "Extremely Critical Financial Impact - The scenario is at the highest level of financial impact. Catastrophic financial consequences are imminent, with potential for widespread financial collapse. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = finance_definitions.get(input_number, "Invalid input number")

    return definition


def reputation_definition(input_number):
    reputation_definitions = {
        1: "Minimal Reputation Impact - The scenario has negligible effects on reputation. Any potential reputation impacts are minor and easily manageable, with no significant harm expected to the organization's image.",
        2: "Low to Manageable Reputation Impact - There are slight reputation concerns, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing substantial damage to the organization's reputation.",
        3: "Moderate Reputation Impact - The scenario noticeably affects reputation, possibly causing moderate damage. Mitigation measures are necessary to minimize these impacts and ensure the organization's positive image.",
        4: "Moderate to High Reputation Impact - Significant reputation impact is observed, risking notable damage to the organization's image. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Reputation Impact - The scenario presents a high potential for causing substantial damage to the organization's reputation. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive reputation damage.",
        6: "High to Severe Reputation Impact - The reputation impact is very high, risking severe damage. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Reputation Impact - The scenario has the potential to cause severe reputation damage, potentially leading to significant harm to the organization's image. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Reputation Impact - An extremely high risk of reputation damage is present, nearing critical levels. Catastrophic consequences, such as widespread negative perception, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Reputation Impact - The scenario is on the verge of causing catastrophic reputation damage. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent reputation disaster.",
        10: "Extremely Critical Reputation Impact - The scenario is at the highest level of reputation impact. Catastrophic reputation damage is imminent, with potential for widespread negative perception. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = reputation_definitions.get(input_number, "Invalid input number")

    return definition


def regulation_definition(input_number):
    regulatory_definitions = {
        1: "Minimal Regulatory Impact - The scenario has negligible effects on regulatory compliance. Any potential regulatory impacts are minor and easily manageable, with no significant violations expected.",
        2: "Low to Manageable Regulatory Impact - There are slight regulatory concerns, but they can be resolved using standard procedures. Impacts are not likely to escalate to a level causing substantial compliance violations.",
        3: "Moderate Regulatory Impact - The scenario noticeably affects regulatory compliance, possibly causing moderate violations. Mitigation measures are necessary to minimize these impacts and ensure adherence to regulations.",
        4: "Moderate to High Regulatory Impact - Significant regulatory impact is observed, risking notable compliance violations. Swift actions are necessary to prevent escalation and ensure efficient mitigation.",
        5: "High Regulatory Impact - The scenario presents a high potential for causing substantial compliance violations. Urgent and comprehensive measures are essential to mitigate impacts and prevent extensive regulatory breaches.",
        6: "High to Severe Regulatory Impact - The regulatory impact is very high, risking severe compliance violations. Swift and robust actions are imperative to prevent or mitigate these impacts.",
        7: "Severe Regulatory Impact - The scenario has the potential to cause severe regulatory consequences, potentially leading to significant non-compliance issues. Immediate and extraordinary measures are required to prevent a catastrophe.",
        8: "Severe to Critical Regulatory Impact - An extremely high risk of regulatory violations is present, nearing critical levels. Catastrophic consequences, such as widespread non-compliance, are possible. Unprecedented actions are crucial to prevent disaster.",
        9: "Critical Regulatory Impact - The scenario is on the verge of causing catastrophic regulatory violations. The risk is critical, demanding immediate, comprehensive, and unprecedented actions to prevent imminent regulatory disaster.",
        10: "Extremely Critical Regulatory Impact - The scenario is at the highest level of regulatory impact. Catastrophic regulatory violations are imminent, with potential for widespread non-compliance. Swift and decisive actions are the only hope to prevent this unparalleled disaster."
    }

    input_number = int(input_number)
    definition = regulatory_definitions.get(input_number, "Invalid input number")

    return definition


def moderate_content(content):
    """
    Utilizes the OpenAI moderation API to review a block of user content.

    Parameters:
    - content (str): The user content to be moderated.

    Returns:
    - str: 'pass' if the content is acceptable, 'fail' otherwise.
    """

    # OpenAI API endpoint for content moderation
    OPENAI_MODERATION_ENDPOINT = "https://api.openai.com/v1/moderations"

    # Your OpenAI API key
    OPENAI_API_KEY = get_api_key('openai')

    content_context = "In the context of a cybersecurity risk assessment: " + content

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "input": content_context
    }

    response = requests.post(OPENAI_MODERATION_ENDPOINT, headers=headers, json=data)
    result = response.json()

    # Check the moderation result and return 'pass' or 'fail'
    if "results" in result and len(result["results"]) > 0:
        flagged = result["results"][0]["flagged"]
        if flagged:
            return "fail"
        else:
            return "pass"
    else:
        # In case of an unexpected response, consider it a fail for safety
        return "fail"


def clean_numeric_string(value):
    # If value is empty or None, return 0
    if not value:
        return 0
    # Remove non-numeric characters ('$' and ',') and convert to an integer
    return int(''.join(filter(str.isdigit, value)))


def get_int_or_zero(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def checkbox_to_boolean(value):
    return value == 'on'


def create_or_update_raw_scenario(request):
    if request.method == 'POST':
        raw_id = int(request.POST.get('rawID'))  # Assuming rawID is the ID of RAWorksheet

        # Get or create the RAWorksheet instance
        raw_worksheet, created = RAWorksheet.objects.get_or_create(ID=raw_id)

        # Extract data from the POST request
        scenario_id_value = request.POST.get('scenarioID')

        if not scenario_id_value:
            scenario_id = 0
        else:
            scenario_id = int(scenario_id_value)

        control_list_str = request.POST.get('controlList')
        control_list = json.loads(control_list_str)

        bia_sis_outage_bool = request.POST.get('bia_sis_outage') == 'yes'
        bia_sis_compromise_bool = request.POST.get('bia_sis_compromise') == 'yes'
        exposed_system_value = request.POST.get('exposed_system', 'off')
        exposed_system = exposed_system_value.lower() == 'true'

        weak_credentials_value = request.POST.get('weak_credentials', 'off')
        weak_credentials = weak_credentials_value.lower() == 'true'

        scenario_data = {
            'RAWorksheetID': raw_worksheet,
            'ScenarioDescription': request.POST.get('ScenarioDescription'),
            'weak_credentials': weak_credentials,
            'exposed_system': exposed_system,
            'RiskScore': request.POST.get('RiskScore'),
            'VulnScore': request.POST.get('VulnScore'),
            'ReputationScore': request.POST.get('ReputationScore'),
            'OperationScore': request.POST.get('OperationScore'),
            'FinancialScore': request.POST.get('FinancialScore'),
            'SafetyScore': request.POST.get('SafetyScore'),
            'DataScore': request.POST.get('DataScore'),
            'SupplyChainScore': request.POST.get('SupplyChainScore'),
            'lifeScore': request.POST.get('lifeScore'),
            'productionScore': request.POST.get('productionScore'),
            'environmentScore': request.POST.get('environmentScore'),
            'regulatoryScore': request.POST.get('regulatoryScore'),
            'RiskStatus': request.POST.get('RiskStatus'),
            'threatSource': request.POST.get('threatSource'),
            'riskSummary': request.POST.get('riskSummary'),
            'scenarioCost': clean_numeric_string(request.POST.get('scenarioCost')),
            'event_cost_low': clean_numeric_string(request.POST.get('event_cost_low')),
            'event_cost_high': clean_numeric_string(request.POST.get('event_cost_high')),
            'event_cost_median': clean_numeric_string(request.POST.get('event_cost_median')),
            'justifySafety': request.POST.get('justifySafety') or "No data entered",
            'justifyLife': request.POST.get('justifyLife') or "No data entered",
            'justifyProduction': request.POST.get('justifyProduction') or "No data entered",
            'justifyFinancial': request.POST.get('justifyFinancial') or "No data entered",
            'justifyReputation': request.POST.get('justifyReputation') or "No data entered",
            'justifyEnvironment': request.POST.get('justifyEnvironment') or "No data entered",
            'justifyRegulation': request.POST.get('justifyRegulation') or "No data entered",
            'justifyData': request.POST.get('justifyData') or "No data entered",
            'justifySupply': request.POST.get('justifySupply') or "No data entered",
            'outage': request.POST.get('outage'),
            'outageLength': get_int_or_zero(request.POST.get('outageLength')),
            'ThreatScore': request.POST.get('ThreatScore'),
            'threatTactic': request.POST.get('threatTactic'),
            'impact': request.POST.get('impact'),
            'residual_risk': int(round(float(request.POST.get('residual_risk')))),
            'bia_safety_hazard': request.POST.get('bia_safety_hazard'),
            'bia_sis_outage': bia_sis_outage_bool,
            'bia_sis_compromise': bia_sis_compromise_bool,
            'bia_life_scope': request.POST.get('bia_life_scope'),
            'bia_contaminants': request.POST.get('bia_contaminants'),
            'bia_contamination': request.POST.get('bia_contamination'),
            'bia_resident': request.POST.get('bia_resident'),
            'bia_wildlife': request.POST.get('bia_wildlife'),
            'bia_data_pii': checkbox_to_boolean(request.POST.get('bia_data_pii', False)),
            'bia_data_ip': checkbox_to_boolean(request.POST.get('bia_data_ip', False)),
            'bia_data_customer': checkbox_to_boolean(request.POST.get('bia_data_customer', False)),
            'bia_data_finance': checkbox_to_boolean(request.POST.get('bia_data_finance', False)),
            'bia_supply_outbound': checkbox_to_boolean(request.POST.get('bia_supply_outbound', False)),
            'bia_supply_inbound': checkbox_to_boolean(request.POST.get('bia_supply_inbound', False)),

            'bia_supply_prodimpact': request.POST.get('bia_supply_prodimpact'),
            'bia_supply_security': checkbox_to_boolean(request.POST.get('bia_supply_security', False)),
            'raw_consequences': request.POST.get('raw_consequences'),
        }

        # Check if scenario_id is provided to determine if it's an update or create
        if scenario_id > 0:
            scenario = get_object_or_404(RAWorksheetScenario, ID=scenario_id)
            for key, value in scenario_data.items():
                setattr(scenario, key, value)
            scenario.save()
        else:
            new_scenario = RAWorksheetScenario(**scenario_data)
            new_scenario.save()
            scenario_id = new_scenario.ID

        # Delete all existing controls for the given scenario
        RawControlList.objects.filter(scenarioID_id=scenario_id).delete()

        # Add new controls from the control_list
        for control_item in control_list:
            control_name = control_item['control']
            control_score = control_item['score']

            # Create a new control instance
            RawControlList.objects.create(
                scenarioID_id=scenario_id,
                control=control_name,
                score=control_score
            )

        return JsonResponse({'message': 'Scenario created/updated successfully'}, status=200)

    # Handle other HTTP methods or return an error if needed
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def analyze_raw_scenario(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    if request.method == 'POST':
        scenario = request.POST.get('scenario')
        # Fetch the organization_id from the user's profile
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            organization_id = user_profile.organization.id
        except UserProfile.DoesNotExist:
            organization_id = None  # Or handle the lack of a profile as you see fit

        # Create a record in user_scenario_audit
        user_scenario_audit.objects.create(
            scenario_text=scenario,
            user=request.user,
            organization_id=organization_id,
            ip_address=get_client_ip(request),
            session_id=request.session.session_key
        )
        # validate the scenario doesn't contain vulgar terms using the OpenAPI moderator
        if is_inappropriate(scenario):
            consequence_text = 'Scenario contains inappropriate terms'
            return JsonResponse({'consequence_text': consequence_text}, status=400)

        validation_prompt = f"""
        Evaluate if the following text represents a coherent and plausible cybersecurity scenario, or OT incident scenario, or industrial incident scenario: '{scenario}'. Respond yes if valid, no if invalid.
        """

        validation_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": validation_prompt}
            ],
            max_tokens=50,
            temperature=0.7
        )

        if "yes" in validation_response['choices'][0]['message']['content'].lower():

            raw_id = request.POST.get('rawID')

            try:
                raw = RAWorksheet.objects.get(ID=raw_id)
            except RAWorksheet.DoesNotExist:
                return JsonResponse({'error': 'Risk assessment worksheet record not found'}, status=404)

            facility_type = RAWorksheet.BusinessUnitType
            industry = RAWorksheet.industry

            # Construct a prompt for GPT-4
            system_message = f"""
            Given a cybersecurity scenario at a {facility_type} in the {industry} industry described as: {scenario}. Concisely describe in 50 words in a bulleted ist format of a maximum of 5 of the most likely direct consequences of the given scenario. The direct consequences should be specific to the facility and the mentioned details. Assume the role of an expert OT Cybersecurity risk advisor. Additional instruction: output ONLY the list items with no text either before or after the list items.
            """
            user_message = scenario

            # Query OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                max_tokens=100,
                temperature=0.1
            )

            # Extract and process the text from the response
            consequence_text = response['choices'][0]['message']['content']
            # consequence_list = consequence_text.split(';')  # Splitting based on the chosen delimiter

            return JsonResponse({'consequence': consequence_text})


    else:
        return JsonResponse({'consequence': [], 'error': 'Not a valid scenario'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def analyze_sim_scenario(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    if request.method == 'POST':
        scenario = request.POST.get('scenario')
        # Fetch the organization_id from the user's profile
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            organization_id = user_profile.organization.id
        except UserProfile.DoesNotExist:
            organization_id = None  # Or handle the lack of a profile as you see fit

        # Create a record in user_scenario_audit
        user_scenario_audit.objects.create(
            scenario_text=scenario,
            user=request.user,
            organization_id=organization_id,
            ip_address=get_client_ip(request),
            session_id=request.session.session_key
        )
        # validate the scenario doesn't contain vulgar terms using the OpenAPI moderator
        if is_inappropriate(scenario):
            consequence_text = 'Scenario contains inappropriate terms'
            return JsonResponse({'consequence_text': consequence_text}, status=400)

        validation_prompt = f"""
        Evaluate if the following text represents a coherent and plausible cybersecurity scenario, or OT incident scenario, or industrial incident scenario: '{scenario}'. Respond yes if valid, no if invalid.
        """

        validation_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": validation_prompt}
            ],
            max_tokens=50,
            temperature=0.7
        )

        if "yes" in validation_response['choices'][0]['message']['content'].lower():

            facility_type = request.POST.get('facility_type')
            industry = request.POST.get('industry')

            system_message = f"""
                Analyze the following cybersecurity scenario at a {facility_type} in the {industry} industry: '{scenario}'. For each factor listed below, provide a score out of 10 for impact severity and a brief narrative. Format your response with clear delimiters as follows: 'Factor: [Factor Name] | Score: X/10 | Narrative: [Explanation]'.

                Factors:
                - Safety
                - Danger-to-life
                - Environmental consequences
                - Supply chain
                - Data
                - Operations
                - Financials
                - Reputation
                - Regulations

                Ensure that the scores and narratives are specific to the facility and scenario described. Use '|' as a delimiter between different sections of your response for each factor.
            """

            # Query OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_message}
                ],
                max_tokens=500,
                temperature=0.1
            )

            # Process the response
            consequence_text = response['choices'][0]['message']['content']
            # Parse the response into a structured format
            parsed_consequences = parse_consequences(consequence_text)

            return JsonResponse({'consequence': parsed_consequences})

        else:
            return JsonResponse({'consequence': [], 'error': 'Not a valid scenario'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def parse_consequences(text):
    # Split the text into segments for each factor
    segments = text.split('Factor: ')
    results = []

    for segment in segments[1:]:  # Skip the first split as it will be empty
        parts = segment.split(' | ')
        if len(parts) >= 3:
            factor = parts[0].strip()
            score = parts[1].replace('Score: ', '').strip()
            narrative = parts[2].replace('Narrative: ', '').strip()
            results.append({'factor': factor, 'score': score, 'narrative': narrative})

    return results


def extract_score_and_narrative(text, factor):
    # Adjust the regex pattern to match the new response format with delimiters
    # Using re.IGNORECASE to make the regex case-insensitive
    pattern = re.compile(rf"{factor}\s*:\s*\|\s*Score\s*:\s*(\d+\/10)\s*\|\s*Narrative\s*:\s*([^|]+)", re.IGNORECASE)
    match = pattern.search(text)
    if match:
        score = match.group(1)
        narrative = match.group(2).strip()
    else:
        score = "0/10"  # Default score if not found
        narrative = "Narrative not available"  # Default narrative if not found
    return score, narrative


def generate_sim_attack_tree(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key
    scenario = request.POST.get('scenario')
    attack_tree_system_message = f"""
        Generate a hierarchical structure of a potential attack tree for the given cybersecurity scenario in a machine-readable JSON format. The structure should use 'name' for node labels and 'children' for nested nodes. Each node should represent a step or method in the attack, formatted as: {{'name': 'Node Name', 'children': [{{...}}]}}. EXTRA INSTRUCTION: Output MUST be in JSON format with no additional characters outside of the JSON structure.
    """

    # Query OpenAI API for the attack tree
    attack_tree_response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": attack_tree_system_message},
            {"role": "user", "content": scenario}
        ],
        max_tokens=800,
        temperature=0.3
    )

    # Process the response for attack tree
    attack_tree_raw = attack_tree_response['choices'][0]['message']['content']

    try:
        # Parse the raw JSON string into a Python dictionary
        attack_tree_data = json.loads(attack_tree_raw)

        return JsonResponse(attack_tree_data)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format from AI response"}, status=400)


def analyze_sim_consequences(request):
    if request.method == 'POST':
        scenario = request.POST.get('scenario')
        facility_type = request.POST.get('facility_type')
        industry = request.POST.get('industry')
        # Additional inputs for cost estimation
        organization_size = request.POST.get('organization_size', '').strip()
        asset_value = request.POST.get('asset_value', '').strip()
        operational_impact = request.POST.get('operational_impact', '').strip()
        security_measures = request.POST.get('security_measures', '').strip()
        regulatory_environment = request.POST.get('regulatory_environment', '').strip()

        # Construct the system message for consequences
        consequence_message = f"""
            You are an OT Cybersecurity incident scenario simulator. Given a cybersecurity scenario at a {facility_type} in the {industry} industry described as: '{scenario}'. Concisely describe in 50 words in a bulleted list format of a maximum of 5 of the most likely direct consequences of the given scenario.
        """

        # Construct the system message for cost estimation
        cost_estimation_message = f"""
            As an insurance underwriter, estimate the potential financial impact of a cybersecurity incident for a {facility_type} in the {industry} industry. The estimate should be based on current understandings, previously reported incidents, and real-world events. Provide the best case, worst case, and most likely case cost estimates. Provide only the numerical values, without any additional explanation or narrative. Scenario details: '{scenario}'.
            - Organization Size: {organization_size}
            - Value of Affected Assets: {asset_value}
            - Operational Impact: {operational_impact}
            - Security Measures: {security_measures}
            - Regulatory Environment: {regulatory_environment}
            Provide the estimates as US dollar values as follows:
            Best Case Cost: [value] 
            Worst Case Cost: [value] 
            Most Likely Case Cost: [value] 
        """

        # Query OpenAI API for consequences
        openai_api_key = get_api_key('openai')
        openai.api_key = openai_api_key
        consequence_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": consequence_message}
            ],
            max_tokens=500,
            temperature=0.1
        )
        consequence_text = consequence_response['choices'][0]['message']['content']

        # Query OpenAI API for cost estimation
        cost_response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": cost_estimation_message}
            ],
            max_tokens=500,
            temperature=0.1
        )
        cost_estimation_text = cost_response['choices'][0]['message']['content']
        print(cost_estimation_text)
        # Corrected parsing logic to extract full numerical values including commas
        best_case_cost = re.search(r'Best Case Cost: \$([\d,]+)', cost_estimation_text)
        worst_case_cost = re.search(r'Worst Case Cost: \$([\d,]+)', cost_estimation_text)
        most_likely_case_cost = re.search(r'Most Likely Case Cost: \$([\d,]+)', cost_estimation_text)

        best_case_cost = best_case_cost.group(1) if best_case_cost else "Not available"
        worst_case_cost = worst_case_cost.group(1) if worst_case_cost else "Not available"
        most_likely_case_cost = most_likely_case_cost.group(1) if most_likely_case_cost else "Not available"

        return JsonResponse({
            'best_case_cost': best_case_cost,
            'worst_case_cost': worst_case_cost,
            'most_likely_case_cost': most_likely_case_cost,
            'consequence': consequence_text
        })
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)
