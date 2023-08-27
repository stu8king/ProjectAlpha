import openai
import os

from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions, MitreICSMitigations, MitreICSTechniques
from django.contrib.auth.decorators import login_required
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.Model_CyberPHA import tblIndustry, tblThreatSources, auditlog, tblScenarios, tblCyberPHAHeader
from OTRisk.models.Model_Mitre import MitreICSTactics
from accounts.models import Organization
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
from .forms import RAActionsForm
from xhtml2pdf import pisa
import json
import re
import requests
from .dashboard_views import get_user_organization_id


class UpdateRAAction(View):
    def put(self, request, *args, **kwargs):
        # try:
        print(request.body)
        data = json.loads(request.body.decode('utf-8'))
        action_id = data.get('action_id')
        action_due_date = data.get('actionDueDate')
        action_status = data.get('actionStatus')

        ra_action = RAActions.objects.get(ID=action_id)
        ra_action.actionDueDate = action_due_date
        ra_action.actionStatus = action_status
        current_user_name = request.user.first_name + " " + request.user.last_name
        history_update = f"\n\n{timezone.now()}: {current_user_name} updated the record to change the status to {action_status} and the due date to {action_due_date}."
        ra_action.history += history_update
        ra_action.save()

        return JsonResponse({'success': True})

    # except Exception as e:
    #    return JsonResponse({'success': False, 'error': str(e)})


@login_required()
def ra_actions_view(request):
    selected_action = None
    ra_title = None  # This will store the RATitle or the record from tblCyberPHAHeader

    if request.method == 'POST':
        action_id = request.POST.get('action_id')
        if action_id:
            try:
                selected_action = RAActions.objects.get(ID=action_id)

                # Check RAWorksheetID and retrieve RATitle
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

    # Filter RAActions by organization_id
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
    print(f"{request.POST}")
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
        action_assets = request.POST.get('actionAssets')
        action_due_date = request.POST.get('actionDueDate')
        action_priority = request.POST.get('actionPriority')
        outageSIS = request.POST.get('outageSIS')
        outageICS = request.POST.get('outageICS')
        outageEMS = request.POST.get('outageEMS')
        outageIT = request.POST.get('outageIT')
        outagePS = request.POST.get('outagePS')
        outageWWW = request.POST.get('outageWWW')
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
            actionAssets=action_assets,
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
            history=history
        )
        ra_action.save()

        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error"})


@csrf_exempt
def raw_from_walkdown(request):
    print("test")
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
    raworksheet = get_object_or_404(RAWorksheet, pk=raworksheet_id)
    scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=raworksheet)
    total_scenario_cost = scenarios.aggregate(Sum('scenarioCost'))['scenarioCost__sum']
    formatted_cost = "${:,.2f}".format(total_scenario_cost)
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
                   'reputation_status': reputation_status})


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


@login_required()
def qraw(request):
    # check the organization that the user belong to
    org_id = get_user_organization_id(request)

    if request.method == 'POST':
        edit_mode = int(request.POST.get('edit_mode', 0))

        if edit_mode == 0:

            # Check for duplicate records
            is_duplicate = RAWorksheet.objects.filter(
                organization_id=org_id,
                RATitle=request.POST.get('txtTitle'),
                BusinessUnit=request.POST.get('txtBU'),
                AssessorName=request.POST.get('txtLeader'),
                industry=request.POST.get('selectIndustry'),
                BusinessUnitType=request.POST.get('selectFacility'),
                RATrigger=request.POST.get('selectTrigger'),
                RADescription=request.POST.get('txtDescription')
            ).exists()

            if not is_duplicate:
                # adding new records
                ra_worksheet = RAWorksheet(
                    RATitle=request.POST.get('txtTitle'),
                    BusinessUnit=request.POST.get('txtBU'),
                    AssessorName=request.POST.get('txtLeader'),
                    industry=request.POST.get('selectIndustry'),
                    BusinessUnitType=request.POST.get('selectFacility'),
                    RATrigger=request.POST.get('selectTrigger'),
                    RADescription=request.POST.get('txtDescription'),
                    UserID=request.user.id,
                    organization_id=org_id,
                    WalkdownID=0,
                    StatusFlag="Open",
                    RADate=date.today(),
                )
                ra_worksheet.save()

                # add scenario records
                for i in range(1, 5):
                    if request.POST.get(f'txtScenarioDescription_{i}') == '':
                        break
                    else:
                        raw_cost = request.POST.get(f'lblriskCost_{i}')
                        formatted_cost = int(re.sub(r'[^\d.]', '', raw_cost))
                        scenario = RAWorksheetScenario(
                            RAWorksheetID=ra_worksheet,
                            ScenarioDescription=request.POST.get(f'txtScenarioDescription_{i}'),
                            threatSource=request.POST.get(f'selectThreat_{i}'),
                            threatTactic=request.POST.get(f'selectTactics_{i}'),
                            SafetyScore=request.POST.get(f'range_safety_{i}'),
                            lifeScore=request.POST.get(f'range_life_{i}'),
                            productionScore=request.POST.get(f'range_production_{i}'),
                            FinancialScore=request.POST.get(f'range_finance_{i}'),
                            ReputationScore=request.POST.get(f'range_reputation_{i}'),
                            environmentScore=request.POST.get(f'range_environment_{i}'),
                            regulatoryScore=request.POST.get(f'range_regulatory_{i}'),
                            DataScore=request.POST.get(f'range_data_{i}'),
                            VulnScore=request.POST.get(f'range_vuln_{i}'),
                            ThreatScore=request.POST.get(f'range_threat_{i}'),
                            notes=request.POST.get(f'txtAssets_{i}'),
                            RiskScore=int(request.POST.get(f'lblriskScore_{i}')),
                            RiskStatus=request.POST.get(f'lblriskRating_{i}'),
                            riskSummary=request.POST.get(f'lblriskSummary_{i}'),
                            scenarioCost=formatted_cost,
                            justifySafety=request.POST.get(f'txtSafetyJustify_{i}'),
                            justifyLife=request.POST.get(f'txtlifeJustify_{i}'),
                            justifyProduction=request.POST.get(f'txtproductionJustify_{i}'),
                            justifyFinancial=request.POST.get(f'txtfinancialJustify_{i}'),
                            justifyReputation=request.POST.get(f'txtreputationJustify_{i}'),
                            justifyEnvironment=request.POST.get(f'txtenvironmentJustify_{i}'),
                            justifyRegulation=request.POST.get(f'txtregulationustify_{i}'),
                            justifyData=request.POST.get(f'txtdataJustify_{i}'),

                        )
                        scenario.save()
        elif edit_mode == 1:
            ra_worksheet_id = int(request.POST.get('hdnRawID'))
            ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)
            ra_worksheet.RATitle = request.POST.get('txtTitle')
            ra_worksheet.BusinessUnit = request.POST.get('txtBU')
            ra_worksheet.AssessorName = request.POST.get('txtLeader')
            ra_worksheet.RADescription = request.POST.get('txtDescription')
            ra_worksheet.industry = request.POST.get('selectIndustry')
            ra_worksheet.BusinessUnitType = request.POST.get('selectFacility')
            ra_worksheet.RATrigger = request.POST.get('selectTrigger')
            ra_worksheet.save()

            scenario_count = int(request.POST.get('scenarioCount', 0))
            for i in range(1, scenario_count + 1):
                scenario_id_str = request.POST.get(f'hdnScenarioID_{i}')
                ra_worksheet_id = int(
                    request.POST.get('hdnRawID'))
                ra_worksheet_instance = RAWorksheet.objects.get(ID=ra_worksheet_id)

                if scenario_id_str and scenario_id_str != '0':
                    scenario_id = int(scenario_id_str)
                    try:
                        scenario = RAWorksheetScenario.objects.get(ID=scenario_id)
                    except RAWorksheetScenario.DoesNotExist:
                        scenario = RAWorksheetScenario()  # Create a new instance if not found.
                else:
                    scenario = RAWorksheetScenario()  # Create a new instance.

                raw_cost = request.POST.get(f'lblriskCost_{i}')
                formatted_cost = int(re.sub(r'[^\d.]', '', raw_cost))
                scenario.RAWorksheetID = ra_worksheet_instance
                scenario.ScenarioDescription = request.POST.get(f'txtScenarioDescription_{i}')
                scenario.threatSource = request.POST.get(f'selectThreat_{i}')
                scenario.threatTactic = request.POST.get(f'selectTactics_{i}')
                scenario.SafetyScore = request.POST.get(f'range_safety_{i}')
                scenario.lifeScore = request.POST.get(f'range_life_{i}')
                scenario.productionScore = request.POST.get(f'range_production_{i}')
                scenario.FinancialScore = request.POST.get(f'range_finance_{i}')
                scenario.ReputationScore = request.POST.get(f'range_reputation_{i}')
                scenario.environmentScore = request.POST.get(f'range_environment_{i}')
                scenario.regulatoryScore = request.POST.get(f'range_regulatory_{i}')
                scenario.VulnScore = request.POST.get(f'range_vuln_{i}')
                scenario.ThreatScore = request.POST.get(f'range_threat_{i}')
                scenario.notes = request.POST.get(f'txtAssets_{i}')
                scenario.RiskScore = int(request.POST.get(f'lblriskScore_{i}'))
                scenario.RiskStatus = request.POST.get(f'lblriskRating_{i}')
                scenario.riskSummary = request.POST.get(f'lblriskSummary_{i}')
                scenario.scenarioCost = formatted_cost
                scenario.justifySafety = request.POST.get(f'txtSafetyJustify_{i}')
                scenario.justifyLife = request.POST.get(f'txtlifeJustify_{i}')
                scenario.justifyData = request.POST.get(f'txtdataJustify_{i}')
                scenario.justifyFinancial = request.POST.get(f'txtfinancialJustify_{i}')
                scenario.justifyProduction = request.POST.get(f'txtproductionJustify_{i}')
                scenario.justifyEnvironment = request.POST.get(f'txtenvironmentJustify_{i}')
                scenario.justifyRegulation = request.POST.get(f'txtregulationJustify_{i}')
                scenario.justifyReputation = request.POST.get(f'txtreputationJustify_{i}')
                scenario.save()

    raws = RAWorksheet.objects.filter(organization_id=org_id)

    facilities = FacilityType.objects.all().order_by('FacilityType')
    industries = tblIndustry.objects.all().order_by('Industry')
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    mitreTactics = MitreICSTactics.objects.all().order_by('tactic')
    mitreMitigations = MitreICSMitigations.objects.all().order_by('id')
    scenarios = tblScenarios.objects.all().order_by('Scenario')

    user_ip = request.META.get('REMOTE_ADDR', '')
    user_action = "qraw"
    write_to_audit(request.user.id, user_action, user_ip)

    return render(request, 'qraw.html',
                  {'raws': raws,
                   'facilities': facilities,
                   'industries': industries,
                   'threatsources': threatsources,
                   'mitreTactics': mitreTactics,
                   'mitreMitigations': mitreMitigations,
                   'scenarios': scenarios})


class GetTechniquesView(View):
    def get(self, request, *args, **kwargs):
        mitigation_ids = request.GET.getlist('mitigation_id[]', None)
        print(f"{mitigation_ids}")
        if mitigation_ids:
            techniques = MitreICSTechniques.objects.filter(SourceID__in=mitigation_ids).values('ID', 'TargetName')
            techniques_list = list(techniques)
            return JsonResponse(techniques_list, safe=False)
        else:
            return JsonResponse({"error": "No mitigation ID provided"}, status=400)


# Function to assess the risk using the OpenAI GPT-3 API
def openai_assess_risk(request):
    if request.method == 'GET':
        print(f"{request.GET}")
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        safety_impact = int(request.GET.get('safety_impact'))
        life_impact = int(request.GET.get('life_impact'))
        production_impact = int(request.GET.get('production_impact'))
        financial_impact = int(request.GET.get('financial_impact'))
        reputation_impact = int(request.GET.get('reputation_impact'))
        environment_impact = int(request.GET.get('environment_impact'))
        regulatory_impact = int(request.GET.get('regulatory_impact'))
        data_impact = int(request.GET.get('data_impact'))
        threat_source = request.GET.get('threat_source')
        threat_tactic = request.GET.get('threat_tactic')
        vulnerability_exposure = int(request.GET.get('vulnerability_exposure'))
        threat_exposure = int(request.GET.get('threat_exposure'))
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        asset_status = int(request.GET.get('assetStatus'))

        if asset_status in [1, 2]:
            asset_lc = "New / Hardened"
        elif asset_status in [3, 4]:
            asset_lc = "Current / Managed"
        elif asset_status in [5, 6]:
            asset_lc = "Aging / Supported"
        elif asset_status in [7, 8]:
            asset_lc = "Legacy / Unmanaged"
        elif asset_status in [9, 10]:
            asset_lc = "Obselete"
        else:
            asset_lc = "Unknown status"  # default case

        # Prepare the request data for the OpenAI GPT-3 API in the chat format
        message = [
            {"role": "system",
             "content": f"As a cybersecurity risk assessment professional, assess the risk of {threat_source} using the threat tactic {threat_tactic} in relation to {scenario} in a {facility_type} within the {industry} industry. The assets in-scope for this assessment are {asset_lc}."},
            {"role": "user",
             "content": f"First, provide the overall risk rating. Choose from: Low, Low/Medium, Medium, Medium/High, or High. Base this on the provided information:\nThreat source - {threat_source}, Threat tactic - {threat_tactic}, Safety impact - {safety_impact}/10, Life impact - {life_impact}/10, and so on."},
            {"role": "user",
             "content": f"Second, provide a risk score between 1 and 10. Consider 1 as a very low risk with minimal impact and 10 as a catastrophic risk involving serious injuries or loss of life."},
            {"role": "user",
             "content": f"Third, estimate a value in US dollars if {scenario} were to occur for {facility_type} within the {industry} industry. Use the business impact analysis scores to understand the perspective that the business has with regards to the given scenario of {scenario}, where 1 is minimal/low impact and 10 is maximum/catastrophic impact . Those scores are for safety: {safety_impact}, danger to life: {life_impact}, production/operations: {production_impact}, financial: {financial_impact}, reputation: {reputation_impact}, environmental: {environment_impact}, regulatory: {regulatory_impact}, and data: {data_impact}. Determine how to apply any necessary weightings to impact scores based on the given industry: {industry} and facility type: {facility_type}.Use public sources or industry reports for a credible estimation. If no such data is available, provide a best estimate using Artificial Intelligence. Provide the result as a numeric value to represent a dollar amount."},
            {"role": "user",
             "content": f"Lastly, provide a one-sentence summary highlighting the key factors used in the assessment, especially the industry type, facility type, and other high-weight factors. The output format must be: <overall_risk_rating_value>|<overall_risk_score>|<cost>|<summary> where <overall_risk_rating_value> is the overall risk rating, <overall_risk_score> is the overall risk score, <cost> is the estimated cost, <summary> is the summary statement, and | is a field delimiter ."}
        ]

        # openai.api_key = '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'
        openai.api_key = os.environ.get('OPENAI_API_KEY')
        # Make the API call to the OpenAI GPT-3 API using the message
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use the GPT-3 engine
            messages=message,
            temperature=0,
            max_tokens=256
        )
        print(f"response={response}")
        # Extract the generated response from the API
        generated_response = response['choices'][0]['message']['content']
        risk_summary = generated_response.split('|')[3].strip()
        risk_cost = generated_response.split('|')[2].strip()
        risk_score = generated_response.split('|')[1].strip()
        risk_rating = generated_response.split('|')[0].strip()

        # Create an array to return to the user interface
        result_array = [risk_rating, risk_score, risk_cost, risk_summary]
        print(f"response={generated_response}")

        # Return the generated response as JSON
        return JsonResponse(result_array, safe=False)


def parse_risk_score(response_text):
    lines = response_text.split('\n')
    for line in lines:
        if line.startswith('Risk score:'):
            risk_score = line.split(':')[1].strip().split('/')[0]
            return float(risk_score)
    return None


def write_to_audit(user_id, user_action, user_ip):
    auditlog_entry = auditlog(userID=user_id, timestamp=timezone.now(), user_action=user_action, user_ipaddress=user_ip)
    auditlog_entry.save()


def raw_action(request):
    print(f"{request.POST}")
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
        print(f"data={data}")
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
