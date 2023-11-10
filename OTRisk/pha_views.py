from django.db.models.functions import Coalesce
from django.forms import model_to_dict

from OTRisk.models.Model_CyberPHA import tblIndustry, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario, vulnerability_analysis, tblAssetType, tblMitigationMeasures, MitreControlAssessment, \
    cyberpha_safety, SECURITY_LEVELS
from OTRisk.models.raw import MitreICSMitigations, RAActions
from OTRisk.models.questionnairemodel import FacilityType
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date, time
from django.views import View
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import openai
import re
from django.db.models import Avg, Sum, F, Count, Subquery, OuterRef, Case, When, Value, IntegerField
import concurrent.futures
import os
import math

from ProjectAlpha import settings
from ProjectAlpha.settings import BASE_DIR
from .dashboard_views import get_user_organization_id
from django.contrib.auth.models import User
from concurrent.futures import ThreadPoolExecutor, as_completed
from .forms import VulnerabilityAnalysisForm
import aiohttp
import asyncio
import tempfile
import time
import uuid
from django.core import serializers
from django.http import FileResponse
from pptx import Presentation
from pptx.util import Inches, Pt


@login_required
def iotaphamanager(request, record_id=None):
    pha_header = None
    new_record_id = None  # Initialize new_record_id to None
    annual_revenue_str = "$0"
    if request.method == 'POST':
        title = request.POST.get('txtTitle')
        facility_name = request.POST.get('txtFacility')
        # Check for duplicate record

        pha_id = request.POST.get('txtHdnCyberPHAID')
        if pha_id and int(pha_id) > 0:
            # Update existing record
            pha_header, created = tblCyberPHAHeader.objects.get_or_create(ID=pha_id)
        else:
            duplicate_record = tblCyberPHAHeader.objects.filter(title=title, FacilityName=facility_name).exists()
            if duplicate_record:
                return redirect('OTRisk:iotaphamanager')
            # Create a new record
            pha_header = tblCyberPHAHeader()

        pha_header.title = request.POST.get('txtTitle')
        pha_header.PHALeader = request.POST.get('txtLeader')
        pha_header.PHALeaderEmail = request.POST.get('txtLeaderEmail')
        pha_header.FacilityName = request.POST.get('txtFacility')
        pha_header.Industry = request.POST.get('selIndustry')
        pha_header.FacilityType = request.POST.get('selFacilityType')
        pha_header.AssessmentUnit = request.POST.get('txtUnit')
        pha_header.AssessmentZone = request.POST.get('selZone')
        pha_header.AssessmentStartDate = request.POST.get('txtStartDate')
        pha_header.AssessmentEndDate = request.POST.get('txtEndDate')
        pha_header.facilityAddress = request.POST.get('txtAddress')
        pha_header.safetySummary = request.POST.get('txtSafetySummary')
        pha_header.chemicalSummary = request.POST.get('txtChemical')
        pha_header.physicalSummary = request.POST.get('txtPhysical')
        pha_header.otherSummary = request.POST.get('txtOther')
        pha_header.complianceSummary = request.POST.get('txtCompliance')
        pha_header.country = request.POST.get('countrySelector')
        pha_header.Date = request.POST.get('txtStartDate')
        pha_header.EmployeesOnSite = request.POST.get('txtEmployees')
        pha_header.shift_model = request.POST.get('shift_model')
        try:
            # Attempt to convert the POST value to an integer.
            pha_header.pha_score = int(request.POST.get('hdn_pha_score', 0))
        except ValueError:
            # If conversion fails, set pha_score to 0.
            pha_header.pha_score = 0

        # Continue with the rest of the processing

        pha_header.sl_t = request.POST.get('selSL')
        pha_header.FacilityID = 0
        pha_header.Deleted = 0

        annual_revenue_str = request.POST.get('annual_revenue', '')

        # Strip out $ and , characters
        cleaned_annual_revenue_str = ''.join(filter(str.isdigit, annual_revenue_str))

        # Convert the cleaned string to an integer
        try:
            annual_revenue_int = int(cleaned_annual_revenue_str)
        except ValueError:  # Handle cases where the input might still not be a valid integer
            annual_revenue_int = 0  # Or handle this situation differently if needed

        # Save to your model
        pha_header.annual_revenue = annual_revenue_int

        cyber_insurance_value = request.POST.get('cyber_insurance')
        pha_header.cyber_insurance = False if cyber_insurance_value is None else bool(cyber_insurance_value)

        pha_header.UserID = request.user.id
        pha_header.save()

        new_record_id = pha_header.ID

    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    ra_actions_subquery = RAActions.objects.filter(phaID=OuterRef('ID')).values('phaID').annotate(
        action_count=Count('ID')).values('action_count')

    pha_header_records = tblCyberPHAHeader.objects.filter(UserID__in=users_in_organization, Deleted=0).annotate(
        scenario_count=Count('tblcyberphascenario'),
        ra_action_count=Coalesce(Subquery(ra_actions_subquery, output_field=IntegerField()), Value(0))
    )

    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    zones = tblZones.objects.all().order_by('PlantZone')
    standardslist = tblStandards.objects.all().order_by('standard')
    mitigations = MitreICSMitigations.objects.all()
    return render(request, 'iotaphamanager.html', {
        'pha_header_records': pha_header_records,
        'industries': industries,
        'facilities': facilities,
        'zones': zones,
        'standardslist': standardslist,
        'current_pha_header': pha_header,
        'new_record_id': new_record_id,
        'mitigations': mitigations,
        'SHIFT_MODELS': tblCyberPHAHeader.SHIFT_MODELS,
        'annual_revenue_str': annual_revenue_str,
        'selected_record_id': record_id,
        'SECURITY_LEVELS': SECURITY_LEVELS

    })


def get_headerrecord(request):
    record_id = request.GET.get('record_id')
    headerrecord = get_object_or_404(tblCyberPHAHeader, ID=record_id)

    # create a dictionary with the record data
    headerrecord_data = {
        'title': headerrecord.title,
        'facility': headerrecord.FacilityName,
        'leader': headerrecord.PHALeader,
        'leaderemail': headerrecord.PHALeaderEmail,
        'industry': headerrecord.Industry,
        'facilitytype': headerrecord.FacilityType,
        'unit': headerrecord.AssessmentUnit,
        'zone': headerrecord.AssessmentZone,
        'startdate': headerrecord.AssessmentStartDate.strftime('%Y-%m-%d'),
        'enddate': headerrecord.AssessmentEndDate.strftime('%Y-%m-%d'),
        'address': headerrecord.facilityAddress,
        'safetysummary': headerrecord.safetySummary,
        'chemicalsummary': headerrecord.chemicalSummary,
        'physicalsummary': headerrecord.physicalSummary,
        'othersummary': headerrecord.otherSummary,
        'compliancesummary': headerrecord.complianceSummary,
        'country': headerrecord.country,
        'shift_model': headerrecord.shift_model,
        'EmployeesOnSite': headerrecord.EmployeesOnSite,
        'cyber_insurance': headerrecord.cyber_insurance,
        'annual_revenue': headerrecord.annual_revenue,
        'pha_score': headerrecord.pha_score,
        'sl_t': headerrecord.sl_t
    }

    control_assessments = MitreControlAssessment.objects.filter(cyberPHA=headerrecord)
    control_effectiveness = math.ceil(calculate_effectiveness(record_id))

    # Create a list of dictionaries for control assessments
    control_assessments_data = []
    for assessment in control_assessments:
        assessment_data = {
            'mitigation_id': assessment.control.id,  # Assuming control has an ID field
            'effectiveness_percentage': assessment.effectiveness_percentage,
            'weighting': assessment.weighting,
            # Add other fields if needed
        }
        control_assessments_data.append(assessment_data)

    response_data = {
        'headerrecord': headerrecord_data,
        'control_assessments': control_assessments_data,
        'control_effectiveness': control_effectiveness
    }

    return JsonResponse(response_data)


def get_response(user_message):
    message = [
        {
            "role": "system",
            "content": "You are an expert and experienced process and safety engineer conducting a cybersecurity risk analysis for a cyberPHA (where P=Process, H=Hazards, A=Analysis) scenario related to industrial automation and control systems."
        },
        user_message
    ]

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=message,
        temperature=0.1,
        max_tokens=800
    )
    return response['choices'][0]['message']['content']


@login_required()
def facility_risk_profile(request):
    if request.method == 'GET':
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        Industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        address = request.GET.get('address')
        country = request.GET.get('country')
        facility = request.GET.get('facility')
        employees = request.GET.get('employees')
        shift_model = request.GET.get('shift_model')

        language = request.session.get('organization_defaults', {}).get('language', 'en')  # 'en' is the default value

        # Check if Industry or facility_type are empty or None
        if not Industry or not facility_type:
            error_msg = "Missing industry or facility type. Complete all fields to get an accurate assessment"
            return JsonResponse({
                'safety_summary': error_msg,
                'chemical_summary': error_msg,
                'physical_security_summary': error_msg,
                'other_summary': error_msg
            })

        openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key
        context = f"You are an expert in risk assessment for industrial facilities. For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, with {employees} employees working a {shift_model} shift model,"

        prompts = [
            f"{context}, provide a concise bullet-point list of the likely personnel safety hazards present. Limit the response to a maximum of 100 words, or less. EXTRA INSTRUCTIONS: Do not give commentary or extra information. List only the specific hazard relevant to the facility. Add a line space between each bullet point.  If {language} is not en then give the response in the language {language} with the english directly underneath",
            f"{context}, provide a concise bullet point list of the likely chemicals stored or used and their hazards given the {facility_type}. Limit the response to a maximum of 100 words, or less. EXTRA INSTRUCTIONS: Only list the chemical - no additional information. Add a line space between each bullet point.  If {language} is not en then give the response in the language {language} with the english directly underneath",
            f"{context}, provide a concise bullet-point list of the most likely Physical security challenges. Limit the response to a maximum of 100 words, or less. EXTRA INSTRUCTION: Add a line space between each bullet point.  If {language} is not en then give the response in the language {language} with the english directly underneath",
            # f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a concise bullet point list of other localized risks that are likely to be identified for a {facility_type} at {address}. Limit the response to a maximum of 100 words, or less. Add a line space between each bullet point"
            f"{context}, provide a concise bullet point list of the likely OT devices and equipment that may be connected to IT networks for monitoring and control at  {facility_type} at {address}. Limit the response to a maximum of 100 words, or less. EXTRA INSTRUCTION: Add a line space between each bullet point.  If {language} is not en then give the response in the language {language} with the english directly underneath",
            f"For a {facility_type} located in {country} operating within the {Industry} industry, please provide a concise bullet point list up to a maximum of 15 of ONLY the most current and most relevant regulatory compliance requirements that will apply to that specific industry and facility and that EXPLICITLY state requirements for cybersecurity controls. List only the full title of the regulation - no additional text or explanation. DO NOT REPEAT OR DUPLICATE TITLES IN THE FINAL LIST.  EXTRA INSTRUCTION: Add a line space between each bullet point. If {language} is not en then give the response in the language {language} with the english directly underneath",
            f"{context}: considering the specific nature of a {facility_type} and the regional industrial safety standards in {country}, estimate a detailed and nuanced PHA risk score. Use a scale from 0 to 100, where 0 indicates an absence of safety hazards and 100 signifies the presence of extreme and imminent fatal hazards. Provide a score reflecting the unique risk factors associated with the facility type and its operational context in {country}. Scores should reflect increments of 10, with each decile corresponding to escalating levels of hazard severity and likelihood of occurrence. Base your score on a typical facility of this type and in this region, adhering to standard safety protocols, equipment conditions, and operational practices. Provide the score as a single, precise number without additional commentary."
        ]

        responses = []

        # Loop through the prompts and make an API call for each one
        def fetch_response(prompt):
            return openai.ChatCompletion.create(
                # model="gpt-4",
                model="gpt-4",
                messages=[
                    {"role": "system",
                     "content": "You are a model trained to provide concise responses. Please provide a concise numbered bullet-point list based on the given statement."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=600
            )

            # Use ThreadPoolExecutor to parallelize the API calls

        with concurrent.futures.ThreadPoolExecutor() as executor:
            responses = list(executor.map(fetch_response, prompts))

            # Extract the individual responses
        safety_summary = responses[0]['choices'][0]['message']['content'].strip()
        chemical_summary = responses[1]['choices'][0]['message']['content'].strip()
        physical_security_summary = responses[2]['choices'][0]['message']['content'].strip()
        other_summary = responses[3]['choices'][0]['message']['content'].strip()
        compliance_summary = responses[4]['choices'][0]['message']['content'].strip()
        pha_score = responses[5]['choices'][0]['message']['content'].strip()

        # Return the individual parts as variables
        return JsonResponse({
            'safety_summary': safety_summary.strip(),
            'chemical_summary': chemical_summary.strip(),
            'physical_security_summary': physical_security_summary.strip(),
            'other_summary': other_summary.strip(),
            'compliance_summary': compliance_summary,
            'pha_score': pha_score
        })


@login_required()
def pha_report(request, cyberpha_id):
    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    cyberPHAHeader = tblCyberPHAHeader.objects.get(ID=cyberpha_id)
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberpha_id, Deleted=0)
    average_impact_safety = cyberScenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    average_impact_danger = cyberScenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    average_impact_environment = cyberScenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    average_impact_production = cyberScenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    average_impact_finance = cyberScenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    average_impact_data = cyberScenarios.aggregate(Avg('impactData'))['impactData__avg']
    average_impact_reputation = cyberScenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    average_impact_regulation = cyberScenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']
    average_impact_supply = cyberScenarios.aggregate(Avg('impactSupply'))['impactSupply__avg']
    total_cost_impact = cyberScenarios.aggregate(Sum('sle'))['sle__sum']
    total_cost_impact_low = cyberScenarios.aggregate(Sum('sle_low'))['sle_low__sum']
    total_cost_impact_high = cyberScenarios.aggregate(Sum('sle_high'))['sle_high__sum']

    control_effectiveness = math.ceil(get_overall_control_effectiveness_score(cyberpha_id))
    # Retrieve the top 5 most effective controls
    top_5_controls = MitreControlAssessment.objects.filter(cyberPHA=cyberpha_id).order_by('-effectiveness_percentage')[
                     :5]

    # Retrieve the bottom 5 least effective controls
    bottom_5_controls = MitreControlAssessment.objects.filter(cyberPHA=cyberpha_id).order_by(
        'effectiveness_percentage')[:5]

    overall_probability = math.ceil(calculate_overall_probability(cyberpha_id))

    return JsonResponse({'cyberPHAHeader': model_to_dict(cyberPHAHeader),
                         'scenarios': list(cyberScenarios.values()),
                         'average_impact_safety': average_impact_safety,
                         'average_impact_danger': average_impact_danger,
                         'average_impact_environment': average_impact_environment,
                         'average_impact_production': average_impact_production,
                         'average_impact_finance': average_impact_finance,
                         'average_impact_data': average_impact_data,
                         'average_impact_reputation': average_impact_reputation,
                         'average_impact_regulation': average_impact_regulation,
                         'average_impact_supply': average_impact_supply,
                         'control_effectiveness': control_effectiveness,
                         'top_5_controls': list(
                             top_5_controls.values('control__name', 'effectiveness_percentage', 'weighting')),
                         'bottom_5_controls': list(
                             bottom_5_controls.values('control__name', 'effectiveness_percentage', 'weighting')),
                         'overall_probability': overall_probability,
                         'total_cost_impact': total_cost_impact,
                         'total_cost_impact_low': total_cost_impact_low,
                         'total_cost_impact_high': total_cost_impact_high
                         })


def get_overall_control_effectiveness_score(cyberPHA_ID):
    """
    Calculate the Overall Control Effectiveness Score for a given cyberPHA_ID.

    Args:
        cyberPHA_ID (int): The ID of the cyberPHA security assessment.

    Returns:
        float: The Overall Control Effectiveness Score.
    """

    # Filter the assessments based on the given cyberPHA_ID
    assessments = MitreControlAssessment.objects.filter(cyberPHA=cyberPHA_ID)

    # Calculate the weighted sum of effectiveness percentages
    weighted_sum = assessments.aggregate(
        total=Sum(F('effectiveness_percentage') * F('weighting'))
    )['total'] or 0

    # Calculate the total weight
    total_weight = assessments.aggregate(total=Sum('weighting'))['total'] or 1

    # Calculate the Overall Control Effectiveness Score
    overall_score = weighted_sum / total_weight

    return overall_score


def calculate_overall_probability(cyberpha_id):
    # Retrieve all scenarios related to the given assessment
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberpha_id, Deleted=0)

    # Start with the probability that none of the scenarios occur
    probability_none_occur = 1.0

    # Iterate over each scenario and update the probability
    for scenario in cyberScenarios:
        probability_value = int(scenario.probability.strip('%'))
        probability_none_occur *= (1 - probability_value / 100.0)

    # Calculate the overall probability that at least one scenario occurs
    overall_probability = 1 - probability_none_occur

    return overall_probability * 100  # Return as a percentage


@login_required()
def phascenarioreport(request):
    cyberPHAID = request.POST.get('cyberPHAID')
    cyberPHAHeader = tblCyberPHAHeader.objects.get(ID=cyberPHAID)
    cyberScenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberPHAID, Deleted=0)

    average_impact_safety = cyberScenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    average_impact_danger = cyberScenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    average_impact_environment = cyberScenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    average_impact_production = cyberScenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    average_impact_finance = cyberScenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    average_impact_data = cyberScenarios.aggregate(Avg('impactData'))['impactData__avg']
    average_impact_reputation = cyberScenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    average_impact_regulation = cyberScenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']

    return render(request, 'phascenarioreport.html', {
        'cyberPHAHeader': cyberPHAHeader,
        'cyberScenarios': cyberScenarios,
        'average_impact_safety': average_impact_safety,
        'average_impact_danger': average_impact_danger,
        'average_impact_environment': average_impact_environment,
        'average_impact_production': average_impact_production,
        'average_impact_finance': average_impact_finance,
        'average_impact_data': average_impact_data,
        'average_impact_reputation': average_impact_reputation,
        'average_impact_regulation': average_impact_regulation
    })


@login_required()
def getSingleScenario(request):
    # Get the ID from the GET parameters
    scenario_id = request.GET.get('id')

    # Try to retrieve the scenario with the given ID
    try:
        scenario = tblCyberPHAScenario.objects.get(ID=scenario_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)

    # Convert the scenario to a dictionary
    scenario_dict = {
        'ID': scenario.ID,
        'CyberPHA': scenario.CyberPHA.ID,
        'Scenario': scenario.Scenario,
        'ThreatClass': scenario.ThreatClass,
        'ThreatAgent': scenario.ThreatAgent,
        'ThreatAction': scenario.ThreatAction,
        'Countermeasures': scenario.Countermeasures,
        'RiskCategory': scenario.RiskCategory,
        'Consequence': scenario.Consequence,
        'impactSafety': scenario.impactSafety,
        'impactDanger': scenario.impactDanger,
        'impactProduction': scenario.impactProduction,
        'impactFinance': scenario.impactFinance,
        'impactReputation': scenario.impactReputation,
        'impactEnvironment': scenario.impactEnvironment,
        'impactRegulation': scenario.impactRegulation,
        'impactData': scenario.impactData,
        'impactSupply': scenario.impactSupply,
        'justifySafety': scenario.justifySafety,
        'justifyLife': scenario.justifyLife,
        'justifyProduction': scenario.justifyProduction,
        'justifyFinancial': scenario.justifyFinancial,
        'justifyReputation': scenario.justifyReputation,
        'justifyEnvironment': scenario.justifyEnvironment,
        'justifyRegulation': scenario.justifyRegulation,
        'justifyData': scenario.justifyData,
        'UEL': scenario.UEL,
        'uel_threat': scenario.uel_threat,
        'uel_vuln': scenario.uel_vuln,
        'uel_exposure': scenario.uel_exposure,
        'RRU': scenario.RRU,
        'SM': scenario.SM,
        'MEL': scenario.MEL,
        'RRM': scenario.RRM,
        'SA': scenario.SA,
        'MELA': scenario.MELA,
        'RRa': scenario.RRa,
        'recommendations': scenario.recommendations,
        'Deleted': scenario.Deleted,
        'timestamp': scenario.timestamp,
        'aro': scenario.aro,
        'sle': scenario.sle,
        'sle_low': scenario.sle_low,
        'sle_high': scenario.sle_high,
        'ale': scenario.ale,
        'countermeasureCosts': scenario.countermeasureCosts,
        'control_recommendations': scenario.control_recommendations,
        'standards': scenario.standards,
        'probability': scenario.probability,
        'risk_register': scenario.risk_register,
        'safety_hazard': scenario.safety_hazard,
        'sis_compromise': scenario.sis_compromise,
        'sis_outage': scenario.sis_outage,
        'risk_priority': scenario.risk_priority,
        'risk_status': scenario.risk_status,
        'risk_owner': scenario.risk_owner,
        'risk_response': scenario.risk_response,
        'risk_open_date': scenario.risk_open_date,
        'risk_close_date': scenario.risk_close_date,
        'control_effectiveness': scenario.control_effectiveness,
        'likelihood': scenario.likelihood,
        'frequency': scenario.frequency,
        'sl_a': scenario.sl_a
    }
    # Retrieve the related PHAControlList records
    control_list = []
    for control in scenario.controls.all():
        control_dict = {
            'ID': control.ID,
            'control': control.control,
            'reference': control.reference,
            'score': control.score
        }
        control_list.append(control_dict)

    # Add the control list to the scenario dictionary
    scenario_dict['controls'] = control_list
    has_controls = 1 if len(control_list) > 0 else 0

    # Add has_controls to the scenario_dict
    scenario_dict['has_controls'] = has_controls

    # Return the scenario as a JSON response
    return JsonResponse(scenario_dict)


# function to calculate overall control effectiveness for a given cyberpha
def calculate_effectiveness(cyberPHA_value):
    # Filter assessments by the given cyberPHA value
    assessments = MitreControlAssessment.objects.filter(cyberPHA=cyberPHA_value)

    # If there are no matching records, return 0
    if not assessments.exists():
        return 0

    # Calculate the numerator (sum of effectiveness_percentage multiplied by weighting)
    numerator = assessments.aggregate(
        total_effectiveness=Sum(F('effectiveness_percentage') * F('weighting'))
    )['total_effectiveness']

    # Calculate the denominator (sum of weighting)
    denominator = assessments.aggregate(total_weighting=Sum('weighting'))['total_weighting']

    # Calculate the weighted average
    if denominator:
        overall_effectiveness = numerator / denominator
    else:
        overall_effectiveness = 0

    return overall_effectiveness


@login_required
def scenario_analysis_estimates_only(request):
    if request.method == 'GET':
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        consequences = request.GET.get('consequence')
        threatSource = request.GET.get('threatsource')
        safetyimpact = request.GET.get('safety')
        lifeimpact = request.GET.get('life')
        productionimpact = request.GET.get('production')
        reputationimpact = request.GET.get('reputation')
        environmentimpact = request.GET.get('environment')
        regulatoryimpact = request.GET.get('regulatory')
        dataimpact = request.GET.get('data')
        supplyimpact = request.GET.get('supply')
        severitymitigated = request.GET.get('sm')
        mitigatedexposure = request.GET.get('mel')
        residualrisk = request.GET.get('rrm')
        country = request.GET.get('country')
        uel = request.GET.get('uel')
        financial = request.GET.get('financial')
        cyberPHAID = request.GET.get('cpha')

        # get the effectiveness of controls for the given cyberPHA
        control_effectiveness = calculate_effectiveness(cyberPHAID)

        def common_content_prefix():
            return f"In the {industry} industry, at a {facility_type} in {country}, given the scenario {scenario} with consequences {consequences}, the threat source is {threatSource} performing actions.  Business impact scores (out of 10) are: safety: {safetyimpact}, life: {lifeimpact}, production: {productionimpact}, reputation: {reputationimpact}, environment: {environmentimpact}, regulatory: {regulatoryimpact}, data: {dataimpact}, and supply: {supplyimpact}. The unmitigated risk likelihood without controls is rated as {uel}/10."

        openai.api_key = os.environ.get('OPENAI_API_KEY')
        # Define the common part of the user message
        common_content = f"Given the scenario {scenario} with consequences {consequences} affecting a {facility_type} in the {industry} industry in {country}, the threat source {threatSource} performing actions. The business impact assessment is as follows,  scores are of 10 where 10 represents maximum impact, impact on safety: {safetyimpact}, danger to life: {lifeimpact}, production and operations: {productionimpact}, company reputation: {reputationimpact}, environmental impact: {environmentimpact}, impact of regulatory consequences: {regulatoryimpact}, supply chain impact: {supplyimpact}  data and intellectual property: {dataimpact}. The effectiveness of current controls has been assessed as: Severity of incident mitigated: {severitymitigated}, risk exposure to the scenario mitigated {mitigatedexposure}, and overall residual risk {residualrisk}. The amount of unmitigated rate without control is assumed to be {uel}"

        # Define the refined user messages
        user_messages = [

            {
                "role": "user",
                "content": f"Given the context: {common_content} and analysis of publicly reported cybersecurity incidents, in the context of an OT Cybersecurity Risk Assessment provide ONLY the estimated likelihood (as a whole number percentage) of a targeted attack based on the specific scenario of {scenario}. Answer with a whole number. Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"Given the detailed context that follows, give an assessment of the residual cybersecurity risk risk after all new recommended controls have been implemented. Based on this, provide a residual risk rating from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High. Context: {common_content_prefix()}, where it is emphasized that new controls have significantly reduced vulnerabilities and threats. The expected outcome is a much lower risk than before. Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"Given the context: {common_content}, estimate the DIRECT COSTS of a single loss event (SLE) in US dollars for the {facility_type} for the scenario: {scenario}. Guidelines: Give three estimates best case, worst case, and most likely case. Output as integers in the format low|medium|high where | is the delimiter between the three integer values. Your estimates should be realistic and specific to the scenario. Consider only the relevant Direct costs which can include all or some of the following depending on the incident: incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. In the business impact analysis the evaluation of financial impact for the given scenario is rated as {financial}/10 by the business. Your response should be a single positive integer for each of the three values in the order low|medium|high without any additional text or commentary."
            },

            {
                "role": "user",
                "content": f"Given the context: {common_content} and analysis of publicly reported cybersecurity incidents, provide ONLY the estimated probability (as a whole number percentage) of a successful targeted attack given that the assessed effectiveness of current cybersecurity controls is {control_effectiveness}% . Answer with a number followed by a percentage sign (e.g., nn%). Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"Given the context: {common_content} and news reports of publicly reported cybersecurity incidents, provide ONLY the estimated frequency of a successful targeted attack of the scenario {scenario} where a successful targeted attack means that it succeeds in causing {consequences} at the {facility_type}. Your answer should be given as an integer that represents the number of times per year to expect such a scenario. If the estimated frequency is less than once per year then provide a decimal to indicate the frequency per year. Do NOT include any other words, sentences, or explanations."
            }

        ]

        # Use ThreadPoolExecutor to parallelize the API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit all the tasks and get a list of futures
            futures = [executor.submit(get_response, msg) for msg in user_messages]
            # Collect the results in the order the futures were submitted
            responses = [future.result() for future in futures]

        # Return the responses as variables
        return JsonResponse({
            'likelihood': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'probability': responses[3],
            'frequency': responses[4]
        })


@login_required
def scenario_analysis(request):
    if request.method == 'GET':
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        consequences = request.GET.get('consequence')
        threatSource = request.GET.get('threatsource')
        safetyimpact = request.GET.get('safety')
        lifeimpact = request.GET.get('life')
        productionimpact = request.GET.get('production')
        reputationimpact = request.GET.get('reputation')
        environmentimpact = request.GET.get('environment')
        regulatoryimpact = request.GET.get('regulatory')
        dataimpact = request.GET.get('data')
        supplyimpact = request.GET.get('supply')
        severitymitigated = request.GET.get('sm')
        mitigatedexposure = request.GET.get('mel')
        residualrisk = request.GET.get('rrm')
        standards = request.GET.get('standards')
        country = request.GET.get('country')
        uel = request.GET.get('uel')
        financial = request.GET.get('financial')
        cyberPHAID = request.GET.get('cpha')

        # get the effectiveness of controls for the given cyberPHA
        control_effectiveness = calculate_effectiveness(cyberPHAID)

        def common_content_prefix():
            return f"In the {industry} industry, at a {facility_type} in {country}, given the scenario {scenario} with consequences {consequences}, the threat source is {threatSource} performing actions.  Business impact scores (out of 10) are: safety: {safetyimpact}, life: {lifeimpact}, production: {productionimpact}, reputation: {reputationimpact}, environment: {environmentimpact}, regulatory: {regulatoryimpact}, data: {dataimpact}, and supply: {supplyimpact}. The unmitigated risk likelihood without controls is rated as {uel}/10."

        openai.api_key = os.environ.get('OPENAI_API_KEY')
        # Define the common part of the user message
        common_content = f"Given the scenario {scenario} with consequences {consequences} affecting a {facility_type} in the {industry} industry in {country}, the threat source {threatSource} performing actions. The business impact assessment is as follows,  scores are of 10 where 10 represents maximum impact, impact on safety: {safetyimpact}, danger to life: {lifeimpact}, production and operations: {productionimpact}, company reputation: {reputationimpact}, environmental impact: {environmentimpact}, impact of regulatory consequences: {regulatoryimpact}, supply chain impact: {supplyimpact}  data and intellectual property: {dataimpact}. The effectiveness of current controls has been assessed as: Severity of incident mitigated: {severitymitigated}, risk exposure to the scenario mitigated {mitigatedexposure}, and overall residual risk {residualrisk}. The amount of unmitigated rate without control is assumed to be {uel}"

        # Define the refined user messages
        user_messages = [

            {
                "role": "user",
                "content": f"Given the context: {common_content} and analysis of publicly reported cybersecurity incidents, in the context of an OT Cybersecurity Risk Assessment provide ONLY the estimated likelihood (as a whole number percentage) of a targeted attack based on the specific scenario of {scenario}. Answer with a whole number. Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"Given the detailed context that follows, give an assessment of the residual cybersecurity risk risk after all new recommended controls have been implemented. Based on this, provide a residual risk rating from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High. Context: {common_content_prefix()}, where it is emphasized that new controls have significantly reduced vulnerabilities and threats. The expected outcome is a much lower risk than before. Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"Given the context: {common_content}, estimate the DIRECT COSTS of a single loss event (SLE) in US dollars for the {facility_type} for the scenario: {scenario}. Guidelines: Give three estimates best case, worst case, and most likely case. Output as integers in the format low|medium|high where | is the delimiter between the three integer values. Your estimates should be realistic and specific to the scenario. Consider only the relevant Direct costs which can include all or some of the following depending on the incident: incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. In the business impact analysis the evaluation of financial impact for the given scenario is rated as {financial}/10 by the business. Your response should be a single positive integer for each of the three values in the order low|medium|high without any additional text or commentary."
            },

            {
                "role": "user",
                "content": f"Using the {standards} standard and the following context, concisely provide up to 10 key recommendations and their reference section in {standards} in 200 words or less for a CyberPHA. Context: {common_content_prefix()}. Each recommendation should be formatted as follows: 'X (where 'X' is the recommendation number). Recommendation text (academic citation to reference within {standards}). No preamble or commentary"
            },
            {
                "role": "user",
                "content": f"Given the context: {common_content} and analysis of publicly reported cybersecurity incidents, provide ONLY the estimated probability (as a whole number percentage) of a successful targeted attack given that the assessed effectiveness of current cybersecurity controls is {control_effectiveness}% . Answer with a number followed by a percentage sign (e.g., nn%). Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"Given the context: {common_content} and news reports of publicly reported cybersecurity incidents, provide ONLY the estimated frequency of a successful targeted attack of the scenario {scenario} where a successful targeted attack means that it succeeds in causing {consequences} at the {facility_type}. Your answer should be given as an integer that represents the number of times per year to expect such a scenario. If the estimated frequency is less than once per year then provide a decimal to indicate the frequency per year. Do NOT include any other words, sentences, or explanations."
            }

        ]

        def get_response_safe(user_message):
            try:
                return get_response(user_message)
            except Exception as e:
                return f"Error: {str(e)}"

        # Initialize an empty list to store the responses
        responses = []

        # Use ThreadPoolExecutor to parallelize the API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit all the tasks and get a list of futures
            futures = [executor.submit(get_response, msg) for msg in user_messages]
            # Collect the results in the order the futures were submitted
            responses = [future.result() for future in futures]

        r_list = parse_recommendations((responses[3]))

        # Return the responses as variables
        return JsonResponse({
            'likelihood': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'recommendations': responses[3],
            'probability': responses[4],
            'frequency': responses[5],
            'control_effectiveness': control_effectiveness,
            'r_list': r_list
        })


def parse_recommendations(recommendations_str):
    # Regular expression to match the format
    pattern = re.compile(r'(\d+)\.\s(.*?)(\([^)]+\))')  # This regex captures any content within brackets

    matches = pattern.findall(recommendations_str)

    # Convert matches to a list of dictionaries
    parsed_data = [{
        'line_number': int(match[0]),
        'control_text': match[1].strip(),
        'reference': match[2]
    } for match in matches]

    return parsed_data


def scenario_vulnerability(request, scenario_id):
    try:
        scenario = tblCyberPHAScenario.objects.get(pk=scenario_id)
        vulnerabilities = vulnerability_analysis.objects.filter(scenario=scenario)
        asset_types = tblAssetType.objects.all()  # Fetch asset types

        if request.method == 'POST':
            form = VulnerabilityAnalysisForm(request.POST)
            if form.is_valid():
                form.save()
                # Redirect to the 'scenario_vulnerability' view with the scenario_id
                return redirect('OTRisk:scenario_vulnerability', scenario_id=scenario_id)
        else:
            form = VulnerabilityAnalysisForm()

        return render(request, 'OTRisk/vulnerability_table.html', {
            'scenario': scenario,
            'vulnerabilities': vulnerabilities,
            'form': form,
            'scenario_id_value': scenario_id,
            'asset_types': asset_types
        })
    except tblCyberPHAScenario.DoesNotExist:
        # Handle the scenario not found error, e.g., return a 404 page
        return render(request, 'no_vulnerabilities.html')


def add_vulnerability(request, scenario_id):
    scenario = get_object_or_404(tblCyberPHAScenario, pk=scenario_id)
    action = request.POST.get('action')
    if request.method == 'POST':
        if action == 'save':  # Check if Save button was clicked
            description = request.POST.get('description')
            asset_type_id = request.POST.get('asset_type')
            asset_name = request.POST.get('asset_name')
            cve = request.POST.get('cve')
            cve_detail = request.POST.get('cve_detail')

            # Create a new vulnerability instance and save it
            vulnerability = vulnerability_analysis(
                description=description,
                asset_name=asset_name,
                asset_type_id=asset_type_id,
                cve=cve,
                scenario=scenario,
                cve_detail=cve_detail
            )
            vulnerability.save()

        elif action == 'edit':  # Check if Update button was clicked
            vulnerability_id = request.POST.get('vulnerability_id')
            description = request.POST.get('description')
            asset_type_id = request.POST.get('asset_type')
            asset_name = request.POST.get('asset_name')
            cve = request.POST.get('cve')
            cve_detail = request.POST.get('cve_detail')

            # Get the existing vulnerability instance
            vulnerability = get_object_or_404(vulnerability_analysis, pk=vulnerability_id)

            # Update the fields and save
            vulnerability.description = description
            vulnerability.asset_type_id = asset_type_id
            vulnerability.asset_name = asset_name
            vulnerability.cve = cve
            vulnerability.cve_detail = cve_detail
            vulnerability.save()

    return redirect('OTRisk:scenario_vulnerability', scenario_id=scenario_id)


def get_asset_types(request):
    asset_types = tblAssetType.objects.all()
    asset_type_list = [{'id': asset_type.id, 'AssetType': asset_type.AssetType} for asset_type in asset_types]
    return JsonResponse({'asset_types': asset_type_list})


def generate_ppt(request):
    if request.method == "POST":

        # Extract data from POST parameters
        safety = request.POST.get('txtSafetySummary', '')
        chemical = request.POST.get('txtChemical', '')
        physical = request.POST.get('txtPhysical', '')
        other = request.POST.get('txtOther', '')
        compliance = request.POST.get('txtCompliance', '')
        facility = request.POST.get('FacilityName', '')

        # Create a new PowerPoint presentation
        prs = Presentation()

        # For each section, add a slide and set its title and content
        sections = [
            (f"{facility} Safety Profile", safety),
            (f"{facility} Chemical Profile", chemical),
            (f"{facility} Physical Security Profile", physical),
            (f"{facility} OT Asset Profile", other),
            (f"{facility} Compliance Profile", compliance)
        ]

        for title, content in sections:
            slide_layout = prs.slide_layouts[1]  # Using a title and content layout
            slide = prs.slides.add_slide(slide_layout)
            title_shape = slide.shapes.title
            content_shape = slide.placeholders[1]  # Using the primary content placeholder

            title_shape.text = title
            title_shape.text_frame.paragraphs[0].font.name = 'Arial'
            title_shape.text_frame.paragraphs[0].font.size = Pt(18)

            content_shape.text = content
            for paragraph in content_shape.text_frame.paragraphs:
                paragraph.font.name = 'Arial'
                paragraph.font.size = Pt(10)

        # Save to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pptx') as temp_file:
            prs.save(temp_file.name)
            temp_path = temp_file.name

        # Return a response to provide the file for download
        response = FileResponse(open(temp_path, 'rb'),
                                content_type='application/vnd.openxmlformats-officedocument.presentationml.presentation')
        response['Content-Disposition'] = 'attachment; filename=report.pptx'

        # Remove the temporary file after sending it to the client
        os.remove(temp_path)
        filename = f"report_{uuid.uuid4()}.pptx"

        filepath = os.path.join(os.path.join(BASE_DIR, 'static'), filename)

        prs.save(filepath)
        download_url = os.path.join(settings.STATIC_URL, filename)

        return JsonResponse({
            'status': 'success',
            'download_url': download_url
        })

    else:
        return JsonResponse({
            'status': 'error',
            'error': 'Invalid request method'
        })
