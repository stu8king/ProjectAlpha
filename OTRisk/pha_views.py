from django.forms import model_to_dict

from OTRisk.models.Model_CyberPHA import tblIndustry, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario, vulnerability_analysis, tblAssetType, tblMitigationMeasures, MitreControlAssessment
from OTRisk.models.raw import MitreICSMitigations
from OTRisk.models.questionnairemodel import FacilityType
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date
from django.views import View
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import openai
import re
from django.db.models import Avg, Sum, F
import concurrent.futures
import os
import math
from .dashboard_views import get_user_organization_id
from django.contrib.auth.models import User
from concurrent.futures import ThreadPoolExecutor, as_completed
from .forms import VulnerabilityAnalysisForm
import aiohttp
import asyncio
from django.core import serializers


@login_required
def iotaphamanager(request):
    pha_header = None
    new_record_id = None  # Initialize new_record_id to None
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
        pha_header.country = request.POST.get('countrySelector')
        pha_header.UserID = request.user.id
        pha_header.save()

        new_record_id = pha_header.ID

    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    pha_header_records = tblCyberPHAHeader.objects.filter(UserID__in=users_in_organization)

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
        'mitigations': mitigations
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
        'country': headerrecord.country
    }

    control_assessments = MitreControlAssessment.objects.filter(cyberPHA=headerrecord)

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
        facility = request.GET.get('txtFacility')

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

        prompts = [
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a concise bullet-point list of the likely personnel safety hazards present at {address}. Limit the response to a maximum of 100 words, or less. Add a line space between each bullet point",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a concise bullet point list of the likely chemicals stored or used and their hazards given the {facility_type}. Limit the response to a maximum of 100 words, or less. Add a line space between each bullet point",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a concise bullet-point list of the Physical security challenges given the location of {address}, {country}. Limit the response to a maximum of 100 words, or less. Add a line space between each bullet point",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a concise bullet point list of other localized risks that are likely to be identified for a {facility_type} at {address}. Limit the response to a maximum of 100 words, or less. Add a line space between each bullet point"
        ]

        responses = []

        # Loop through the prompts and make an API call for each one
        def fetch_response(prompt):
            return openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system",
                     "content": "You are a model trained to provide concise responses. Please provide a concise numbered bullet-point list based on the given statement."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500
            )

            # Use ThreadPoolExecutor to parallelize the API calls

        with concurrent.futures.ThreadPoolExecutor() as executor:
            responses = list(executor.map(fetch_response, prompts))

            # Extract the individual responses
        safety_summary = responses[0]['choices'][0]['message']['content'].strip()
        chemical_summary = responses[1]['choices'][0]['message']['content'].strip()
        physical_security_summary = responses[2]['choices'][0]['message']['content'].strip()
        other_summary = responses[3]['choices'][0]['message']['content'].strip()

        # Return the individual parts as variables
        return JsonResponse({
            'safety_summary': safety_summary.strip(),
            'chemical_summary': chemical_summary.strip(),
            'physical_security_summary': physical_security_summary.strip(),
            'other_summary': other_summary.strip()
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
    top_5_controls = MitreControlAssessment.objects.filter(cyberPHA=cyberpha_id).order_by('-effectiveness_percentage')[:5]

    print(top_5_controls)
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
        'CyberPHA': scenario.CyberPHA,
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
        'justifySafety': scenario.justifySafety,
        'justifyLife': scenario.justifyLife,
        'justifyProduction': scenario.justifyProduction,
        'justifyFinancial': scenario.justifyFinancial,
        'justifyReputation': scenario.justifyReputation,
        'justifyEnvironment': scenario.justifyEnvironment,
        'justifyRegulation': scenario.justifyRegulation,
        'justifyData': scenario.justifyData,
        'UEL': scenario.UEL,
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
        'probability': scenario.probability

    }

    # Return the scenario as a JSON response
    return JsonResponse(scenario_dict)


@login_required()
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

        def common_content_prefix():
            return f"In the {industry} industry, at a {facility_type} in {country}, given the scenario {scenario} with consequences {consequences}, the threat source is {threatSource} performing actions.  Business impact scores (out of 10) are: safety: {safetyimpact}, life: {lifeimpact}, production: {productionimpact}, reputation: {reputationimpact}, environment: {environmentimpact}, regulatory: {regulatoryimpact}, data: {dataimpact}, and supply: {supplyimpact}. The unmitigated risk without controls is rated as {uel}/10."

        openai.api_key = os.environ.get('OPENAI_API_KEY')
        # Define the common part of the user message
        common_content = f"Given the scenario {scenario} with consequences {consequences} affecting a {facility_type} in the {industry} industry in {country}, the threat source {threatSource} performing actions. The business impact assessment is as follows,  scores are of 10 where 10 represents maximum impact, impact on safety: {safetyimpact}, danger to life: {lifeimpact}, production and operations: {productionimpact}, company reputation: {reputationimpact}, environmental impact: {environmentimpact}, impact of regulatory consequences: {regulatoryimpact}, supply chain impact: {supplyimpact}  data and intellectual property: {dataimpact}. The effectiveness of current controls has been assessed as: Severity of incident mitigated: {severitymitigated}, risk exposure to the scenario mitigated {mitigatedexposure}, and overall residual risk {residualrisk}. The amount of unmitigated rate without control is assumed to be {uel}"

        # Define the refined user messages
        user_messages = [
            {
                "role": "user",
                "content": f"Based on the following context, concisely list the necessary OT and ICS cybersecurity controls in order of effectiveness. Limit to 100 words. Context: {common_content_prefix()}. Give the response only. No preamble or commentary"
            },
            ##{
            ##    "role": "user",
            ##    "content": f"Based on the following context, provide the cyberPHA adjusted severity score (Sa) out of 10. Context: {common_content_prefix()}. Answer with a number . Do NOT include any other words, sentences, or explanations."
            ##},
            ##{
            ##    "role": "user",
            ##    "content": f"Based on the following context, provide the adjusted exposure level (MELa) out of 10. Context: {common_content_prefix()}. Answer with a number . Do NOT include any other words, sentences, or explanations."
            ##},
            {
                "role": "user",
                "content": f"Given the detailed context that follows, give an assessment of the residual cybersecurity risk risk after all new recommended controls have been implemented. Based on this, provide a residual risk rating from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High. Context: {common_content_prefix()}, where it's emphasized that new controls have significantly reduced vulnerabilities and threats. The expected outcome is a much lower risk than before. Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"Given the context: {common_content_prefix()}, estimate the DIRECT COSTS of a single loss event (SLE) in US dollars for the {facility_type} for the scenario: {scenario}. Guidelines: Give three estimates best case, worst case, and most likely case. Output as integers in the format low|medium|high where | is the delimiter between the three integer values. Your estimates should be realistic and specific to the scenario. Consider only the relevant Direct costs which can include all or some of the following depending on the incident: incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. In the business impact analysis the evaluation of financial impact for the given scenario is rated as {financial}/10 by the business. Your response should be a single positive integer for each of the three values in the order low|medium|high without any additional text or commentary."
            },

            {
                "role": "user",
                "content": f"Using the {standards} standard and the following context, concisely provide up to 10 key recommendations and their reference section in {standards} in 200 words or less for a CyberPHA. Context: {common_content_prefix()}. Give the response only. No preamble or commentary"
            },
            {
                "role": "user",
                "content": f"Given the context: {common_content_prefix()} and analysis of publicly reported cybersecurity incidents, provide ONLY the estimated probability (as a percentage) of a successful targeted attack given the current controls given in the context. Answer with a number followed by a percentage sign (e.g., 'nn%'). Do NOT include any other words, sentences, or explanations."
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

        # Return the responses as variables
        return JsonResponse({
            'controls': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'recommendations': responses[3],
            'probability': responses[4]
        })


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

            # Create a new vulnerability instance and save it
            vulnerability = vulnerability_analysis(
                description=description,
                asset_name=asset_name,
                asset_type_id=asset_type_id,
                cve=cve,
                scenario=scenario,
            )
            vulnerability.save()

        elif action == 'edit':  # Check if Update button was clicked
            vulnerability_id = request.POST.get('vulnerability_id')
            description = request.POST.get('description')
            asset_type_id = request.POST.get('asset_type')
            asset_name = request.POST.get('asset_name')
            cve = request.POST.get('cve')

            # Get the existing vulnerability instance
            vulnerability = get_object_or_404(vulnerability_analysis, pk=vulnerability_id)

            # Update the fields and save
            vulnerability.description = description
            vulnerability.asset_type_id = asset_type_id
            vulnerability.asset_name = asset_name
            vulnerability.cve = cve
            vulnerability.save()

    return redirect('OTRisk:scenario_vulnerability', scenario_id=scenario_id)


def get_asset_types(request):
    asset_types = tblAssetType.objects.all()
    asset_type_list = [{'id': asset_type.id, 'AssetType': asset_type.AssetType} for asset_type in asset_types]
    return JsonResponse({'asset_types': asset_type_list})
