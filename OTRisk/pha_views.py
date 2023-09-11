from django.forms import model_to_dict

from OTRisk.models.Model_CyberPHA import tblIndustry, tblThreatSources, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario
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
from django.db.models import Avg
import concurrent.futures
import os
from .dashboard_views import get_user_organization_id
from django.contrib.auth.models import User


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

    return render(request, 'iotaphamanager.html', {
        'pha_header_records': pha_header_records,
        'industries': industries,
        'facilities': facilities,
        'zones': zones,
        'standardslist': standardslist,
        'current_pha_header': pha_header,
        'new_record_id': new_record_id
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

    return JsonResponse(headerrecord_data)


def get_response(user_message):
    message = [
        {
            "role": "system",
            "content": "You are an expert and experienced process and safety engineer conducting a cybersecurity risk analysis for a cyberPHA (where P=Process, H=Hazards, A=Analysis) scenario related to industrial automation and control systems."
        },
        user_message
    ]

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=message,
        temperature=0.2,
        max_tokens=800
    )
    return response['choices'][0]['message']['content']


def scenario_analysis(request):
    if request.method == 'GET':
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        consequences = request.GET.get('consequence')
        threatSource = request.GET.get('threatsource')
        currentControls = request.GET.get('selectedMitigationOptions')
        threatActions = request.GET.get('selectedThreatOptions')
        safetyimpact = request.GET.get('safety')
        lifeimpact = request.GET.get('life')
        productionimpact = request.GET.get('production')
        reputationimpact = request.GET.get('reputation')
        environmentimpact = request.GET.get('environment')
        regulatoryimpact = request.GET.get('regulatory')
        dataimpact = request.GET.get('data')
        severitymitigated = request.GET.get('sm')
        mitigatedexposure = request.GET.get('mel')
        residualrisk = request.GET.get('rrm')
        standards = request.GET.get('standard')
        country = request.GET.get('country')

        openai.api_key = os.environ.get('OPENAI_API_KEY')
        # Define the common part of the user message
        common_content = f"Given the scenario {scenario} with consequences {consequences} affecting a {facility_type} in the {industry} industry, the threat source {threatSource} performing actions {threatActions}, and current controls {currentControls}. The business impact assessment, giving scores out of 10 where 10 represents maximum impact,  rates safety as {safetyimpact}, danger to life as {lifeimpact}, production and operations as {productionimpact}, company reputation as {reputationimpact}, environmental consequences as {environmentimpact}, regulatory consequences as {regulatoryimpact}, and data and intellectual property as {dataimpact}. The effectiveness of current controls is analyzed as severity of the threat mitigated {severitymitigated}, risk exposure mitigated {mitigatedexposure}, and residual risk {residualrisk}."

        # Define the five user messages
        user_messages = [
            {"role": "user",
             "content": common_content + f" As a bullet point list, list the recommended controls, in the context of a cyberPHA, in order of effectiveness, to address the scenario and consequences. Do not list controls that are in {currentControls}."},
            {"role": "user",
             "content": common_content + f"The Adjusted Severity Score (Sa) in the context of a CyberPHA (Cyber Process Hazard Analysis) is a measure of the potential severity of a cyber threat, taking into account the effectiveness of existing countermeasures or mitigation measures. Without any additional text or commentary, giving only the number, provide the cyberPHA adjusted severity score (Sa) (out of 10) after applying recommended controls where 10 is indicated that controls are almost completed effective and a score of 0 would indicate that controls have zero effect.."},
            {"role": "user",
             "content": common_content + f" In the context of a cyber process hazard analysis - CyberPHA - the Adjusted Exposure Level (MELa) is a measure of the potential exposure to a threat after mitigation measures have been applied. MELa is a measure of the remaining risk after you've done everything you can to protect against a threat. Without any additional text or commentary, giving only the number, provide the amount of mitigated exposure (out of 10) after applying new controls on top of {currentControls} for {scenario}."},
            {"role": "user",
             "content": common_content + f" In the context of a cyber Process Hazard Analysis (cyberPHA), the Adjusted Residual Risk (RRa) is a measure of the remaining risk after all mitigation measures or controls have been implemented.Without any additional text or commentary, giving only the single word response, provide the residual risk rating (Low, Medium, or High) after applying new controls for {scenario}."},
            {"role": "user",
             "content": common_content + f" In the context of a cyberPHA, estimate the cost impact of the following scenario in US dollars. CRITICAL INSTRUCTION: You must provide a single number with no commentary or explanation. Consider the scenario at a {facility_type} in the {industry} industry. Use the BIA scores: safety {safetyimpact}/10, life {lifeimpact}/10, production {productionimpact}/10, reputation {reputationimpact}/10, environment {environmentimpact}/10, regulatory {regulatoryimpact}/10, and data {dataimpact}/10. Provide only a numeric value with the correct currency symbol for {country}. Scenario: {scenario}."},
            # {"role": "user",
            #  "content": common_content + f" Using {standards} as a reference, provide a list, without any additional commentary, text, or headings other than the specific requested information, a maximum of 5 key recommendations  that are most relevant to the CyberPHA and an assessment of operational technology - OT - with a particular focus on safety and environmental controls (make it the top 5 that give the most value and risk mitigation and do not include any currently implemented controls listed in the following: {currentControls}), to address the scenario aligned with the specifically named {standards} standards. Each recommendation should be in the format '[recommendation text] ([reference])', where '[reference]' is the relevant section from {standards}. References should be given in a manner that enables the user to quickly identify where to locate the related information within {standards}"},
            {
                "role": "user",
                "content": common_content + f"Using the {standards} standard as a reference, provide a list of up to 5 key recommendations most relevant to the CyberPHA and the scenario of {scenario}: and an assessment of operational technology (OT) with a focus on safety and environmental controls. Prioritize recommendations that offer the most value and risk mitigation. Exclude any controls already implemented as listed in {currentControls}. Each recommendation should be presented in the format '[recommendation text] ([reference to specific section in {standards}])’. Your audience is cybersecurity leaders, engineering operators, and risk management professionals. Ensure the references are clear and enable quick identification within the {standards} standard."
            }
        ]

        # Initialize an empty list to store the responses
        responses = []

        # Use ThreadPoolExecutor to parallelize the API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            responses = list(executor.map(get_response, user_messages))

        # Return the responses as variables
        return JsonResponse({
            'controls': responses[0],
            'adjustedSeverity': responses[1],
            'adjustedExposure': responses[2],
            'adjustedRR': responses[3],
            'costs': responses[4],
            'recommendations': responses[5]
        })


def facility_risk_profile(request):
    if request.method == 'GET':
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        Industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        address = request.GET.get('address')
        country = request.GET.get('country')
        facility = request.GET.get('txtFacility')

        openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key

        prompts = [
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a user friendly formatted bullet-point list of the likely safety hazards and hazards to human life present at {address}. Limited the response to a maximum of 150 words",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a user friendly formatted bullet point list of the likely chemicals stored or used and their hazards given the {facility_type}. Limited the response to a maximum of 150 words",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a user friendly formatted bullet-point list of the Physical security standards and challenges or the most likely physical security challenges given the location of {address}, {country}. Limited the response to a maximum of 150 words",
            f"For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, provide a user friendly formatted bullet point list of other localized risks that are likely to be identified for a {facility_type} at {address}. Limited the response to a maximum of 150 words"
        ]

        responses = []

        # Loop through the prompts and make an API call for each one
        for prompt in prompts:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system",
                     "content": "You are a model trained to provide concise responses. Please provide a numbered bullet-point list based on the given statement."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=256
            )
            # Append the response to the responses list
            responses.append(response['choices'][0]['message']['content'])

            # Extract the individual responses
        safety_summary, chemical_summary, physical_security_summary, other_summary = responses

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
    return JsonResponse({'cyberPHAHeader': model_to_dict(cyberPHAHeader),
                         'scenarios': list(cyberScenarios.values()),
                         'average_impact_safety': average_impact_safety,
                         'average_impact_danger': average_impact_danger,
                         'average_impact_environment': average_impact_environment,
                         'average_impact_production': average_impact_production,
                         'average_impact_finance': average_impact_finance,
                         'average_impact_data': average_impact_data,
                         'average_impact_reputation': average_impact_reputation,
                         'average_impact_regulation': average_impact_regulation
                         })


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
        'ale': scenario.ale,
        'countermeasureCosts': scenario.countermeasureCosts,
        'control_recommendations': scenario.control_recommendations,
        'standards': scenario.standards
    }

    # Return the scenario as a JSON response
    return JsonResponse(scenario_dict)
