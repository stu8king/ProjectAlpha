from OTRisk.models.Model_CyberPHA import tblIndustry, tblThreatSources, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario
from OTRisk.models.questionnairemodel import FacilityType
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date
from django.views import View
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import openai
import re
from django.db.models import Avg


@login_required
def iotaphamanager(request):
    if request.method == 'POST':
        pha_header = tblCyberPHAHeader(
            PHALeader=request.POST.get('txtLeader'),
            PHALeaderEmail=request.POST.get('txtLeaderEmail'),
            FacilityName=request.POST.get('txtFacility'),
            Industry=request.POST.get('selIndustry'),
            FacilityType=request.POST.get('selFacilityType'),
            AssessmentUnit=request.POST.get('txtUnit'),
            AssessmentZone=request.POST.get('selZone'),
            AssessmentStartDate=request.POST.get('txtStartDate'),
            AssessmentEndDate=request.POST.get('txtEndDate'),
            facilityAddress=request.POST.get('txtAddress'),
            safetySummary=request.POST.get('txtSafetySummary'),
            chemicalSummary=request.POST.get('txtChemical'),
            physicalSummary=request.POST.get('txtPhysical'),
            otherSummary=request.POST.get('txtOther')
        )
        pha_header.save()

    pha_header_records = tblCyberPHAHeader.objects.all().order_by('ID')
    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    zones = tblZones.objects.all().order_by('PlantZone')
    standardslist = tblStandards.objects.all().order_by('standard')

    return render(request, 'iotaphamanager.html', {
        'pha_header_records': pha_header_records,
        'industries': industries,
        'facilities': facilities,
        'zones': zones,
        'standardslist': standardslist
    })


def get_headerrecord(request):
    print("test1")
    record_id = request.GET.get('record_id')
    print(f"{record_id}")
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
        'othersummary': headerrecord.otherSummary
    }

    return JsonResponse(headerrecord_data)


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

        openai.api_key = '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'
        # Define the common part of the user message
        common_content = f"Given the scenario {scenario} with consequences {consequences} affecting a {facility_type} in the {industry} industry, the threat source {threatSource} performing actions {threatActions}, and current controls {currentControls}. The business impact assessment, giving scores out of 10 where 10 represents maximum impact,  rates safety as {safetyimpact}, danger to life as {lifeimpact}, production and operations as {productionimpact}, company reputation as {reputationimpact}, environmental consequences as {environmentimpact}, regulatory consequences as {regulatoryimpact}, and data and intellectual property as {dataimpact}. The effectiveness of current controls is analyzed as severity of the threat mitigated {severitymitigated}, risk exposure mitigated {mitigatedexposure}, and residual risk {residualrisk}."

        # Define the five user messages
        user_messages = [
            {"role": "user",
             "content": common_content + f" As a bullet point list, list the recommended controls, in the context of a cyberPHA, in order of effectiveness, to address the scenario and consequences. Do not list controls that are in {currentControls}."},
            {"role": "user",
             "content": common_content + "The Adjusted Severity Score (Sa) in the context of a CyberPHA (Cyber Process Hazard Analysis) is a measure of the potential severity of a cyber threat, taking into account the effectiveness of existing countermeasures or mitigation measures. Without any additional text or commentary, giving only the number, provide the cyberPHA adjusted severity score (Sa) (out of 10) after applying recommended controls where 10 is indicated that controls are almost completed effective and a score of 0 would indicate that controls have zero effect.."},
            {"role": "user",
             "content": common_content + f" In the context of a cyber process hazard analysis - CyberPHA - the Adjusted Exposure Level (MELa) is a measure of the potential exposure to a threat after mitigation measures have been applied. MELa is a measure of the remaining risk after you've done everything you can to protect against a threat. Without any additional text or commentary, giving only the number, provide the amount of mitigated exposure (out of 10) after applying new controls on top of {currentControls} for {scenario}."},
            {"role": "user",
             "content": common_content + " In the context of a cyber Process Hazard Analysis (cyberPHA), the Adjusted Residual Risk (RRa) is a measure of the remaining risk after all mitigation measures or controls have been implemented.Without any additional text or commentary, giving only the single word response, provide the residual risk rating (Low, Medium, or High) after applying new controls for {scenario}."},
            {"role": "user",
             "content": common_content + f" Using {standards} as the source, provide a list, without any additional commentary, text, or headings other than the specific requested information, a maximum of 5 key recommendations  that are most relevant to the CyberPHA and an assessment of operational technology - OT - with a paeticular focus on safety and environmental controls (make it the top 5 that give the most value and risk mitigation and do not include any currently implemented controls listed in the following: {currentControls}), to address the scenario aligned with the specifically named {standards} standards. Each recommendation should be in the format '[recommendation text] ([reference])', where '[reference]' is the relevant section from {standards}. References should be given in a manner that enables the user to quickly identify where to locate the related information within {standards}"},
        ]

        # Initialize an empty list to store the responses
        responses = []

        # Make the API calls to the OpenAI GPT-3 API using the user messages
        for user_message in user_messages:
            message = [
                {
                    "role": "system",
                    "content": "You are a process and safety engineer conducting a risk analysis for a cyberPHA scenario related to industrial automation and control systems."
                },
                user_message
            ]

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # Use the GPT-3 engine
                messages=message,
                temperature=0,
                max_tokens=256
            )

            # Extract the generated response from the API and add it to the responses list
            responses.append(response['choices'][0]['message']['content'])

        # Return the responses as variables
        return JsonResponse({
            'controls': responses[0],
            'adjustedSeverity': responses[1],
            'adjustedExposure': responses[2],
            'adjustedRR': responses[3],
            'recommendations': responses[4]
        })


def facility_risk_profile(request):
    if request.method == 'GET':
        print(f"{request.GET}")
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        Industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        address = request.GET.get('address')

        Industry = Industry
        facility_type = facility_type
        address = address

        # Prepare the request data for the OpenAI GPT-3 API in the chat format
        message = [
            {
                "role": "system",
                "content": "As a physical security and cybersecurity risk assessment professional, I need you to assess and determine the risk profile of a given location based on it’s address and the type of facility that it represents."
            },
            {
                "role": "user",
                "content": f"Provide, without any commentary or additional information only the four specific pieces of information that are asked for. Profile a one sentence narrative for each of the four specific piece of information: 1. Summary of most likely safety hazards. 2. Summary of most likely chemicals stored at the facility and their associated hazards. 3. Summary of most likely physical security status and challenges. 4. Any other localized risks to note:\nAddress - {address}, Industry - {Industry}, facility type - {facility_type} Provide only the four pieces of information that have been requested. No title or header. The output must be given as simply <safety summary>|<chemical summary>|<physical security summary>|<other summary>."
            }
        ]

        openai.api_key = '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'

        # Make the API call to the OpenAI GPT-3 API using the message
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use the GPT-3 engine
            messages=message,
            temperature=0.3,
            max_tokens=256
        )

        # Extract the generated response from the API
        generated_response = response['choices'][0]['message']['content']

        # Split the generated response into individual parts
        safety_summary, chemical_summary, physical_security_summary, other_summary = generated_response.split("|")

        # Return the individual parts as variables
        return JsonResponse({
            'safety_summary': safety_summary,
            'chemical_summary': chemical_summary,
            'physical_security_summary': physical_security_summary,
            'other_summary': other_summary
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

    print(f"{average_impact_safety}")

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
        'control_recommendations': scenario.control_recommendations
    }

    # Return the scenario as a JSON response
    return JsonResponse(scenario_dict)
