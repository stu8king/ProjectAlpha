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
import concurrent.futures
import os


@login_required
def iotaphamanager(request):
    print(f"{request.POST}")
    pha_header = None
    if request.method == 'POST':
        pha_id = request.POST.get('txtHdnCyberPHAID')
        if pha_id and int(pha_id) > 0:
            # Update existing record
            pha_header, created = tblCyberPHAHeader.objects.get_or_create(ID=pha_id)
        else:
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
        'standardslist': standardslist,
        'current_pha_header': pha_header
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
        temperature=0,
        max_tokens=500
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

        # openai.api_key = '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'
        openai.api_key = os.environ.get('OPENAI_API_KEY')
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
             "content": common_content + f"In the context of a cybersecurity assessment and associated Process Hazard Analysis (cyberPHA),  analyse the following scenario then estimate a likely cost impact (as the total expences related to regulatory penalties, reparations, compensation, event recovery, investigations, repairing and replacing equipment, and other extra costs that might be relevant) of a single occurance of the scenario in the currency of {country} at the specified facility . Your response must be a single number to represent the estimated cost of the event. Do not offer or provide any additional text or commentary or explanation. Only respond with a value. Include the correct currency symbol for the given country. The scenario is: {scenario}. The scenario occurs at a {facility_type} in {country} within the {industry} industry. Experts in the business have conducted a business impact analysis (BIA) of this scenario.  The BIA scores are: impacts on personnel and public safety {safetyimpact}/10; danger to life {lifeimpact}/10; impact on production and operations {productionimpact}/10; impact on company reputation {reputationimpact}/10; impact on the local environment {environmentimpact}/10;  impacts relating to regulatory requirements:{regulatoryimpact}/10, and impacts relating to company data and intellectual: {dataimpact}/10. (where 1/10 is minimal/low impact and 10/10 is maximum/catastrophic impact).  Determine how to apply any necessary weightings to the BIA scores based on the given country, industry and facility type. Use any available public sources or industry reports for a credible estimation. If no such data is available, provide a best estimate using Artificial Intelligence. Provide the result as a numeric value to represent a currency amount using the correct currency symbol for {country}. Do not include any additional dialogue or explanation - only the integer value representing the result so that it can be stored in the integer field of a database table"},
            {"role": "user",
             "content": common_content + f" Using {standards} as a reference, provide a list, without any additional commentary, text, or headings other than the specific requested information, a maximum of 5 key recommendations  that are most relevant to the CyberPHA and an assessment of operational technology - OT - with a particular focus on safety and environmental controls (make it the top 5 that give the most value and risk mitigation and do not include any currently implemented controls listed in the following: {currentControls}), to address the scenario aligned with the specifically named {standards} standards. Each recommendation should be in the format '[recommendation text] ([reference])', where '[reference]' is the relevant section from {standards}. References should be given in a manner that enables the user to quickly identify where to locate the related information within {standards}"},
        ]

        # Initialize an empty list to store the responses
        responses = []

        # Use ThreadPoolExecutor to parallelize the API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            responses = list(executor.map(get_response, user_messages))

        print(f"cost={responses[4]}")
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
        print(f"{request.GET}")
        # Gather the necessary data for the risk assessment (impact scores and scenario information)
        Industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        address = request.GET.get('address')
        country = request.GET.get('country')
        facility = request.GET.get('txtFacility')

        # Prepare the request data for the OpenAI GPT-3 API in the chat format
        message = [
            {
                "role": "system",
                "content": "As a physical security and cybersecurity risk assessment professional, you must assess and determine the risk profile of a given location based on it’s address, country, and the type of facility that it represents."
            },
            {
                "role": "user",
                "content": f"Provide, without any commentary or additional information only the four specific pieces of information that are asked for. Give a one sentence reply to each of the four specific pieces of information being asked for. If there is no information to offer, use AI to offer the most pragmatic response taking each of the variables into account. The four pieces are information needed as follows: 1. Provide a summary of the most likely safety hazards for the {facility} {facility_type}, {address}, {country}. 2. Provide a sentence about the most likely chemicals stored or used at the {facility} {facility_type}, {address}, {country} and their associated hazards. 3. Give a summary of the most likely physical security standards and challenges for {facility} {facility_type} with the {Industry} industry at {address} in {country}. 4. Give a sentence that summarizes any other localized risks to note for this {facility_type} at {address} in {country}:\nAddress - {address}, Country - {country}, Industry - {Industry}, facility type - {facility_type} Provide only the four pieces of information that have been requested. No title or header. The output must be given in the following format where the | symbol denotes a delimited between variables. <safety summary>|<chemical summary>|<physical security summary>|<other summary>."
            }
        ]

        # openai.api_key = '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'

        openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key

        try:
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
            split_response = generated_response.split("|")

            # Check if the split response has the expected number of values
            if len(split_response) != 4:
                raise ValueError("The model's response did not match the expected format.")

            # Split the generated response into individual parts
            safety_summary, chemical_summary, physical_security_summary, other_summary = generated_response.split("|")

            # Return the individual parts as variables
            return JsonResponse({
                'safety_summary': safety_summary,
                'chemical_summary': chemical_summary,
                'physical_security_summary': physical_security_summary,
                'other_summary': other_summary
            })

        except openai.error.OpenAIError as e:
            # Handle any OpenAI API related errors
            print(f"{str(e)}")
            return JsonResponse({
                'error': f"OpenAI API Error: {str(e)}"
            })

        except ValueError as ve:
            # Handle the unexpected response format
            print(f"{str(ve)}")
            return JsonResponse({
                'error': str(ve)
            })

        except Exception as ex:
            # Handle any other unexpected errors
            print(f"{str(ex)}")
            return JsonResponse({
                'error': f"An unexpected error occurred: {str(ex)}"
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
