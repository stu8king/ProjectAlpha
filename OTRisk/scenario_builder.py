import decimal
import os

from django.views.decorators.http import require_POST, require_http_methods
from pptx import Presentation
from pptx.util import Inches
import requests
from io import BytesIO
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers import serialize
from django.forms import formset_factory, modelformset_factory
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Subquery, OuterRef, Count, IntegerField, Case, When, Value, Prefetch

import OTRisk.forms
from OTRisk.models.RiskScenario import RiskScenario
from OTRisk.models.Model_Scenario import tblConsequence
from OTRisk.models.questionnairemodel import Questionnaire, FacilityType
from OTRisk.models.ThreatAssessment import ThreatAssessment
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions, MitreICSMitigations, RawControlList, \
    QRAW_Safeguard
from django.db.models import F, Count, Avg, Case, When, Value, CharField, Sum
from django.db.models.functions import Ceil

from accounts import models
from accounts.views import get_client_ip
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.core import serializers
from OTRisk.models.Model_Workshop import tblWorkshopNarrative, tblWorkshopInformation
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblRiskCategories, \
    tblControlObjectives, \
    tblThreatIntelligence, tblMitigationMeasures, tblScenarios, tblSafeguards, tblThreatSources, tblThreatActions, \
    tblNodes, tblUnits, tblZones, tblCyberPHAScenario, tblIndustry, auditlog, tblStandards, MitreControlAssessment, \
    CyberPHAScenario_snapshot, Audit, PHAControlList, SECURITY_LEVELS, OrganizationDefaults, scenario_compliance, \
    ScenarioConsequences, APIKey, ScenarioBuilder, PHA_Safeguard, OpenAIAPILog, CybersecurityDefaults, \
    user_scenario_audit
from django.shortcuts import render, redirect
from .dashboard_views import get_user_organization_id, get_scenarios_for_regulation
from django.contrib.auth.decorators import login_required
from .forms import LoginForm, OrganizationDefaultsForm, CyberSecurityScenarioForm, scenario_sim, \
    CybersecurityDefaultsForm
from datetime import date, datetime
import json
import openai, math
import requests, re
from xml.etree import ElementTree as ET
from .raw_views import qraw, openai_assess_risk, GetTechniquesView, raw_action, check_vulnerabilities, rawreport, \
    raw_from_walkdown, save_ra_action, get_rawactions, ra_actions_view, UpdateRAAction, reports, reports_pha, \
    create_or_update_raw_scenario, analyze_raw_scenario, analyze_sim_scenario, generate_sim_attack_tree, \
    analyze_sim_consequences, update_workflow, get_analysis_result, cleanup_scenariobuilder
from .dashboard_views import dashboardhome, get_group_report, get_heatmap_records
from .pha_views import iotaphamanager, facility_risk_profile, get_headerrecord, scenario_analysis, phascenarioreport, \
    getSingleScenario, pha_report, scenario_vulnerability, add_vulnerability, get_asset_types, calculate_effectiveness, \
    generate_ppt, analyze_scenario, assign_cyberpha_to_group, fetch_groups, fetch_all_groups, retrieve_scenario_builder, \
    facilities, air_quality_index, delete_pha_record, is_inappropriate, get_api_key
from .report_views import pha_reports, get_scenario_report_details, qraw_reports, get_qraw_scenario_report_details
from .forms import CustomConsequenceForm, OrganizationAdmin
from .models.Model_Scenario import CustomConsequence
from accounts.models import Organization, OrganizationHistory
from accounts.models import UserProfile
from .forms import UserForm, UserProfileForm, ChangePasswordForm
import secrets
import string
from django.core.mail import send_mail, EmailMultiAlternatives, get_connection
from django.contrib.auth.decorators import user_passes_test
from django.db import connection, transaction
from django.urls import reverse
from OTRisk.forms import SQLQueryForm, ControlAssessmentForm, AssessmentFrameworkForm, NewAssessmentAnswerForm, \
    EditAssessmentAnswerForm, QuestionnaireUploadForm, OrganizationForm
from .models.model_assessment import AssessmentFramework, AssessmentQuestion, SelfAssessment, AssessmentAnswer
import csv
from django.contrib import messages
import chardet
import datetime


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


@login_required()
def scenario_sim_v2(request):  # Changed the function name
    scenario_form = CyberSecurityScenarioForm(request.POST)
    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    attack_vectors = tblThreatActions.objects.all().order_by('ThreatAction')
    return render(request, 'OTRisk/scenario_sim_v2.html',
                  {'scenario_form': scenario_form, 'industries': industries, 'facilities': facilities,
                   'threats': threatsources, 'attack_vectors': attack_vectors})


@login_required
def analyze_sim_scenario_v2(request):
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

        investments_data = request.POST.get('investments')
        investments = json.loads(investments_data) if investments_data else []

        if investments:
            investment_statement = "Investments have been made in:\n"
            for idx, investment in enumerate(investments, start=1):
                investment_statement += f"{idx}: Investment Type:{investment['type']}, Vendor:{investment['vendor_name']}, Product:{investment['product_name']}, Investment date:{investment['date']}.\n"
        else:
            investment_statement = "No investments have been specified."


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
                model=get_api_key('OpenAI_Model'),
                messages=[
                    {"role": "system", "content": system_message}
                ],
                max_tokens=800,
                temperature=0.1
            )

            # Process the response
            consequence_text = response['choices'][0]['message']['content']
            # Parse the response into a structured format
            parsed_consequences = parse_consequences(consequence_text)

            if investments:

                investment_impact_prompt = f"""
                Given the cybersecurity scenario: '{scenario}' for the {facility_type} and the following investments:
                {investment_statement}
                Please provide exactly 6 bullet points summarizing the impact of these investments on:
                1. Level of risk reduction
                2. Business impact analysis improvement
                3. Event costs mitigation
                4. Operational risks decrease
                5. Compliance enhancement
                6. Return on investment or cost savings
    
                Each bullet point should contain a concise statement (no more than 30 words) quantifying the impact. EXTRA INSTRUCTION: be cautiously and modestly optimistic.
                """

                # Query OpenAI API for investment impact analysis
                investment_impact_response = openai.ChatCompletion.create(
                    model=get_api_key('OpenAI_Model'),
                    messages=[
                        {"role": "system", "content": investment_impact_prompt}
                    ],
                    max_tokens=400,  # Adjust token limit based on expected response length
                    temperature=0.1  # Adjust for creativity as needed
                )

                # Process the investment impact response
                investment_impact_text = investment_impact_response['choices'][0]['message']['content']
            else:
                investment_impact_text = "No tools or software were submitted for this scenario."

            response = {
                'consequence': parsed_consequences,
                'investment_impact': investment_impact_text
            }

            return JsonResponse(response)

        else:
            return JsonResponse({'consequence': [], 'error': 'Not a valid scenario'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def generate_sim_attack_tree_v2(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key
    scenario = request.POST.get('scenario')

    threat_actor = request.POST.get('threat_actor')
    attack_vector = request.POST.get('attack_vector')
    targeted_system = request.POST.get('targeted_system')
    attack_effect = request.POST.get('attack_effect')
    impact = request.POST.get('impact')
    compliance = request.POST.get('compliance')
    facility_type = request.POST.get('facility_type')
    industry = request.POST.get('industry')

    enriched_scenario = f"""
        Scenario: {scenario}
        Threat Actor: {threat_actor}
        Attack Vector: {attack_vector}
        Compliance Requirements: {compliance}
        Facility Type: {facility_type}
        Industry: {industry}
        Targeted System: {targeted_system}
        Attack Effect: {attack_effect}
        Attack Impact: {impact}
        """

    attack_tree_system_message = """
                    Generate a hierarchical structure of a probable attack tree, based on the MITRE ATT@CK framework for Industrial Control Systems (ICS) applied to and specific to the given OT cybersecurity scenario, in a strictly valid JSON format. Incorporate relevant terminology from ISA 62443-3-2 if applicable. The structure should use 'name' for node labels and 'children' for nested nodes, where each node represents a step or method in the attack. The attack tree must have at least two main branches, each potentially containing dozens of branches or sub-branches. CRITICAL INSTRUCTION: Ensure the output is in JSON format WITH NO additional characters outside of the JSON structure. The JSON structure should be formatted as: {'name': 'Node Name', 'children': [{...}]}.

                    Example of a correctly formatted output:
                    {
                      "name": "Attack Root",
                      "children": [
                        {
                          "name": "Branch 1",
                          "children": [
                            {
                              "name": "Sub-branch 1.1",
                              "children": []
                            },
                            {
                              "name": "Sub-branch 1.2",
                              "children": []
                            }
                          ]
                        },
                        {
                          "name": "Branch 2",
                          "children": [
                            {
                              "name": "Sub-branch 2.1",
                              "children": []
                            },
                            {
                              "name": "Sub-branch 2.2",
                              "children": []
                            }
                          ]
                        }
                      ]
                    }

                    Please generate a similar structure for the provided cybersecurity scenario, adhering STRICTLY to the JSON format and ensuring at least two main branches are present.
                    """

    # Query OpenAI API for the attack tree
    attack_tree_response = openai.ChatCompletion.create(
        model="gpt-4-0125-preview",
        messages=[
            {"role": "system", "content": attack_tree_system_message},
            {"role": "user", "content": enriched_scenario}
        ],
        max_tokens=800,
        temperature=0.3
    )
    attack_tree_raw = attack_tree_response['choices'][0]['message']['content']
    attack_tree_raw = attack_tree_raw.strip()

    match = re.search(r'\{.*\}', attack_tree_raw, re.DOTALL)
    if match:
        cleaned_json_str = match.group(0)
    else:
        cleaned_json_str = "{}"  # Fallback to empty JSON object if no match

    # Process the response for attack tree
    try:
        # Parse the raw JSON string into a Python dictionary
        attack_tree_data = json.loads(cleaned_json_str)

        return JsonResponse(attack_tree_data)
    except json.JSONDecodeError:

        return JsonResponse({"error": "Invalid JSON format from AI response"}, status=400)


def return_api_key(key_name):
    openai_api_key = get_api_key('openai')

    return openai_api_key


def call_openai_api(system_message, openai_api_key):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4-0125-preview",
            messages=[{"role": "system", "content": system_message}],
            max_tokens=350,
            temperature=0.1,
            api_key=openai_api_key
        )
        return response['choices'][0]['message']['content']
    except Exception as e:
        return None


def extract_cost_value(text, label):
    match = re.search(fr'{label}: (\d+)', text)
    return match.group(1) if match else "Not available"


@require_POST
def analyze_sim_consequences_v2(request):
    scenario_details = {key: request.POST.get(key, '').strip() for key in
                        ['scenario', 'facility_type', 'industry', 'country', 'organization_size',
                         'regulatory_environment']}

    # Messages for OpenAI
    consequence_message, cost_estimation_message = create_system_messages(scenario_details)

    openai_key = get_api_key('openai')
    consequence_text = call_openai_api(consequence_message, openai_key)
    cost_estimation_text = call_openai_api(cost_estimation_message, openai_key)

    if not consequence_text or not cost_estimation_text:
        return JsonResponse({"error": "Failed to get response from OpenAI"}, status=500)

    costs = cost_estimation_text.split('|')  # Split the string into a list of values
    if len(costs) == 3:
        best_case_cost, most_likely_case_cost, worst_case_cost = costs
        formatted_costs = {
            'best_case_cost': f"${int(best_case_cost):,}",
            'most_likely_case_cost': f"${int(most_likely_case_cost):,}",
            'worst_case_cost': f"${int(worst_case_cost):,}"
        }
    else:
        formatted_costs = {
            'best_case_cost': "Not available",
            'most_likely_case_cost': "Not available",
            'worst_case_cost': "Not available"
        }

    projection_text = call_openai_api(create_projection_message(scenario_details), openai_key)

    return JsonResponse({
        **formatted_costs,
        'consequence': consequence_text,
        'projection': projection_text
    })


def create_system_messages(details):
    # Common content derived from details for use in both messages
    common_content = f"""
    Scenario involving a {details['facility_type']} within the {details['industry']} sector is as follows: '{details['scenario']}'. This scenario features an organization size of {details['organization_size']} and a regulatory compliance level of {details['regulatory_environment']}. 
    """

    # Refining the consequence message for clarity and specificity
    consequence_message = f"""
    {common_content} As a cybersecurity scenario analyzer, evaluate the described scenario. List up to 8 direct consequences that are most likely to occur as a result of this scenario, in a bullet-point format, limited to 80 words or less.
    
    The format of the response must be precisely as follows:
    
    - <consequence 1>
    - <consequence 2) and so on.
    
    For example to illustrate what a correctly formatted output will resemble:
    
  - Compromised HMI devices, causing inaccurate data display and potential safety risks.
  - Infection spread to MES, Industrial PCs and servers, causing data loss and system malfunction.
  - Networked production machinery and robotics could be rendered inoperable, affecting production efficiency.
    
    Do NOT add any additional characters or symbols
    
    """

    # Enhancing the cost estimation message for accuracy and detail
    cost_estimation_message = f"""
    {common_content} Acting as an insurance actuary specializing in cybersecurity, you are tasked with estimating the direct financial impact of the described cybersecurity incident. Utilize data from similar incidents, industry reports, and known costs related to cybersecurity breaches, such as data loss, system downtime, and recovery efforts. 

    Provide three distinct cost estimates reflecting the best case, worst case, and most likely case scenarios. These estimates should solely focus on direct costs including, but not limited to, incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. 

    It is crucial that your response adheres to the following format: 'low|medium|high', with each value representing an integer estimate of costs in US dollars. Do not include any text, symbols, currency signs, or explanations outside of these three numerical values. If specific data is unavailable, base your estimates on a reasonable approximation derived from similar incidents within the industry.

    Example of the expected format: 500000|1500000|2500000

    Note: Your response must strictly consist of three positive integers separated by '|', representing the low, medium, and high estimates respectively. Any deviation from this format will not be processed correctly.
    """

    return consequence_message, cost_estimation_message


def create_projection_message(details):
    projection_message = f"""
    Your task is to generate a 12-month direct cost projection for a hypothetical cybersecurity incident, focusing specifically on a {details['organization_size']} {details['facility_type']} within the {details['industry']} industry in {details['country']}. The projection should strictly follow a numerical format without any additional text, narrative, or characters. 

    Scenario description: '{details['scenario']}'.

    Based on historical data from similar OT and IT cybersecurity incidents, and considering direct costs such as incident response, remediation, legal fees, regulatory fines, and other direct expenses, produce a monthly cost projection. 

    The output must strictly adhere to the format of 'Month1Value|Month2Value|...|Month12Value', where each value is an integer representing the direct cost for that month in US dollars. Do not include currency symbols, text, or any narrative explanation. The projection should be realistic and based on the average annual revenue of facilities of similar size and industry in the specified country, referencing industry-specific data from the latest Verizon DBIR, applicable regulations from CISA, and standards from the NIST Cybersecurity Framework.

    Format example (do not include this line in your response): 10500|8200|7500|6900|6700|6500|6300|6100|5900|5700|5500|5300

    Provide the 12-month direct cost projection below in the specified format only.
    """

    return projection_message


@login_required()
def generate_scenario_description_v2(request):
    if request.method == 'POST':
        # Extracting existing form data
        attacker = request.POST.get('attacker', '').strip()
        attack_vector = request.POST.get('attackVector', '').strip()
        target_component = request.POST.get('targetComponent', '').strip()
        attack_effect = request.POST.get('attackEffect', '').strip()
        target_system = request.POST.get('targetSystem', '').strip()
        impact = request.POST.get('impact', '').strip()
        motivation = request.POST.get('motivation', '').strip()
        country = request.POST.get('country', '').strip()
        industry = request.POST.get('industry', '').strip()
        facility_type = request.POST.get('facility_type', '').strip()
        regulatory_environment = request.POST.get('regulations', '').strip()
        severity = request.POST.get('severity', '').strip()
        detection_response = request.POST.get('detectionResponse', '').strip()
        preventive_measures = request.POST.get('preventiveMeasures', '').strip()

        # Reading new checkbox values
        active_ops = request.POST.get('active_ops', 'false').lower() == 'true'
        cyber_insurance = request.POST.get('cyber_insurance', 'false').lower() == 'true'
        bc_plan = request.POST.get('bc_plan', 'false').lower() == 'true'

        # Constructing the prompt
        prompt = f"""
        Construct a scenario based on the following details, ensuring the narrative focuses on the sequence of actions and events without detailing the consequences. The scenario MUST illustrate a realistic cybersecurity attack against operational technology (OT) and industrial control systems (ICS) within the specified environment, considering operational context and defensive measures:

        - Attacker: {attacker}
        - Attack Vector: {attack_vector}
        - Target Component: {target_component}
        - Effect of Attack: {attack_effect}
        - Target System/Network: {target_system}
        - Potential Immediate Impact: {impact}
        - Attacker's Motivation: {motivation}
        - Facility Type: {facility_type}
        - Industry Sector: {industry}
        - Country {country}
        - Regulatory Environment: {regulatory_environment}

        Additional Context:
        - Are active operations underway? {'Yes' if active_ops else 'No'}
        - Is there cyber insurance cover? {'Yes' if cyber_insurance else 'No'}
        - Is there a business continuity plan in place? {'Yes' if bc_plan else 'No'}

        Use this information to generate a concise scenario as a very fact-based technical brief in natural language, under 200 words, formatted as coherent paragraphs. Avoid detailing long-term consequences or broad impacts. Avoid repeating information given in the scenario description. Focus solely on the attack's progression. 
        """

        # Setting OpenAI API key
        openai.api_key = get_api_key('openai')
        open_ai_model = get_api_key('OpenAI_Model')

        # Querying the OpenAI API
        response = openai.ChatCompletion.create(
            model=open_ai_model,
            messages=[
                {"role": "system", "content": prompt}
            ],
            max_tokens=350,
            temperature=0.2
        )
        # Extracting the generated scenario
        # The response structure is different for chat completions, so adjust accordingly
        if response.choices and response.choices[0].message:
            scenario_description = response.choices[0].message['content'].strip()
        else:
            scenario_description = "No scenario generated."

        return JsonResponse({'scenario_description': scenario_description})
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


def related_incidents(request):
    """
    This function uses OpenAI's GPT-4 to find cybersecurity incidents related to a provided scenario.
    The response is formatted for easy client-side parsing and display in a table.
    """
    # Fetching the scenario and additional_info from POST request
    scenario = request.POST.get('scenario', '')

    # Early return if the scenario description is missing
    if not scenario:
        return JsonResponse({"error": "Scenario description is required."}, status=400)

    # Constructing the prompt for GPT-4
    prompt = f"""
    You are a university research assistant. Given the cybersecurity scenario: '{scenario}',  identify
    up to three cybersecurity incidents that have been reported anywhere in the world in any language that have details in common with the given scenario. 
    For each related incident, provide a brief (english) summary, where it occurred, and include a URL link where information about the incident can be found. 
    Format each incident as follows:
    <Incident title>|<incident description>|<Incident Date>|<incident URL>
    Provide each incident on a new line, with no additional text, narrative, or commentary.
    """

    # Fetching the OpenAI API key
    openai.api_key = get_api_key('openai')
    open_ai_model = get_api_key('OpenAI_Model')
    try:
        # Making the API call to OpenAI's GPT-4
        response = openai.ChatCompletion.create(
            model=open_ai_model,
            messages=[{"role": "system", "content": prompt}],
            temperature=0.2,
        )

        # Extracting the content from the response
        if response.choices:
            generated_text = response.choices[0].message['content'].strip()
        else:
            generated_text = 'No related incidents found.'

        # Preparing the JSON response
        return JsonResponse({"generated_summary": generated_text})
    except Exception as e:
        # Handling errors and returning an error message
        return JsonResponse({"error": str(e)}, status=500)


def retrieve_scenario_builder_v2(request, scenario_id):
    try:
        # Retrieve the scenario from the database
        scenario = ScenarioBuilder.objects.get(id=scenario_id)

        # Parse the stored JSON data
        scenario_data = json.loads(scenario.scenario_data)

        # Extract elements from the scenario data
        attack_tree_data = scenario_data.get('attackTree')
        scenario_description = scenario_data.get('scenario')
        investment_projection = scenario_data.get('investment_projection')

        industry = scenario_data.get('industry')
        facility = scenario_data.get('facility')
        country = scenario_data.get('country')
        org = scenario_data.get('org')
        regs = scenario_data.get('regs')
        attacker = scenario_data.get('attacker')
        vector = scenario_data.get('vector')
        target = scenario_data.get('target')
        effect = scenario_data.get('effect')
        network = scenario_data.get('network')
        impact = scenario_data.get('impact')
        motivation = scenario_data.get('motivation')
        incidents = scenario_data.get('incidents')

        # Correctly process consequences to ensure each starts with a single dash
        raw_consequences = scenario_data.get('consequences', '')
        # Split by any known delimiter and ensure each consequence starts with a dash
        consequences_list = raw_consequences.replace(',', '\n').split('\n')
        consequences = [f"- {line.strip()}" if not line.strip().startswith('-') else line.strip()
                        for line in consequences_list if line.strip()]
        # Join the consequences with a line break between each
        formatted_consequences = '\n'.join(consequences)
        table_data = scenario_data.get('tableData')

        costs = scenario_data.get('costs')
        # Check if cost_projection is None or not present, and set a default value if so
        cost_projection = scenario_data.get('cost_projection', '0|0|0|0|0|0|0|0|0|0|0|0')
        if not cost_projection:
            cost_projection = '0|0|0|0|0|0|0|0|0|0|0|0'

        # Prepare factors data
        factors = {}
        for item in table_data:
            factor = item.get('factor')
            score = int(item.get('score').split('/')[0])  # Extract score as integer
            narrative = item.get('narrative')
            factors[factor] = {'score': score, 'narrative': narrative}

        # Return the extracted data
        return JsonResponse({
            'attack_tree_data': attack_tree_data,
            'scenario_description': scenario_description,
            'consequences': formatted_consequences,
            'factors': factors,
            'costs': costs,
            'cost_projection': cost_projection,
            'investment_projection': investment_projection,
            'industry': industry,
            'facility': facility,
            'country': country,
            'org': org,
            'regs': regs,
            'attacker': attacker,
            'vector': vector,
            'target': target,
            'effect': effect,
            'network': network,
            'impact': impact,
            'motivation': motivation,
            'incidents': incidents
        })

    except ScenarioBuilder.DoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
