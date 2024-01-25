import json
from django.db.models import CharField
from django.db.models.functions import Coalesce
from django.forms import model_to_dict, CharField
from django.utils.dateparse import parse_datetime
from django.core.serializers import serialize
from django.views.decorators.http import require_POST

from OTRisk.models.Model_CyberPHA import tblIndustry, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario, vulnerability_analysis, tblAssetType, tblMitigationMeasures, MitreControlAssessment, \
    cyberpha_safety, SECURITY_LEVELS, ScenarioConsequences, user_scenario_audit, auditlog, CyberPHAModerators, \
    WorkflowStatus, APIKey, CyberPHA_Group, ScenarioBuilder
from OTRisk.models.raw import SecurityControls
from OTRisk.models.raw import MitreICSMitigations, RAActions
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.model_assessment import SelfAssessment, AssessmentFramework
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date, time, datetime
from django.views import View
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
import openai
import re
from django.db.models import Avg, Sum, F, Count, Subquery, OuterRef, Case, When, Value, IntegerField, Q
import concurrent.futures
import os
import math

from ProjectAlpha import settings
from ProjectAlpha.settings import BASE_DIR
from accounts.models import UserProfile
from accounts.views import get_client_ip
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


def get_api_key(service_name):
    try:
        key_record = APIKey.objects.get(service_name=service_name)
        return key_record.key
    except ObjectDoesNotExist:
        # Handle the case where the key is not found
        return None


@login_required
def iotaphamanager(request, record_id=None):
    pha_header = None
    new_record_id = None  # Initialize new_record_id to None
    annual_revenue_str = "$0"
    coho_str = "$0"

    if request.method == 'POST':
        is_new_record = False  # Initialize flag
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
            is_new_record = True
            pha_header = tblCyberPHAHeader()

        pha_header.title = request.POST.get('txtTitle')
        pha_header.PHALeader = request.POST.get('txtLeader')
        pha_header.PHALeaderEmail = request.POST.get('txtLeaderEmail')
        pha_header.FacilityName = request.POST.get('txtFacility')
        pha_header.Industry = request.POST.get('selIndustry')
        pha_header.FacilityType = request.POST.get('selFacilityType')

        pha_header.AssessmentUnit = request.POST.get('txtUnit')

        selZone_value = request.POST.get('selZone')
        pha_header.AssessmentZone = selZone_value if selZone_value else "None"

        pha_header.AssessmentStartDate = request.POST.get('txtStartDate')
        pha_header.AssessmentEndDate = request.POST.get('txtEndDate')
        pha_header.facilityAddress = request.POST.get('txtAddress')
        pha_header.safetySummary = request.POST.get('txtSafetySummary')
        pha_header.chemicalSummary = request.POST.get('txtChemical')
        pha_header.physicalSummary = request.POST.get('txtPhysical')
        pha_header.otherSummary = request.POST.get('txtOther')
        pha_header.threatSummary = request.POST.get('threatSummary')
        pha_header.insightSummary = request.POST.get('insightSummary')
        pha_header.strategySummary = request.POST.get('strategySummary')
        pha_header.complianceSummary = request.POST.get('txtCompliance')
        pha_header.country = request.POST.get('countrySelector')
        pha_header.Date = request.POST.get('txtStartDate')
        pha_header.EmployeesOnSite = request.POST.get('txtEmployees')
        pha_header.shift_model = request.POST.get('shift_model')
        try:
            assessment_id = int(request.POST.get('assessment_id')) if request.POST.get('assessment_id') else None
        except ValueError:
            assessment_id = None
        pha_header.assessment = assessment_id

        pha_header.npm = request.POST.get('npm')
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
        coho_str = request.POST.get('coho', '')
        # Strip out $ and , characters
        cleaned_annual_revenue_str = ''.join(filter(str.isdigit, annual_revenue_str))
        cleaned_coho_str = ''.join(filter(str.isdigit, coho_str))

        # Convert the cleaned string to an integer
        try:
            annual_revenue_int = int(cleaned_annual_revenue_str)
        except ValueError:  # Handle cases where the input might still not be a valid integer
            annual_revenue_int = 0  # Or handle this situation differently if needed
        try:
            coho_int = int(cleaned_coho_str)
        except ValueError:  # Handle cases where the input might still not be a valid integer
            coho_int = 0  # Or handle this situation differently if needed
        # Save to your model
        pha_header.annual_revenue = annual_revenue_int
        pha_header.coho = coho_int

        cyber_insurance_value = request.POST.get('cyber_insurance')
        pha_header.cyber_insurance = False if cyber_insurance_value is None else bool(cyber_insurance_value)

        pha_header.UserID = request.user.id
        pha_header.save()
        saved_record_id = pha_header.ID

        if is_new_record:
            pha_header.set_workflow_status('Started')
        # Save Workflow Status
        selected_workflow_status = request.POST.get('workflow_selector')
        if selected_workflow_status:
            pha_header.set_workflow_status(selected_workflow_status)
        # First, remove existing moderators for this PHA record
        CyberPHAModerators.objects.filter(pha_header=pha_header).delete()
        # Get the list of selected moderator IDs from the form
        selected_moderators_ids = request.POST.getlist('moderator')
        # Get the target date from the form

        target_date_str = request.POST.get('targetDate', None)
        if target_date_str:
            try:
                # Create a naive datetime object from the string
                naive_datetime = datetime.strptime(target_date_str, '%m/%d/%Y')
                # Make it timezone aware
                target_date = timezone.make_aware(naive_datetime, timezone.get_default_timezone())
            except ValueError:
                target_date = None
        else:
            target_date = None

        # Create new associations
        for moderator_id in selected_moderators_ids:
            moderator = User.objects.get(id=moderator_id)
            CyberPHAModerators.objects.create(pha_header=pha_header, moderator=moderator, target_date=target_date)

        new_record_id = pha_header.ID

        write_to_audit(
            request.user,
            f'Saved cyberPHA header data for {pha_header.title}',
            get_client_ip(request)
        )
    organization_id_from_session = request.session.get('user_organization')

    users_in_organization = User.objects.filter(userprofile__organization__id=organization_id_from_session)

    ra_actions_subquery = RAActions.objects.filter(phaID=OuterRef('ID')).values('phaID').annotate(
        action_count=Count('ID')).values('action_count')

    # Subquery to get the latest workflow status for each tblCyberPHAHeader record
    latest_status_subquery = WorkflowStatus.objects.filter(
        cyber_pha_header=OuterRef('pk')
    ).order_by('-timestamp').values('status')[:1]

    # Annotate the pha_header_records queryset with the latest workflow status
    pha_header_records = tblCyberPHAHeader.objects.filter(
        UserID__in=users_in_organization,
        Deleted=0
    ).annotate(
        scenario_count=Count('tblcyberphascenario'),
        ra_action_count=Coalesce(Subquery(ra_actions_subquery, output_field=IntegerField()), Value(0)),
        latest_workflow_status=Subquery(latest_status_subquery)
    )

    if record_id is not None:
        first_record_id = record_id
    else:
        first_record = pha_header_records.first()
        first_record_id = first_record.ID if first_record else 0
    # get the list of assessments
    # 0 means a global assessment that's built in for all customer
    # any other value is a customer specific assessment so should only be visible for the customer where their id matches
    current_user_profile = UserProfile.objects.get(user=request.user)
    user_organization_id = request.session.get('user_organization', 0)  # Default to 0 if not in session
    assessments = SelfAssessment.objects.filter(
        Q(organization_id=user_organization_id)
    )
    industries = tblIndustry.objects.all().order_by('Industry')
    facilities = FacilityType.objects.all().order_by('FacilityType')
    zones = tblZones.objects.all().order_by('PlantZone')
    standardslist = tblStandards.objects.all().order_by('standard')
    mitigations = MitreICSMitigations.objects.all()
    anychart_key = get_api_key('anychart')
    moderators_in_organization = UserProfile.objects.filter(
        organization_id=user_organization_id,
        role_moderator=True
    )

    # Retrieve current workflow status for the pha_header
    current_workflow_status = "Started"  # Default status

    if pha_header:
        latest_status = pha_header.workflow_statuses.last()
        if latest_status:
            current_workflow_status = latest_status.status

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
        'coho_str': coho_str,
        'selected_record_id': first_record_id,
        'SECURITY_LEVELS': SECURITY_LEVELS,
        'assessments': assessments,
        'moderators': moderators_in_organization,
        'current_workflow_status': current_workflow_status,
        'workflow_status_choices': WorkflowStatus.STATUS_CHOICES,
        'anychart_key': anychart_key,
        'group_types': CyberPHA_Group.GROUP_TYPES,
        'saved_record_id': new_record_id
    })


def get_headerrecord(request):
    record_id = request.GET.get('record_id')
    headerrecord = get_object_or_404(tblCyberPHAHeader, ID=record_id)
    # Retrieve the latest workflow status for this header record
    latest_status = headerrecord.workflow_statuses.last()
    current_workflow_status = latest_status.status if latest_status else "Started"
    # Get current group assignments
    current_groups = headerrecord.groups.all()
    current_groups_data = serialize('json', current_groups)

    # Serialize all_groups
    all_groups = CyberPHA_Group.objects.all()
    all_groups_data = serialize('json', all_groups)

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
        'threatSummary': headerrecord.threatSummary,
        'insightSummary': headerrecord.insightSummary,
        'strategySummary': headerrecord.strategySummary,
        'country': headerrecord.country,
        'shift_model': headerrecord.shift_model,
        'EmployeesOnSite': headerrecord.EmployeesOnSite,
        'cyber_insurance': headerrecord.cyber_insurance,
        'annual_revenue': headerrecord.annual_revenue,
        'pha_score': headerrecord.pha_score,
        'sl_t': headerrecord.sl_t,
        'assessment_id': headerrecord.assessment,
        'coho': headerrecord.coho,
        'npm': headerrecord.npm,
        'current_workflow_status': current_workflow_status,
        'current_groups': current_groups_data,
        'all_groups': all_groups_data,
        'group_types': CyberPHA_Group.GROUP_TYPES,
    }

    # Query for moderators associated with this header record
    moderators = CyberPHAModerators.objects.filter(pha_header=headerrecord)
    moderator_ids = [moderator.moderator.id for moderator in moderators]

    moderators_data = [
        {'id': moderator.moderator.id, 'name': f"{moderator.moderator.first_name} {moderator.moderator.last_name}"}
        for moderator in moderators
    ]

    # Retrieve all users from the current organization who are moderators
    organization_moderators = User.objects.filter(
        userprofile__organization_id=get_user_organization_id(request),
        userprofile__role_moderator=True
    )
    organization_moderators_data = [
        {'id': user.id, 'name': f"{user.first_name} {user.last_name}"}
        for user in organization_moderators
    ]
    # Log the user activity
    write_to_audit(
        request.user,
        f'Viewed cyberPHA: {headerrecord.title}',
        get_client_ip(request)
    )
    control_assessments = MitreControlAssessment.objects.filter(cyberPHA=headerrecord)
    # control_effectiveness = math.ceil(calculate_effectiveness(record_id))
    try:
        control_effectiveness = SelfAssessment.objects.get(id=headerrecord.assessment).score_effective
    except SelfAssessment.DoesNotExist:
        control_effectiveness = 0
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
        'control_effectiveness': control_effectiveness,
        'organization_moderators': organization_moderators_data,  # All moderators in the organization
        'current_moderators': moderators_data,  # Moderators for the specific header record
        'moderator_ids': moderator_ids  # IDs of Moderators for the specific header record

    }

    return JsonResponse(response_data)


def extract_section(text, title):
    """
    Extracts a section from the provided text using the given title.
    """
    start = text.find(title)
    if start == -1:
        return ''
    start += len(title)
    end = text.find('**', start)
    return text[start:end].strip() if end != -1 else text[start:].strip()


def process_section(section_text):
    # Split the section into individual bullet points
    bullet_points = section_text.split('\n')

    # Add a line space between each bullet point
    processed_text = '\n\n'.join(bullet_point.strip() for bullet_point in bullet_points if bullet_point.strip())

    return processed_text


def facility_threat_profile(facility, facility_type, country, industry, safety_summary, chemical_summary,
                            physical_security_summary, other_summary, compliance_summary):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    # Constructing a more specific context with format instructions
    context = (
        f"You are a data scientist expert on industrial cybersecurity providing value-add analysis for an OT cybersecurity assessment. Analyze the {facility} which is a {facility_type} in {country}, operating within the {industry} industry. "
        f"Use the following summaries to generate a report: Safety Hazards - {safety_summary}, "
        f"Chemical Hazards - {chemical_summary}, Physical Security Challenges - {physical_security_summary}, "
        f"OT Devices - {other_summary}, and Compliance Requirements - {compliance_summary}. The analysis should offer insights that are in depth and specific to the facility. ")

    prompt = (f"{context} Provide a detailed analysis formatted into three distinct sections. "
              f"Start each section with its title in bold: '**Cybersecurity Threats and Vulnerabilities**', "
              f"'**Predictive Insights**', and '**Proactive Defense Strategies**'. "
              f"Follow each title with a numbered list of points."
              f"Focus solely on these aspects without additional narrative or contextual information.")

    # API call using chat model endpoint
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system",
             "content": "You are a model trained to provide concise and informative responses in a specific format."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=800
    )

    # Extracting the threat profile correctly from the response
    message = response['choices'][0]['message']
    full_response = message['content'] if message and 'content' in message else ''

    # Split the response into three parts
    threatSummary = process_section(extract_section(full_response, '**Cybersecurity Threats and Vulnerabilities**'))
    insightSummary = process_section(extract_section(full_response, '**Predictive Insights**'))
    strategySummary = process_section(extract_section(full_response, '**Proactive Defense Strategies**'))

    return threatSummary, insightSummary, strategySummary


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

        # Log the user activity
        write_to_audit(
            request.user,
            f'Generated a cyberPHA risk profile for: {facility}',
            get_client_ip(request)
        )
        # Check if Industry or facility_type are empty or None
        if not Industry or not facility_type:
            error_msg = "Missing industry or facility type. Complete all fields to get an accurate assessment"
            return JsonResponse({
                'safety_summary': error_msg,
                'chemical_summary': error_msg,
                'physical_security_summary': error_msg,
                'other_summary': error_msg
            })

        openai_api_key = get_api_key('openai')
        # openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key
        context = f"You are an expert in industrial risk management and engineering processes. For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, with {employees} employees working a {shift_model} shift model,"

        prompts = [
            f"{context}, provide a concise bullet-point list of the likely safety hazards present. Limit the response to a maximum of 100 words, or less. EXTRA INSTRUCTIONS: Do not give commentary or extra information. List only the specific hazard relevant to the facility. Add a line space between each bullet point.  If {language} is not en then give the response in the language {language} with the english directly underneath",
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

        # Call to facility_threat_profile
        threatSummary, insightSummary, strategySummary = facility_threat_profile(facility, facility_type, country,
                                                                                 Industry, safety_summary,
                                                                                 chemical_summary,
                                                                                 physical_security_summary,
                                                                                 other_summary,
                                                                                 compliance_summary)

        # Return the individual parts as variables in JsonResponse
        return JsonResponse({
            'safety_summary': safety_summary,
            'chemical_summary': chemical_summary,
            'physical_security_summary': physical_security_summary,
            'other_summary': other_summary,
            'compliance_summary': compliance_summary,
            'pha_score': pha_score,
            'threatSummary': threatSummary,
            'insightSummary': insightSummary,
            'strategySummary': strategySummary
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
    current_user = request.user

    # Try to retrieve the scenario with the given ID
    try:
        scenario = tblCyberPHAScenario.objects.get(ID=scenario_id)
    except ObjectDoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
        # Check if the current user is the owner, moderator, read-only, or has full access

    if scenario.userID == current_user:
        user_role = 'Scenario Owner'
    else:
        try:
            user_profile = UserProfile.objects.get(user=current_user)
            if user_profile.role_moderator:
                user_role = 'Scenario Moderator'
            elif user_profile.role_readonly:
                user_role = 'Read Only'
            elif user_profile.organization == scenario.CyberPHA.organization:
                user_role = 'Scenario Editor'
            else:
                return JsonResponse({'error': 'Access denied'}, status=403)
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User profile not found'}, status=404)

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
        'env_contaminant': scenario.env_contaminant,
        'env_ecosystem': scenario.env_ecosystem,
        'env_contamination': scenario.env_contamination,
        'env_population': scenario.env_population,
        'env_wildlife': scenario.env_wildlife,
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
        'ale_median': scenario.ale_median,
        'ale_low': scenario.ale_low,
        'ale_high': scenario.ale_high,
        'ale': scenario.ale,
        'countermeasureCosts': scenario.countermeasureCosts,
        'control_recommendations': scenario.control_recommendations,
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
        'sl_a': scenario.sl_a,
        'dangerScope': scenario.dangerScope,
        'prodOutage': scenario.outage,
        'prodOutageDuration': scenario.outageDuration,
        'prodOutageCost': scenario.outageCost,
        'ai_bia_score': scenario.ai_bia_score,
        'exposed_system': scenario.exposed_system,
        'weak_credentials': scenario.weak_credentials,
        'compliance_map': scenario.compliance_map,
        'attack_tree_text': scenario.attack_tree_text,
        'scenario_status': scenario.scenario_status,
        'user_role': user_role
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
    # Retrieve related consequences
    consequences = ScenarioConsequences.objects.filter(scenario=scenario)
    consequences_list = [{'consequence_text': consequence.consequence_text, 'is_validated': consequence.is_validated}
                         for consequence in consequences]
    scenario_dict['Consequences'] = consequences_list
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


def get_response(user_message):
    message = [
        {
            "role": "system",
            "content": "You are an expert and experienced process and safety engineer conducting a cybersecurity risk analysis for a cyberPHA (where P=Process, H=Hazards, A=Analysis) scenario related to industrial automation and control systems."
        },
        user_message
    ]

    response = openai.ChatCompletion.create(
        model="gpt-4-1106-preview",
        messages=message,
        temperature=0.1,
        max_tokens=600
    )
    return response['choices'][0]['message']['content']


def compliance_map_data(common_content):
    user_message = {
        "role": "user",
        "content": f"{common_content}. Based on the provided information, map the current OT security posture to a maximum of 10 of the MOST RELEVANT AND IMPORTANT industry regulatory compliance regulations for this organization in the given country. Use '||' to separate each item and '>' to separate parts within an item. Example format: <Concise Compliance Concern, maximum 30 words> > <Compliance Reference> > <Internet URL>|. Ensure each item is returned in a format that can be easily parsed for display in an HTML table. Output only the line items with NO additional text, header, intro, or narrative."
    }

    try:
        response = get_response(user_message)
        return response
    except Exception as e:
        return f"Error: {str(e)}"


@login_required
def scenario_analysis(request):
    # Log the user activity

    if request.method == 'GET':
        industry = request.GET.get('industry')
        facility_type = request.GET.get('facility_type')
        scenario = request.GET.get('scenario')
        threatSource = request.GET.get('threatsource')
        safetyimpact = request.GET.get('safety')
        safety_hazard = request.GET.get('safety_hazard')
        lifeimpact = request.GET.get('life')
        productionimpact = request.GET.get('production')
        production_outage = request.GET.get('production_outage')
        production_outage_length = request.GET.get('production_outage_length')
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
        exposed_system = request.GET.get('exposed_system')
        weak_credentials = request.GET.get('weak_credentials')
        # Retrieve the string of validated consequences
        validated_consequences_str = request.GET.get('validated_consequences', '')

        # Split the string into a list, using semicolon as the separator
        validated_consequences_list = validated_consequences_str.split(';')

        # get the effectiveness of controls for the given cyberPHA
        try:
            cyber_pha_header = tblCyberPHAHeader.objects.get(ID=cyberPHAID)

            # Get the assessment id from the tblCyberPHAHeader instance
            assessment_id = cyber_pha_header.assessment

            # Retrieve the corresponding SelfAssessment instance using the assessment_id
            if assessment_id is not None:
                self_assessment = SelfAssessment.objects.get(id=assessment_id)
                control_effectiveness = self_assessment.score_effective
            else:
                # Handle the case where assessment_id is None
                control_effectiveness = 0  # Default value

        except tblCyberPHAHeader.DoesNotExist:
            # Handle the case where tblCyberPHAHeader with the given ID does not exist
            control_effectiveness = 0

        # get the compliance summary for the cyberpha
        compliance = cyber_pha_header.complianceSummary

        # get relevant financial data
        # net profit margin
        net_profit_margin = cyber_pha_header.npm
        # cost per operating hour
        cost_op_hour = cyber_pha_header.coho
        annual_revenue = cyber_pha_header.annual_revenue

        openai.api_key = get_api_key('openai')
        # Define the common part of the user message
        common_content = f"As an expert in cybersecurity risk and an expert in engineering systems, analyse a specific OT Cybersecurity Risk Scenario for a {facility_type} in the {industry} industry in {country}:  {scenario}. (IMPORTANT CONTEXT: Systems in scope for the scenario are exposed to the Internet with a public IP address: {exposed_system}. Systems in scope for the scenario have weak or default credentials: {weak_credentials}).  Business impact scores range from 0 (no impact) to 10 (greatest impact): safety: {safetyimpact}, life danger: {lifeimpact}, production: {productionimpact} (production outage: {production_outage}: length of production outage {production_outage_length} hours), company reputation: {reputationimpact}, environmental impact: {environmentimpact}, regulatory: {regulatoryimpact}, supply chain : {supplyimpact}  data and intellectual property: {dataimpact}. Cybersecurity controls are {control_effectiveness}% effective (if 0 then control effectiveness has not been assessed) : Mitigated severity with current controls: {severitymitigated}, risk exposure to the scenario mitigated {mitigatedexposure},   residual risk {residualrisk}. The amount of unmitigated rate without controls is: {uel}"

        write_to_audit(
            request.user,
            f'Executed a scenario analysis for {cyber_pha_header.title} and scenario: {scenario}',
            get_client_ip(request)
        )
        # Define the refined user messages
        user_messages = [

            {
                "role": "user",
                "content": f" {common_content} . Consider publicly reported cybersecurity incidents over the time scale from 2 years ago to the current day , in the context of this OT Cybersecurity Risk Assessment provide ONLY the estimated likelihood (as a whole number percentage) of the given scenario. Answer with a whole number. Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"{common_content}. Assess the cybersecurity residual risk after all recommended controls have been implemented and are assumed to be at least 75% effective and give an estimated residual risk rating from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High.  Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"{common_content}.  Consequences of the scenario are: {validated_consequences_list}. Read and comply with all instructions that follow. Provide an estimate of the DIRECT COSTS of a single loss event (SLE) in US dollars. Provide three cost estimates: best case, worst case, and most likely case. Output these estimates as integers in the specific format: 'low|medium|high', where '|' is the delimiter. Ensure that your estimates are realistic and tailored to the scenario, focusing solely on relevant Direct costs such as incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. The financial impact for this scenario is rated as {financial}/10 in the business impact analysis. IMPORTANT: Respond with only three positive integers, representing the low, medium, and high estimates, in the exact order and format specified: 'low|medium|high'. Do not include any additional text, explanations, or commentary."
            },

            {
                "role": "user",
                "content": f" {common_content}. With this information and analysis of publicly reported cybersecurity incidents, provide ONLY the estimated probability (as a whole number percentage) of a successful targeted attack given that the assessed effectiveness of current cybersecurity controls is {control_effectiveness}% . Answer with a number followed by a percentage sign (e.g., nn%). Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"{common_content}. Based on the scenario described, provide an estimate of the annual Threat Event Frequency (TEF) as defined by the Open FAIR Body of Knowledge. TEF is the probable frequency, within a given timeframe, that a threat agent will act against an asset. It reflects the number of attempts by a threat actor to cause harm, regardless of whether these attempts are successful. Your response should reflect an integer or a decimal value representing the estimated number of times per year such a threat event is expected to occur. IMPORTANT: Respond only with the frequency value as an integer or a decimal, without including any additional words, sentences, or explanations. This value should strictly represent the estimated annual occurrence rate of the threat event as per the given scenario."

            },
            {
                "role": "user",
                "content": f"{common_content}. Estimate a business impact score from 0 to 100. Consequences of the scenario are given as follows: {validated_consequences_list}. A score of 1 would mean minimal business impact while a score of 100 would indicate catastrophic business impact without the ability to continue operations. Your answer should be given as an integer. Do NOT include any other words, sentences, or explanations."
            }
        ]

        def get_response_safe(user_message):
            try:
                return get_response(user_message)
            except Exception as e:
                return f"Error: {str(e)}"

        # Initialize an empty list to store the responses
        responses = []

        # Use ThreadPoolExecutor to parallelize the first five API calls
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit all the tasks and get a list of futures
            futures = [executor.submit(get_response, msg) for msg in user_messages]
            # Collect the results in the order the futures were submitted
            responses = [future.result() for future in futures]

        # Now handle the compliance mapping separately
        compliance_data = compliance_map_data(common_content)
        responses.append(compliance_data)

        # Return the responses as variables
        return JsonResponse({
            'likelihood': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'probability': responses[3],
            'frequency': responses[4],
            'biaScore': responses[5],
            'control_effectiveness': control_effectiveness,
            'scenario_compliance_data': responses[6]
        })


def prepare_controls_summary():
    controls = SecurityControls.objects.filter(framework='ISA 62443-2-1')
    summary = ""
    for control in controls:
        summary += f"Control: {control.Control}"
    return summary


def get_recommended_controls(scenario, threat_source):
    # Prepare the summary of controls
    controls_summary = prepare_controls_summary()

    # Construct the prompt for OpenAI
    prompt = f"Given these controls from the ISA 62443-2-1 standard:\n{controls_summary}\nWhat are the top 5 controls that would be most applicable for a scenario involving '{scenario}' with a threat source of '{threat_source}'? "

    # Make a call to OpenAI API
    try:
        response = openai.Completion.create(
            engine="text-davinci-002",  # Or the appropriate engine you are using
            prompt=prompt,
            max_tokens=250,  # Adjust as needed
            temperature=0.7  # Adjust for creativity level
        )
        return response.choices[0].text.strip()
    except Exception as e:
        # Handle exceptions (e.g., API errors)
        print(f"Error: {e}")
        return None


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


def reformat_attack_tree(data):
    # Recursive function to adjust the format
    def adjust_node_format(node):
        new_node = {'name': node['Node']}
        if 'Children' in node and node['Children']:
            new_node['children'] = [adjust_node_format(child) for child in node['Children']]
        return new_node

    formatted_tree = {'name': data['Attack'], 'children': []}
    for node in data['Nodes']:
        formatted_tree['children'].append(adjust_node_format(node))

    return formatted_tree


@login_required
def analyze_scenario(request):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    if request.method == 'POST':
        scenario = request.POST.get('scenario')
        attack_tree_drawn = request.POST.get('attackTreeDrawn') == 'true'
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

            pha_id = request.POST.get('phaID')

            try:
                cyber_pha = tblCyberPHAHeader.objects.get(ID=pha_id)
            except tblCyberPHAHeader.DoesNotExist:
                return JsonResponse({'error': 'PHA record not found'}, status=404)

            facility_type = cyber_pha.FacilityType
            industry = cyber_pha.Industry
            zone = cyber_pha.AssessmentZone
            unit = cyber_pha.AssessmentUnit
            address = cyber_pha.facilityAddress
            country = cyber_pha.country
            devices = cyber_pha.otherSummary

            # Construct a prompt for GPT-4
            system_message = f"""
            Given a cybersecurity scenario at a {facility_type} in the {industry} industry, located at {address} in {country}, specifically in the {zone} zone and the {unit} unit, described as: {scenario}. Considering the likely presence of these OT devices: {devices}, concisely describe in 50 words in a list format (separated by semicolons) of a maximum of 5 of the most likely direct consequences of the given scenario. The direct consequences should be specific to the facility and the mentioned details. Assume the role of an expert OT Cybersecurity risk advisor. Additional instruction: output ONLY the list items with no text either before or after the list items.
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
            consequence_list = consequence_text.split(';')  # Splitting based on the chosen delimiter

            attack_tree_json = {}

            if not attack_tree_drawn:
                attack_tree_system_message = f"""
                    Generate a hierarchical structure of a potential attack tree for the given cybersecurity scenario in a machine-readable JSON format. The structure should use 'name' for node labels and 'children' for nested nodes. Each node should represent a step or method in the attack, formatted as: {{'name': 'Node Name', 'children': [{{...}}]}}. EXTRA INSTRUCTION: Output MUST be in JSON format with no additional characters outside of the JSON structure.
                """

                # Query OpenAI API for the attack tree
                attack_tree_response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": attack_tree_system_message},
                        {"role": "user", "content": user_message}
                    ],
                    max_tokens=800,
                    temperature=0.3
                )

                # Process the response for attack tree
                attack_tree_raw = attack_tree_response['choices'][0]['message']['content']

                try:
                    # Parse the raw JSON string into a Python dictionary
                    attack_tree_json = json.loads(attack_tree_raw)
                except json.JSONDecodeError:
                    attack_tree_json = {"error": "Invalid JSON format from AI response"}

            return JsonResponse({'consequence': consequence_list, 'attack_tree': attack_tree_json})


    else:
        return JsonResponse({'consequence': [], 'attack_tree': {}, 'error': 'Not a valid scenario'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def generate_attack_tree(user_message):
    attack_tree_system_message = f"""
        Generate a hierarchical structure of a potential attack tree for the given cybersecurity scenario in a machine-readable JSON format. The structure should use 'name' for node labels and 'children' for nested nodes. Each node should represent a step or method in the attack, formatted as: {{'name': 'Node Name', 'children': [{{...}}]}}. EXTRA INSTRUCTION: Output MUST be in JSON format with no additional characters outside of the JSON structure.
    """

    # Query OpenAI API for the attack tree
    attack_tree_response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": attack_tree_system_message},
            {"role": "user", "content": user_message}
        ],
        max_tokens=800,
        temperature=0.3
    )

    # Process the response for attack tree
    attack_tree_raw = attack_tree_response['choices'][0]['message']['content']

    try:
        # Parse the raw JSON string into a Python dictionary
        return json.loads(attack_tree_raw)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON format from AI response"}


def is_inappropriate(text):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key

    try:
        response = openai.Moderation.create(
            input=text,
            model="text-moderation-latest"
        )
        # Check the 'flagged' field in the results
        return any(result['flagged'] for result in response['results'])
    except Exception as e:
        return False  # or handle error appropriately


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


@csrf_exempt
@require_POST
def assign_cyberpha_to_group(request):
    cyberpha_id = request.POST.get('cyberpha_id')
    existing_group_id = request.POST.get('existing_group_id')
    new_group_name = request.POST.get('new_group_name')
    new_group_type = request.POST.get('new_group_type')

    try:
        cyberpha = tblCyberPHAHeader.objects.get(pk=cyberpha_id)

        if existing_group_id:
            group = CyberPHA_Group.objects.get(pk=existing_group_id)
            # Check if the group is already assigned
            if group not in cyberpha.groups.all():
                cyberpha.groups.add(group)
            else:
                return JsonResponse({'status': 'error', 'message': 'CyberPHA is already assigned to this group.'})

        elif new_group_name and new_group_type:
            # Check if group with the same name and type already exists
            group, created = CyberPHA_Group.objects.get_or_create(name=new_group_name, group_type=new_group_type)
            if not created:
                return JsonResponse({'status': 'error', 'message': 'Group with this name and type already exists.'})
            cyberpha.groups.add(group)

        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


def fetch_groups(request):
    cyberpha_id = request.GET.get('cyberpha_id')
    cyberpha = tblCyberPHAHeader.objects.get(pk=cyberpha_id)
    groups = cyberpha.groups.all()

    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


def fetch_all_groups(request):
    groups = CyberPHA_Group.objects.all()
    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


from django.http import JsonResponse
import json


def retrieve_scenario_builder(request, scenario_id):
    try:
        # Retrieve the scenario from the database
        scenario = ScenarioBuilder.objects.get(id=scenario_id)

        # Parse the stored JSON data
        scenario_data = json.loads(scenario.scenario_data)

        # Extract elements from the scenario data
        attack_tree_data = scenario_data.get('attackTree')
        scenario_description = scenario_data.get('scenario')
        consequences = scenario_data.get('consequences', '').split("-")
        table_data = scenario_data.get('tableData')
        costs = scenario_data.get('costs')

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
            'consequences': consequences,
            'factors': factors,
            'costs': costs
        })

    except ScenarioBuilder.DoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
