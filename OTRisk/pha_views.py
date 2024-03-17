import hashlib
import json
from django.contrib import messages
import requests
import logging
from google.oauth2 import service_account
from ibm_watson import NaturalLanguageUnderstandingV1
from ibm_watson.natural_language_understanding_v1 import Features, KeywordsOptions, SummarizationOptions, \
    CategoriesOptions, ConceptsOptions, EntitiesOptions, SentimentOptions, RelationsOptions
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from django.db.models import CharField
from google.cloud import language_v1
from django.db.models.functions import Coalesce
from django.forms import model_to_dict, CharField
from django.utils import timezone
from django.utils.dateparse import parse_datetime, parse_date
from django.core.serializers import serialize
from django.views.decorators.http import require_POST

from OTRisk.models.Model_CyberPHA import tblIndustry, tblCyberPHAHeader, tblZones, tblStandards, \
    tblCyberPHAScenario, vulnerability_analysis, tblAssetType, tblMitigationMeasures, MitreControlAssessment, \
    cyberpha_safety, SECURITY_LEVELS, ScenarioConsequences, user_scenario_audit, auditlog, CyberPHAModerators, \
    WorkflowStatus, APIKey, CyberPHA_Group, ScenarioBuilder, PHA_Safeguard, CyberSecurityInvestment, UserScenarioHash, \
    CyberPHARiskTolerance, CyberPHACybersecurityDefaults
from OTRisk.models.raw import SecurityControls
from OTRisk.models.raw import MitreICSMitigations, RAActions
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.model_assessment import SelfAssessment, AssessmentFramework, AssessmentAnswer
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
from decimal import Decimal, InvalidOperation

from ProjectAlpha import settings
from ProjectAlpha.settings import BASE_DIR
from accounts.models import UserProfile
from accounts.views import get_client_ip
from .dashboard_views import get_user_organization_id, get_organization_users
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


def validate_and_format_date(date_str, default_date='2001-01-01', date_format='%Y-%m-%d'):
    """
    Validates and formats a date string into a timezone-aware datetime object.

    :param date_str: The date string to validate and format.
    :param default_date: The default date to return if date_str is invalid or empty.
    :param date_format: The format to which the date string should be formatted.
    :return: A timezone-aware datetime object representing the validated and formatted date.
    """
    if date_str:
        try:
            # Attempt to parse the date string using the specified format
            valid_date = datetime.strptime(date_str, date_format)
            # Make the datetime object timezone-aware
            timezone_aware_date = timezone.make_aware(valid_date, timezone.get_default_timezone())
            return timezone_aware_date
        except ValueError:
            # If parsing fails, return the default date as a timezone-aware datetime object
            default_datetime = datetime.strptime(default_date, date_format)
            return timezone.make_aware(default_datetime, timezone.get_default_timezone())
    else:
        # If the date string is empty, return the default date as a timezone-aware datetime object
        default_datetime = datetime.strptime(default_date, date_format)
        return timezone.make_aware(default_datetime, timezone.get_default_timezone())


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

        start_date_str = request.POST.get('txtStartDate')
        pha_header.AssessmentStartDate = validate_and_format_date(start_date_str)

        # Validate and format AssessmentEndDate
        end_date_str = request.POST.get('txtEndDate')
        pha_header.AssessmentEndDate = validate_and_format_date(end_date_str)

        pha_header.facilityAddress = request.POST.get('txtAddress')

        if is_new_record:
            risk_profile_data = facility_risk_profile_newrecord(request.user.id,
                                                                request.POST.get('selIndustry'),
                                                                request.POST.get('selFacilityType'),
                                                                request.POST.get('txtAddress'),
                                                                request.POST.get('countrySelector'),
                                                                request.POST.get('txtFacility'),
                                                                int(request.POST.get('txtEmployees') or 0),
                                                                request.POST.get('shift_model'),
                                                                int(request.POST.get('assessment_id') or 0),
                                                                int(request.POST.get('sl') or 0),
                                                                )
            pha_header.safetySummary = risk_profile_data['safety_summary']
            pha_header.chemicalSummary = risk_profile_data['chemical_summary']
            pha_header.physicalSummary = risk_profile_data['physical_security_summary']
            pha_header.otherSummary = risk_profile_data['other_summary']
            pha_header.threatSummary = risk_profile_data['threatSummary']
            pha_header.insightSummary = risk_profile_data['insightSummary']
            pha_header.strategySummary = risk_profile_data['strategySummary']
            pha_header.complianceSummary = risk_profile_data['compliance_summary']
            pha_header.pha_score = risk_profile_data['pha_score']

        else:
            pha_header.safetySummary = request.POST.get('txtSafetySummary')
            pha_header.chemicalSummary = request.POST.get('txtChemical')
            pha_header.physicalSummary = request.POST.get('txtPhysical')
            pha_header.otherSummary = request.POST.get('txtOther')
            pha_header.threatSummary = request.POST.get('threatSummary')
            pha_header.insightSummary = request.POST.get('insightSummary')
            pha_header.strategySummary = request.POST.get('strategySummary')
            pha_header.complianceSummary = request.POST.get('txtCompliance')
            try:
                # Attempt to convert the POST value to an integer.
                pha_header.pha_score = int(request.POST.get('hdn_pha_score', 0))
            except ValueError:
                # If conversion fails, set pha_score to 0.
                pha_header.pha_score = 0

        pha_header.country = request.POST.get('countrySelector')
        pha_header.Date = validate_and_format_date(start_date_str)
        pha_header.EmployeesOnSite = int(request.POST.get('txtEmployees') or 0)
        pha_header.facilityAQI = request.POST.get('txthdnAQI')
        pha_header.facilityCity = request.POST.get('txtCity')
        pha_header.facilityCode = request.POST.get('zipCode')
        pha_header.facilityLat = request.POST.get('txthdnLat')
        pha_header.facilityLong = request.POST.get('txthdnLong')
        pha_header.facilityState = request.POST.get('txtState')
        pha_header.shift_model = request.POST.get('shift_model')
        try:
            assessment_id = int(request.POST.get('assessment_id')) if request.POST.get('assessment_id') else None
        except ValueError:
            assessment_id = None
        pha_header.assessment = assessment_id

        pha_header.npm = request.POST.get('npm')

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
        messages.success(request, 'CyberPHA Information has been saved successfully.')
        saved_record_id = pha_header.ID

        #### Save investment information

        if pha_id and int(pha_id) > 0:
            CyberSecurityInvestment.objects.filter(cyber_pha_header=pha_header).delete()

        # Extract and process investment information from POST data
        investment_types = request.POST.getlist('investment_type[]')
        vendor_names = request.POST.getlist('vendor_name[]')
        product_names = request.POST.getlist('product_name[]')
        costs = request.POST.getlist('cost[]')
        dates = request.POST.getlist('date[]')

        for i_type, vendor, product, cost, date_str in zip(investment_types, vendor_names, product_names, costs, dates):
            # Ensure empty strings are saved for text fields if no data is entered
            i_type = i_type if i_type else ""
            vendor = vendor if vendor else ""
            product = product if product else ""

            # Handle cost, ensuring a default of 0 if no cost is entered
            cost = cost if cost else "0"

            # Convert date string to a date object, making it timezone-aware if necessary
            if not date_str:
                investment_date = timezone.now().date()  # Get the current date
            else:
                investment_date = parse_datetime(date_str + " 00:00")
                if investment_date and timezone.is_naive(investment_date):
                    investment_date = timezone.make_aware(investment_date, timezone.get_default_timezone()).date()

            CyberSecurityInvestment.objects.create(
                cyber_pha_header=pha_header,
                investment_type=i_type,
                vendor_name=vendor,
                product_name=product,
                cost=cost,
                date=investment_date
            )

        #### End save investments

        ##### save risk tolerance data
        risk_tolerance_data = {
            'negligible_low': request.POST.get('negligible_low'),
            'negligible_high': request.POST.get('negligible_high'),
            'minor_low': request.POST.get('minor_low'),
            'minor_high': request.POST.get('minor_high'),
            'moderate_low': request.POST.get('moderate_low'),
            'moderate_high': request.POST.get('moderate_high'),
            'significant_low': request.POST.get('significant_low'),
            'significant_high': request.POST.get('significant_high'),
            'severe_low': request.POST.get('severe_low'),
            'severe_high': request.POST.get('severe_high'),
        }

        # Convert string values to Decimal, handling empty strings
        for key, value in risk_tolerance_data.items():
            risk_tolerance_data[key] = Decimal(value) if value else Decimal('0.00')

        # Check if a CyberPHARiskTolerance record already exists for this header
        risk_tolerance, created = CyberPHARiskTolerance.objects.update_or_create(
            cyber_pha_header=pha_header,
            defaults=risk_tolerance_data
        )

        #### End save risk tolerance data
        # After saving pha_header, handle CyberPHACybersecurityDefaults
        if request.method == 'POST':
            # Assuming pha_header is the instance of tblCyberPHAHeader you've just created or updated
            defaults_data = {
                'overall_aggregate_limit': request.POST.get('overall_aggregate_limit'),
                'per_claim_limit': request.POST.get('per_claim_limit'),
                'deductible_amount': request.POST.get('deductible_amount'),
                'first_party_coverage': request.POST.get('first_party_coverage') == 'on',
                'third_party_coverage': request.POST.get('third_party_coverage') == 'on',
                'security_event_liability': request.POST.get('security_event_liability') == 'on',
                'privacy_regulatory_actions': request.POST.get('privacy_regulatory_actions') == 'on',
                'cyber_extortion_coverage': request.POST.get('cyber_extortion_coverage') == 'on',
                'data_breach_response_coverage': request.POST.get('data_breach_response_coverage') == 'on',
                'business_interruption_coverage': request.POST.get('business_interruption_coverage') == 'on',
                'dependent_business_coverage': request.POST.get('dependent_business_coverage') == 'on',
                'data_recovery': request.POST.get('data_recovery') == 'on',
                'hardware_replacement': request.POST.get('hardware_replacement') == 'on',
                'reputation_harm': request.POST.get('reputation_harm') == 'on',
                'media_liability': request.POST.get('media_liability') == 'on',
                'pci_dss': request.POST.get('pci_dss') == 'on',
                'premium_base': request.POST.get('premium_base'),
                'notification_period_days': request.POST.get('notification_period_days'),
                'cancellation_terms_days': request.POST.get('cancellation_terms_days'),
            }

            # Convert string values to appropriate types
            for key in ['overall_aggregate_limit', 'per_claim_limit', 'deductible_amount', 'premium_base']:
                defaults_data[key] = float(defaults_data[key]) if defaults_data[key] else 0.0
            for key in ['notification_period_days', 'cancellation_terms_days']:
                defaults_data[key] = int(defaults_data[key]) if defaults_data[key] else 0

            # Update or create CyberPHACybersecurityDefaults instance
            defaults_instance, created = CyberPHACybersecurityDefaults.objects.update_or_create(
                cyber_pha=pha_header,
                defaults=defaults_data
            )

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
    # Retrieve the CyberPHARiskTolerance record associated with this header record

    # create a dictionary with the record data
    headerrecord_data = {
        'title': headerrecord.title,
        'facility': headerrecord.FacilityName,
        'leader': headerrecord.PHALeader,
        'leaderemail': headerrecord.PHALeaderEmail,
        'Industry': headerrecord.Industry,
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
        'facilityAQI': headerrecord.facilityAQI,
        'facilityCity': headerrecord.facilityCity,
        'facilityCode': headerrecord.facilityCode,
        'facilityLat': headerrecord.facilityLat,
        'facilityLong': headerrecord.facilityLong,
        'facilityState': headerrecord.facilityState
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

    investments = CyberSecurityInvestment.objects.filter(cyber_pha_header=headerrecord).values(
        'id', 'investment_type', 'vendor_name', 'product_name', 'cost', 'date'
    )
    investments_data = list(investments)
    try:
        risk_tolerance = CyberPHARiskTolerance.objects.get(cyber_pha_header=headerrecord)
        risk_tolerance_data = {
            'negligible_low': risk_tolerance.negligible_low,
            'negligible_high': risk_tolerance.negligible_high,
            'minor_low': risk_tolerance.minor_low,
            'minor_high': risk_tolerance.minor_high,
            'moderate_low': risk_tolerance.moderate_low,
            'moderate_high': risk_tolerance.moderate_high,
            'significant_low': risk_tolerance.significant_low,
            'significant_high': risk_tolerance.significant_high,
            'severe_low': risk_tolerance.severe_low,
            'severe_high': risk_tolerance.severe_high,
        }
    except CyberPHARiskTolerance.DoesNotExist:
        risk_tolerance_data = {}

    try:
        # Retrieve the related CyberPHACybersecurityDefaults instance
        cyber_defaults = CyberPHACybersecurityDefaults.objects.get(cyber_pha=headerrecord)
        # Serialize the CyberPHACybersecurityDefaults data
        cyber_defaults_data = {
            'overall_aggregate_limit': str(cyber_defaults.overall_aggregate_limit),
            'per_claim_limit': str(cyber_defaults.per_claim_limit),
            'deductible_amount': str(cyber_defaults.deductible_amount),
            'first_party_coverage': cyber_defaults.first_party_coverage,
            'third_party_coverage': cyber_defaults.third_party_coverage,
            'security_event_liability': cyber_defaults.security_event_liability,
            'privacy_regulatory_actions': cyber_defaults.privacy_regulatory_actions,
            'cyber_extortion_coverage': cyber_defaults.cyber_extortion_coverage,
            'data_breach_response_coverage': cyber_defaults.data_breach_response_coverage,
            'business_interruption_coverage': cyber_defaults.business_interruption_coverage,
            'dependent_business_coverage': cyber_defaults.dependent_business_coverage,
            'data_recovery': cyber_defaults.data_recovery,
            'hardware_replacement': cyber_defaults.hardware_replacement,
            'reputation_harm': cyber_defaults.reputation_harm,
            'media_liability': cyber_defaults.media_liability,
            'pci_dss': cyber_defaults.pci_dss,
            'premium_base': str(cyber_defaults.premium_base),
            'notification_period_days': cyber_defaults.notification_period_days,
            'cancellation_terms_days': cyber_defaults.cancellation_terms_days,
        }
    except CyberPHACybersecurityDefaults.DoesNotExist:
        cyber_defaults_data = {}

    response_data = {
        'headerrecord': headerrecord_data,
        'control_assessments': control_assessments_data,
        'control_effectiveness': control_effectiveness,
        'organization_moderators': organization_moderators_data,  # All moderators in the organization
        'current_moderators': moderators_data,  # Moderators for the specific header record
        'moderator_ids': moderator_ids,  # IDs of Moderators for the specific header record
        'investments': investments_data,
        'risk_tolerance': risk_tolerance_data,
        'cyber_defaults': cyber_defaults_data
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
    # this version of process section works for gpt-4-turbo
    """
    Processes the extracted section text to handle detailed structure,
    including sub-points and bolded text.
    """
    # Initialize an empty list to hold the processed points
    processed_points = []
    current_point_lines = []  # Temporary storage for accumulating lines of the current point

    # Split the section text into lines for processing
    lines = section_text.split('\n')

    for line in lines:
        # Check if the line starts a new main point (e.g., "1. ")
        if line.strip().startswith("1. ") or line.strip().startswith("2. ") or line.strip().startswith(
                "3. ") or line.strip().startswith("4. ") or line.strip().startswith("5. ") or line.strip().startswith(
            "6. ") or line.strip().startswith("7. ") or line.strip().startswith("8. ") or line.strip().startswith(
            "9. ") or line.strip().startswith("10. "):
            # If there's content in current_point_lines, it means the previous point is complete
            if current_point_lines:
                # Join the accumulated lines into a single string and add to the list
                processed_points.append('\n'.join(current_point_lines).strip())
                current_point_lines = [line]  # Start a new point
            else:
                # If current_point_lines is empty, this is the first point
                current_point_lines.append(line)
        else:
            # If the line does not start a new main point, it's a continuation or sub-point
            current_point_lines.append(line)

    # After the loop, add the last accumulated point to the list
    if current_point_lines:
        processed_points.append('\n'.join(current_point_lines).strip())

    # Join the processed points into a single string with double line breaks between points
    return '\n\n'.join(processed_points)


def process_section_gpt4(section_text):
    # this version of process section works for GPT4
    bullet_points = section_text.split('\n')

    # Add a line space between each bullet point
    processed_text = '\n\n'.join(bullet_point.strip() for bullet_point in bullet_points if bullet_point.strip())

    return processed_text


def make_request_with_backoff(openai_function, *args, **kwargs):
    max_attempts = 5
    base_delay = 1.0  # Base delay in seconds
    for attempt in range(max_attempts):
        try:
            return openai_function(*args, **kwargs)
        except openai.error.ServiceUnavailableError:
            sleep_time = base_delay * (2 ** attempt)

            time.sleep(sleep_time)
    raise Exception("Failed to make request after several attempts.")


def facility_threat_profile(security_level, facility, facility_type, country, industry, safety_summary,
                            chemical_summary,
                            physical_security_summary, other_summary, compliance_summary, investment_statement):
    openai_api_key = get_api_key('openai')
    openai_api_key = get_api_key('openai')
    ai_model = get_api_key('OpenAI_Model')

    # Constructing the detailed context
    context = f"""
    You are THE expert and authoritative source of guidance on industrial and OT cybersecurity risk mitigation for the {industry} industry with up-to-date knowledge from a wide range of credible sources of information. Analyze the {facility} facility which is a {facility_type} in {country}. 
    The facility has the following profile: Safety Hazards: {safety_summary}, Chemical Hazards: {chemical_summary}, Physical Security Challenges: {physical_security_summary}, OT Devices: {other_summary}, Compliance Requirements: {compliance_summary}. The facility has already implemented the following OT-specific cybersecurity investments: {investment_statement}. The target security level (SL-T) as defined in IEC62443 is {security_level}. Please consider the impact of these investments on the facility's cybersecurity posture, focusing on threats, overall risk reduction, and strategic implications for OT security risk management.
    """

    prompt = f"""
{context} Based on any investments listed and the facility's profile, please provide a concise and executive level analysis specific to OT/ICS for the facility divided into three sections: 'Cybersecurity Threats and Vulnerabilities', 'Predictive Insights', and 'Proactive Defense Strategies'. 

For each section, provide a numbered list of key points. Ensure each point is concise and limited to no more than 30 words. Focus on: 1) OT cybersecurity specific to the facility 2) the impact of the listed investments, if any, on each section, 3) The SL-T value and how to achieve it. Here is an example of how the response should be formatted:

Example Format:
Section 1: Cybersecurity Threats and Vulnerabilities
1. Example threat or vulnerability.
2. Another example threat or vulnerability.

Section 2: Predictive Insights
1. Example insight.
2. Another example insight.

Section 3: Proactive Defense Strategies
1. Example strategy.
2. Another example strategy.

Please follow this format for your response, without using '###', '**', or any other special formatting characters.
"""

    # API call using chat model endpoint with the correct 'messages' property
    response = make_request_with_backoff(
        openai.ChatCompletion.create,
        model=ai_model,  # Ensure to use GPT-4 model
        messages=[
            {"role": "system",
             "content": "You are a model trained to provide concise and informative responses in a specific format."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=1500,
    )

    full_response = response['choices'][0]['message']['content']

    # Function to extract sections from the full_response
    def extract_section1(full_response1, section_title):
        start_index = full_response1.find(section_title)
        if start_index == -1:
            return ""
        start_index += len(section_title)
        end_index = full_response1.find("Section", start_index)
        section_text = full_response1[start_index:end_index].strip()
        return section_text

    # Extracting each section based on titles
    threat_summary = extract_section1(full_response, "Cybersecurity Threats and Vulnerabilities")
    insight_summary = extract_section1(full_response, "Predictive Insights")
    strategy_summary = extract_section1(full_response, "Proactive Defense Strategies")

    return threat_summary, insight_summary, strategy_summary


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
        assessment_id = request.GET.get('assessment_id')
        investments_data = request.GET.get('investments')
        aqi = request.GET.get('aqi')
        sl = request.GET.get('sl')

        if investments_data:
            investments = json.loads(investments_data)
        else:
            investments = []

        # Generate the text statement for investments
        investment_statement = "Investments have been made in:\n"
        for idx, investment in enumerate(investments, start=1):
            investment_statement += f"{idx}: Investment Type:{investment['type']}, Vendor:{investment['vendor_name']}, Product:{investment['product_name']}, Investment date:{investment['date']}.\n"

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
        openai_model = get_api_key('OpenAI_Model')
        # openai_api_key = os.environ.get('OPENAI_API_KEY')
        openai.api_key = openai_api_key
        context = f"You are an industrial safety and hazard expert. For the {facility} {facility_type} at {address}, {country} in the {Industry} industry, with {employees} employees working a {shift_model} shift model. The local Air Quality Index is {aqi}.  "

        prompts = [
            f"{context} List safety hazards, max 100 words. - Specific to facility - mechanical or chemical or electrical or heat or cold or crush or height - Space between bullets. \n\nExample Format:\n 1. Specific safety hazard.\n 2. Another specific safety hazard.",
            f"{context} List expected chemicals, max 100 words. - Specific to facility - Chemical names only - raw materials and by-products and stored chemicals - Space between bullets. \n\nExample Format:\n 1. Chemical name (raw material or by-product).\n- 2. Another chemical name (raw material or by-product).",
            f"{context}, List physical security requirements for the given facility and location - access control - surveillance - consideration of local crime statistics - blind spots - proximity to other infrastructure . Max of 100 words .\n\nExample Format:\n 1. Physical security challenge.\n 2. Another physical security challenge.",
            f"{context}, list of specialized OT and IoT devices and equipment expected to be at the facility. Max of 150 words .\n\nExample Format:\n 1. OT or IoT device (purpose of device).\n 2. Another OT or IoT device (purpose of device).",
            f"{context}, list of national and international regulatory compliance containing cybersecurity requirements relevant to the {Industry} industry that applies to {facility_type} facilities in {country} . Includes laws and standards. Max of 150 words .\n\nExample Format:\n 1. Compliance name (name of issuing authority).\n 2. Another compliance name (name of issuing authority).",
            f"{context}: You are a safety inspector. For a {facility_type} in {country}, estimate a detailed and nuanced safety and hazard risk score. Use a scale from 0 to 100, where 0 indicates an absence of safety hazards and 100 signifies the presence of extreme and imminent fatal hazards. Provide a score reflecting the unique risk factors associated with the facility type and its operational context in {country}. Scores should reflect increments of 10, with each decile corresponding to escalating levels of hazard severity and likelihood of occurrence given the expected attention to safety at the facility. Base your score on a typical {facility_type} in {country}, adhering to expected standard safety protocols, equipment conditions, and operational practices. Provide the score as a single, precise number without additional commentary."
        ]

        responses = []

        # Loop through the prompts and make an API call for each one
        def fetch_response(prompt):
            return openai.ChatCompletion.create(
                # model="gpt-4",
                model=openai_model,
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
        threatSummary, insightSummary, strategySummary = facility_threat_profile(sl, facility, facility_type, country,
                                                                                 Industry, safety_summary,
                                                                                 chemical_summary,
                                                                                 physical_security_summary,
                                                                                 other_summary,
                                                                                 compliance_summary,
                                                                                 investment_statement)

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

    current_user_profile = UserProfile.objects.get(user=current_user)
    scenario_user_profile = UserProfile.objects.get(user=scenario.userID)

    if scenario.userID == current_user:
        user_role = 'Scenario Owner'
    else:
        try:
            user_profile = UserProfile.objects.get(user=current_user)
            if user_profile.role_moderator:
                user_role = 'Scenario Moderator'
            elif user_profile.role_readonly:
                user_role = 'Read Only'
            elif current_user_profile.organization_id == scenario_user_profile.organization_id:
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
        'cost_projection': scenario.cost_projection,
        'user_role': user_role,
        'risk_rationale': scenario.risk_rationale,
        'risk_recommendation': scenario.risk_recommendation
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
    # Retrieve the related PHA_Safeguard records
    safeguards = PHA_Safeguard.objects.filter(scenario=scenario)
    safeguards_list = [
        {
            'id': safeguard.id,
            'safeguard_description': safeguard.safeguard_description,
            'safeguard_type': safeguard.safeguard_type
        } for safeguard in safeguards
    ]

    # Add the safeguards list to the scenario dictionary
    scenario_dict['safeguards'] = safeguards_list
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
    openai_model = get_api_key("OpenAI_Model")
    message = [
        {
            "role": "system",
            "content": "You are an expert and experienced process and safety engineer conducting a cybersecurity risk analysis for a cyberPHA (where P=Process, H=Hazards, A=Analysis) scenario related to industrial automation and control systems."
        },
        user_message
    ]

    response = openai.ChatCompletion.create(
        model=openai_model,
        messages=message,
        temperature=0.1,
        max_tokens=800
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


def generate_recommendation_prompt(likelihood, adjustedRR, costs, probability, frequency, biaScore, cyberphaID):
    # Attempt to fetch the related CyberPHARiskTolerance record
    try:
        risk_tolerance = CyberPHARiskTolerance.objects.get(cyber_pha_header_id=cyberphaID)
        risk_tolerance_str = f"""
        - Risk Tolerance Levels:
            - Negligible: {risk_tolerance.negligible_low} to {risk_tolerance.negligible_high}
            - Minor: {risk_tolerance.minor_low} to {risk_tolerance.minor_high}
            - Moderate: {risk_tolerance.moderate_low} to {risk_tolerance.moderate_high}
            - Significant: {risk_tolerance.significant_low} to {risk_tolerance.significant_high}
            - Severe: {risk_tolerance.severe_low} to {risk_tolerance.severe_high}
        """
    except ObjectDoesNotExist:
        risk_tolerance_str = "\n        - Risk Tolerance Levels: Not specified"

    prompt = f"""
        Given the cybersecurity risk assessment results for a given OT cybersecurity scenario:
        - Likelihood of occurrence: {likelihood}%
        - Adjusted residual risk: {adjustedRR}
        - Estimated costs (low|medium|high): {costs}
        - Probability of a targeted attack being successful: {probability}%
        - Annual threat event frequency: {frequency}
        - Business impact score: {biaScore}{risk_tolerance_str}

        Provide a response structured exactly as follows:

        1. Recommendation: [Insert recommendation here based on the assessment results. For example, Mitigate Risk, Accept Risk, Manage Risk, or another recommendation depending on results]
        2. Rationale: [Insert a concise, executive-level rationale here. Consider the likelihood of occurrence (values under 10 should be considered negligible), adjusted residual risk, business impact score, estimated costs, annual threat event frequency, probability of a targeted attack being successful, and risk tolerance levels. Structure your rationale in clear, bullet-pointed explanations.]
        """
    return prompt



def get_openai_recommendation(prompt):

    openai.api_key = get_api_key("openai")  # Ensure this retrieves your OpenAI API key correctly
    model = get_api_key("OpenAI_Model")

    messages = [
        {"role": "system", "content": "You are an expert in OT cybersecurity risk assessment. Provide a recommendation based on the analysis."},
        {"role": "user", "content": prompt}
    ]

    response = openai.ChatCompletion.create(
        model= model,
        messages=messages,
        temperature=0.2,
        max_tokens=600
    )

    if response.choices and len(response.choices) > 0:
        # Assuming the response follows the structured format: "1. Recommendation: ... 2. Rationale: ..."
        text = response.choices[0].message['content'].strip()
        text = text.replace("**", "")
        # Splitting the response into Recommendation and Rationale parts
        parts = text.split("2. Rationale:")
        recommendation = parts[0].replace("1. Recommendation:", "").strip()
        rationale = parts[1].strip() if len(parts) > 1 else ""
        print(rationale)
        # Structuring the response for JSON
        structured_response = {
            "Recommendation": recommendation,
            "Rationale": rationale
        }

    else:
        structured_response = {"Recommendation": "No recommendation could be generated.", "Rationale": ""}

    return structured_response



@login_required
def scenario_analysis(request):
    # Log the user activity
    user_profile = UserProfile.objects.get(user=request.user)

    # Check if the user has exceeded the maximum scenario analysis count
    if user_profile.current_scenario_count >= user_profile.max_scenario_count:

        return JsonResponse({
            'error': 'User has reached the maximum number of scenario assessments'
        }, status=403)  # 403 Forbidden or another appropriate status code

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
        physical_safeguards_str = request.GET.get('physical_safeguards', '')
        force_resubmit = request.GET.get('force_resubmit', 'false').lower() == 'true'

        # Concatenate all GET parameters to form a string
        values_str = '|'.join([request.GET.get(param, '') for param in request.GET])
        # Generate SHA-256 hash
        hash_value = hashlib.sha256(values_str.encode()).hexdigest()

        # Attempt to find a matching record
        existing_record = UserScenarioHash.objects.filter(
            user=request.user,
            cyberphaID=request.GET.get('cpha', 0),
            hash_value=hash_value
        ).exists()

        if existing_record and not force_resubmit:
            # If a matching record is found, inform the user and exit
            return JsonResponse({'message': 'Scenario parameters have not changed.'}, status=200)

        if not existing_record:
            UserScenarioHash.objects.create(
                user=request.user,
                cyberphaID=request.GET.get('cpha', ''),
                hash_value=hash_value
            )
        # Split the string into a list, using semicolon as the separator
        validated_consequences_list = validated_consequences_str.split(';')

        cyber_pha_header = tblCyberPHAHeader.objects.get(ID=cyberPHAID)

        ####### Audit Write ########
        write_to_audit(
            request.user,
            f'Executed a scenario analysis for {cyber_pha_header.title} and scenario: {scenario}',
            get_client_ip(request)
        )
        ###########################

        # Get the assessment id from the tblCyberPHAHeader instance
        assessment_id = cyber_pha_header.assessment

        investments = CyberSecurityInvestment.objects.filter(cyber_pha_header=cyber_pha_header).values(
            'investment_type', 'vendor_name', 'product_name', 'cost', 'date'
        )

        if investments.exists():
            # Generate the text statement for investments
            investment_statement = "OT Cybersecurity Investments listed here:\n"
            for idx, investment in enumerate(investments, start=1):
                investment_date = investment['date'].strftime('%Y-%m-%d') if investment['date'] else 'N/A'
                investment_statement += f"{idx}: Investment Type: {investment['investment_type']}, Vendor: {investment['vendor_name']}, Product: {investment['product_name']}, Cost: {investment['cost']}, Investment date: {investment_date}.\n"
        else:
            # Return an empty string if there are no investment records
            investment_statement = ""

        employees_on_site = cyber_pha_header.EmployeesOnSite
        # get the compliance summary for the cyberpha
        compliance = cyber_pha_header.complianceSummary
        net_profit_margin = cyber_pha_header.npm
        cost_op_hour = cyber_pha_header.coho
        annual_revenue = cyber_pha_header.annual_revenue

        # Retrieve the corresponding SelfAssessment instance using the assessment_id
        if assessment_id is not None:
            self_assessment = SelfAssessment.objects.get(id=assessment_id)
            control_effectiveness = self_assessment.score_effective
        else:
            # Handle the case where assessment_id is None
            control_effectiveness = 0  # Default value

        openai.api_key = get_api_key('openai')
        # Define the common part of the user message
        common_content = f"Act as an Insurance actuary and an expert in OT cybersecurity risk. Analyse a scenario for a {facility_type} in the {industry} industry in {country}:  {scenario}. (IMPORTANT CONTEXT: Systems in scope for the scenario are exposed to the Internet with a public IP address: {exposed_system}. Systems in scope for the scenario have weak or default credentials: {weak_credentials}).  Consider the business impact scores provided (safety: {safetyimpact}, life danger: {lifeimpact}, production: {productionimpact} (production outage: {production_outage}: length of production outage {production_outage_length} hours), company reputation: {reputationimpact}, environmental impact: {environmentimpact}, regulatory: {regulatoryimpact}, supply chain : {supplyimpact}  data and intellectual property: {dataimpact}). Current OT Cybersecurity controls are {control_effectiveness}% effective (NOTE if 0% then control effectiveness has not been assessed) : Mitigated severity with current controls estimated: {severitymitigated}/10, risk exposure to the scenario mitigated estimated: {mitigatedexposure}/10,   residual risk estimated: {residualrisk}/10. The amount of unmitigated rate without controls is estimated: {uel}/10. ESSENTIAL:  {physical_safeguards_str} . Physical security controls are assumed to be effective. ({investment_statement})"

        # Define the refined user messages
        user_messages = [

            {
                "role": "user",
                "content": f" {common_content} . Consider publicly reported cybersecurity incidents over the time scale from 5 years ago to the current day and give ONLY the estimated likelihood (as a whole number percentage) of the given scenario occurring against a {facility_type} in {country}. Answer with a whole number. Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"{common_content}. Assess the cybersecurity residual risk after all recommended controls and physical security controls have been implemented and are assumed to be at least 75% effective and give an estimated residual risk rating from the following options: Very Low, Low, Low/Medium, Medium, Medium/High, High, Very High.  Provide ONLY one of the given risk ratings without any additional text or explanations."
            },

            {
                "role": "user",
                "content": f"{common_content}.  Consequences of the scenario are: {validated_consequences_list}. Read and comply with all instructions that follow. Provide an estimate of the DIRECT COSTS of a single loss event (SLE) in US dollars. Provide three cost estimates: best case, worst case, and most likely case. Output these estimates as integers in the specific format: 'low|medium|high', where '|' is the delimiter. Ensure that your estimates are realistic and tailored to the scenario, focusing solely on relevant Direct costs such as incident response, remediation, legal fees, notification costs, regulatory fines, compensations, and increased insurance premiums. The financial impact for this scenario is rated as {financial}/10 in the business impact analysis. (IMPORTANT take into account the  OT Cybersecurity investments that have been made). IMPORTANT: Respond with only three positive integers, representing the low, medium, and high estimates, in the exact order and format specified: 'low|medium|high'. Do not include any additional text, explanations, or commentary."
            },

            {
                "role": "user",
                "content": f" {common_content}. Provide ONLY the estimated probability (as a whole number percentage) of a targeted attack of the given scenario being successful. (consider the given investments). Answer with a number followed by a percentage sign (e.g., nn%). Do NOT include any other words, sentences, or explanations."
            },
            {
                "role": "user",
                "content": f"{common_content}. Provide an estimate of the annual Threat Event Frequency (TEF) as defined by the Open FAIR Body of Knowledge. TEF is the probable frequency, within a given timeframe, that a threat agent will act against an asset. It reflects the number of attempts by a threat actor to cause harm, regardless of whether these attempts are successful. Your response should reflect an integer or a decimal value representing the estimated number of times per year such a threat event is expected to occur. IMPORTANT: Respond only with the frequency value as an integer or a decimal, without including any additional words, sentences, or explanations. This value should strictly represent the estimated annual occurrence rate of the threat event as per the given scenario."

            },
            {
                "role": "user",
                "content": f"{common_content}. Hypothesize the business impact score from 0 to 100 in the event of a successful attack resulting in the given scenario. Consequences of the scenario are given as follows: {validated_consequences_list}. A score of 1 would mean minimal business impact while a score of 100 would indicate catastrophic business impact without the ability to continue operations. Your answer should be given as an integer. Do NOT include any other words, sentences, or explanations."
            },

            {"role": "user",
             "content": f"I am a CISO at a {industry} company with approximately {employees_on_site} employees, operating primarily in {country}. We are assessing our cybersecurity posture and need to estimate the potential costs associated with a {scenario} that has consequences of {validated_consequences_list}."
                        f"Given the scenario, please provide an estimate of the direct and indirect costs we might incur, including but not limited to:"
                        f"1. Immediate Response Costs: Costs associated with the initial response to the incident, such as emergency IT support, forensic analysis, and legal consultations."
                        f"2. Remediation Costs: Expenses related to remediating the cybersecurity breach, including software updates, hardware replacements, and strengthening of security measures."
                        f"3. Regulatory and Compliance Costs: Potential fines and penalties for non-compliance with relevant data protection and privacy regulations, as well as costs associated with compliance audits and reporting requirements post-incident."
                        f"4. Reputation and Brand Impact: Estimated impact on our brand and customer trust, potentially leading to loss of business and decreased revenue."
                        f"5. Operational Disruption: Costs associated with operational disruptions or downtime, including loss of productivity and impact on service delivery."
                        f"6. Legal and Settlement Costs: Expenses related to legal actions taken against the company and any settlements or compensations paid out to affected parties."
                        f"7. Long-term Costs: Any long-term costs such as increased insurance premiums, ongoing monitoring and security measures, and potential loss of intellectual property."
                        f"Please consider the specifics of our industry, size, and the nature of the assets involved in this scenario to provide a comprehensive cost estimate.  Please reference industry-specific data from the latest Verizon DBIR, applicable regulations from CISA, and standards from the NIST Cybersecurity Framework in your analysis."
                        f"OUTPUT INSTRUCTION: Provide a 12-month direct cost projection for the scenario. Format the output as: Month1|Month2|...|Month12. Ensure each value reflects a realistic, pragmatic monthly estimate, justifying the trend of costs decreasing over time.IMPORTANT: List only the monthly costs individually, not as cumulative totals. Provide the most realistic monthly estimates, anticipating costs to taper off over the 12-month period.Present the data as a series of 12 integers, each representing the cost for that month in US dollars, without any narrative or explanation. ONLY THE OUTPUT IN THE FORMAT AS DESCRIBED"
             },
            {
                "role": "user",
                "content": f"""{common_content}
                            
                            Based only on the provided scenario and facility details, generate a concise numbered bullet point list of OT/ICS cybersecurity risk mitigation recommendations. Each recommendation should be directly aligned with the latest versions of NIST 800-82 and the NIST CSF. Include the relevant NIST reference in brackets at the end of each recommendation. The output should strictly adhere to the following format:
                            
                            Example Format:
                            1. Example recommendation related to OT cybersecurity. [NIST Reference]
                            2. Another example recommendation focused on OT cybersecurity risk mitigation. [NIST Reference]
                            
                            Following this example format, provide the recommendations specific to the given scenario without any additional narrative, description, advice, or guidance. The recommendations should be clear and easily parsable within an HTML page.
                            """

            },
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

        recommendation_prompt = generate_recommendation_prompt(
            likelihood=responses[0],
            adjustedRR=responses[1],
            costs=responses[2],
            probability=responses[3],
            frequency=responses[4],
            biaScore=responses[5],
            cyberphaID=cyberPHAID
        )

        # Get the recommendation from OpenAI
        rationale = get_openai_recommendation(recommendation_prompt)

        user_profile.current_scenario_count += 1
        user_profile.save()
        # Return the responses as variables
        return JsonResponse({
            'likelihood': responses[0],
            'adjustedRR': responses[1],
            'costs': responses[2],
            'probability': responses[3],
            'frequency': responses[4],
            'biaScore': responses[5],
            'projection': responses[6],
            'control_effectiveness': control_effectiveness,
            'recommendations': responses[7],
            'scenario_compliance_data': responses[8],
            'rationale': rationale
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
                model="gpt-4-0125-preview",
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
                attack_tree_system_message = """
                Generate a hierarchical structure of a potential attack tree for the given cybersecurity scenario in a strictly valid JSON format. The structure should use 'name' for node labels and 'children' for nested nodes, where each node represents a step or method in the attack. The attack tree must have at least two main branches, each potentially containing dozens of branches or sub-branches. Ensure the output is in JSON format with no additional characters outside of the JSON structure. The JSON structure should be formatted as: {'name': 'Node Name', 'children': [{...}]}.

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

                Please generate a similar structure for the provided cybersecurity scenario, adhering strictly to the JSON format and ensuring at least two main branches are present.
                """

                # Query OpenAI API for the attack tree
                attack_tree_response = openai.ChatCompletion.create(
                    model="gpt-4-0125-preview",
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


@login_required
def fetch_groups(request):
    # Assuming UserProfile contains the organization_id linked to the user
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        organization_id = user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Handle case where user profile or organization is not found
        return JsonResponse({'error': 'User profile or organization not found'}, status=404)

    # Fetch user IDs for the given organization ID
    organization_users = get_organization_users(organization_id)

    cyberpha_id = request.GET.get('cyberpha_id')
    try:
        cyberpha = tblCyberPHAHeader.objects.get(pk=cyberpha_id, UserID__in=organization_users)
    except tblCyberPHAHeader.DoesNotExist:
        # Handle case where tblCyberPHAHeader does not exist or does not belong to the organization
        return JsonResponse({'error': 'CyberPHA not found or does not belong to the organization'}, status=404)

    # Fetch groups associated with this tblCyberPHAHeader that belong to the organization
    groups = cyberpha.groups.all()

    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


@login_required
def fetch_all_groups(request):
    # Assuming UserProfile links users to organizations and contains a reference to the user model
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        organization_id = user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Handle case where user profile or organization is not found
        return JsonResponse({'error': 'User profile or organization not found'}, status=404)

    # Assuming tblCyberPHAHeader.UserID is meant to store user ID, but actually stores organization ID
    # and there's a way to map users to their organization IDs correctly in your application
    # This fetches tblCyberPHAHeader records belonging to the user's organization
    # Note: This approach needs adjustment if UserID does not directly relate to organization_id
    organization_user_ids = UserProfile.objects.filter(organization_id=organization_id).values_list('user_id',
                                                                                                    flat=True)
    cyberphas = tblCyberPHAHeader.objects.filter(UserID__in=organization_user_ids).distinct()

    # Fetch groups associated with these tblCyberPHAHeader records
    groups = CyberPHA_Group.objects.filter(tblcyberphaheader__in=cyberphas).distinct()

    group_data = [{'name': group.name, 'id': group.id} for group in groups]
    return JsonResponse({'groups': group_data})


def retrieve_scenario_builder(request, scenario_id):
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
            'motivation': motivation
        })

    except ScenarioBuilder.DoesNotExist:
        return JsonResponse({'error': 'Scenario not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


logger = logging.getLogger(__name__)


def get_facilities_by_zip(zip_code):
    url = f"https://ofmpub.epa.gov/frs_public2/frs_rest_services.get_facilities?zip_code={zip_code}&output=JSON"
    try:
        response = requests.get(url, verify=False, timeout=20)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error("HTTP Error %s: %s", response.status_code, response.reason)
            return None
    except requests.RequestException as e:
        logger.error("Request error: %s", e)
        return None
    except ValueError as e:
        logger.error("JSON decoding error: %s", e)
        return None


def facilities(request):
    zip_code = request.GET.get('zip')
    if zip_code:
        facilities = get_facilities_by_zip(zip_code)
        if facilities:
            return JsonResponse({'facilities': facilities}, safe=False)
        else:
            return JsonResponse({'error': 'No facilities found or error in API call'}, status=500)
    else:
        return JsonResponse({'error': 'No ZIP code provided'}, status=400)


def get_coordinates_from_address(address, country, google_maps_api_key):
    geocode_url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address},+{country}&key={google_maps_api_key}"
    response = requests.get(geocode_url)
    data = response.json()
    if data['status'] == 'OK':
        latitude = data['results'][0]['geometry']['location']['lat']
        longitude = data['results'][0]['geometry']['location']['lng']
        return latitude, longitude
    else:
        return None, None


def air_quality_index(request):
    latitude = request.GET.get('lat')
    longitude = request.GET.get('lon')
    address = request.GET.get('address')
    country = request.GET.get('country')

    aqicn_api_key = get_api_key("aqicn")  # Replace with your actual AQICN API key

    # If latitude and longitude are not provided, use address and country to get them
    if not latitude or not longitude:
        if address and country:
            latitude, longitude = get_coordinates_from_address(address, country,
                                                               "AIzaSyC9z71m0_5oIR2tg4ygvOt61jCL-IgxlBI")
            if not latitude or not longitude:
                return JsonResponse({'error': 'Failed to geocode address'}, status=400)

    url = f"https://api.waqi.info/feed/geo:{latitude};{longitude}/?token={aqicn_api_key}"

    try:
        response = requests.get(url)
        data = response.json()
        aqi = data.get('data', {}).get('aqi')
        return JsonResponse({'aqi': aqi})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def facility_risk_profile_newrecord(userid, industry, facility_type, address, country, facility, employees,
                                    shift_model, assessment_id, sl):
    language = 'en'

    if not industry or not facility_type:
        error_msg = "Missing industry or facility type. Complete all fields to get an accurate assessment"
        return JsonResponse({
            'safety_summary': error_msg,
            'chemical_summary': error_msg,
            'physical_security_summary': error_msg,
            'other_summary': error_msg
        })

    openai_api_key = get_api_key('openai')
    openai_model = get_api_key('OpenAI_Model')
    # openai_api_key = os.environ.get('OPENAI_API_KEY')
    openai.api_key = openai_api_key
    context = f"You are an industrial safety and hazard expert. For the {facility} {facility_type} at {address}, {country} in the {industry} industry, with {employees} employees working a {shift_model} shift model,"

    prompts = [
        f"{context} List safety hazards, max 100 words. - Specific to facility - mechanical or chemical or electrical or heat or cold or crush or height - Space between bullets. \n\nExample Format:\n 1. Specific safety hazard.\n 2. Another specific safety hazard.",
        f"{context} List expected chemicals, max 100 words. - Specific to facility - Chemical names only - raw materials and by-products and stored chemicals - Space between bullets. \n\nExample Format:\n 1. Chemical name (raw material or by-product).\n- 2. Another chemical name (raw material or by-product).",
        f"{context}, List physical security requirements for the given facility and location - access control - surveillance - consideration of local crime statistics - blind spots - proximity to other infrastructure . Max of 100 words .\n\nExample Format:\n 1. Physical security challenge.\n 2. Another physical security challenge.",
        f"{context}, list of specialized OT and IoT devices and equipment expected to be at the facility. Max of 150 words .\n\nExample Format:\n 1. OT or IoT device (purpose of device).\n 2. Another OT or IoT device (purpose of device).",
        f"{context}, list of national and international regulatory compliance containing cybersecurity requirements relevant to the {industry} industry that applies to {facility_type} facilities in {country} . Includes laws and standards. Max of 150 words .\n\nExample Format:\n 1. Compliance name (name of issuing authority).\n 2. Another compliance name (name of issuing authority).",
        f"{context}: You are a safety inspector. For a {facility_type} in {country}, estimate a detailed and nuanced safety and hazard risk score. Use a scale from 0 to 100, where 0 indicates an absence of safety hazards and 100 signifies the presence of extreme and imminent fatal hazards. Provide a score reflecting the unique risk factors associated with the facility type and its operational context in {country}. Scores should reflect increments of 10, with each decile corresponding to escalating levels of hazard severity and likelihood of occurrence given the expected attention to safety at the facility. Base your score on a typical {facility_type} in {country}, adhering to expected standard safety protocols, equipment conditions, and operational practices. Provide the score as a single, precise number without additional commentary."
    ]

    responses = []

    # Loop through the prompts and make an API call for each one
    def fetch_response(prompt):
        return openai.ChatCompletion.create(
            # model="gpt-4",
            model=openai_model,
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
    threatSummary, insightSummary, strategySummary = facility_threat_profile(sl, facility, facility_type, country,
                                                                             industry, safety_summary,
                                                                             chemical_summary,
                                                                             physical_security_summary,
                                                                             other_summary,
                                                                             compliance_summary,
                                                                             "")

    return {
        'safety_summary': safety_summary,
        'chemical_summary': chemical_summary,
        'physical_security_summary': physical_security_summary,
        'other_summary': other_summary,
        'compliance_summary': compliance_summary,
        'pha_score': pha_score,
        'threatSummary': threatSummary,
        'insightSummary': insightSummary,
        'strategySummary': strategySummary
    }


@csrf_exempt
def delete_pha_record(request):
    if request.method == 'POST':
        record_id = request.POST.get('id')
        try:
            pha_record = tblCyberPHAHeader.objects.get(ID=record_id)
            pha_record.Deleted = 1
            pha_record.save()

            return JsonResponse({'deleted': True})
        except tblCyberPHAHeader.DoesNotExist:
            return JsonResponse({'deleted': False})
    return JsonResponse({'deleted': False})
