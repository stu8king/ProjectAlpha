from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy, reverse
from django.db import connection
from django.views import View, generic
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DeleteView
from django.views.generic.edit import CreateView
from OTRisk.models.RiskScenario import RiskScenario, tblScenarioRecommendations
from OTRisk.models.Model_Scenario import tblConsequence
from OTRisk.models.sitewalkdown import SiteWalkdown
from OTRisk.models.sitewalkdown import SiteWalkdownQuestionnaire, WalkdownAnswers
from OTRisk.models.questionnairemodel import Questionnaire, tblFacility, FacilityType
from OTRisk.models.post import Post, AssessmentTeam
from OTRisk.models.ThreatAssessment import ThreatAssessment
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions
from django.db.models import F, Count, Avg
from django import forms
from .forms import RiskScenarioForm, PostForm, AssessmentTeamForm
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.core import serializers
from OTRisk.models.Model_Workshop import tblWorkshopNarrative, tblWorkshopInformation
from OTRisk.models.Model_CyberPHA import tblCyberPHAEntry, tblCyberPHAHeader, tblRiskCategories, tblCyberPHATeam, \
    tblControlObjectives, \
    tblThreatIntelligence, tblMitigationMeasures, tblScenarios, tblSafeguards, tblThreatSources, tblThreatActions, \
    tblNodes, tblUnits, tblZones, tblCyberPHAScenario, tblIndustry, auditlog, tblStandards
from OTRisk.models.Model_Mitre import MitreICSTactics
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from .forms import LoginForm
from datetime import date, datetime
import json
import requests
from xml.etree import ElementTree as ET
from bs4 import BeautifulSoup
from .raw_views import qraw, openai_assess_risk, GetTechniquesView, raw_action, check_vulnerabilities, rawreport, \
    raw_from_walkdown, save_ra_action, get_rawactions, ra_actions_view
from .dashboard_views import dashboardhome
from .pha_views import iotaphamanager, facility_risk_profile, get_headerrecord, scenario_analysis, phascenarioreport, \
    getSingleScenario

import uuid

app_name = 'OTRisk'


def get_consequences(request):
    consequences = tblConsequence.objects.all()
    data = [{'id': c.id, 'Consequence': c.Consequence} for c in consequences]
    return JsonResponse({'consequences': data})


def scenarioreport(request):
    cyberphaid = request.GET.get('hdnID', 0)

    scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberphaid, Deleted=0)
    scenarioheader = tblCyberPHAHeader.objects.get(ID=cyberphaid)
    avg_impactsafety = scenarios.aggregate(Avg('impactSafety'))['impactSafety__avg']
    avg_impactDanger = scenarios.aggregate(Avg('impactDanger'))['impactDanger__avg']
    avg_impactProduction = scenarios.aggregate(Avg('impactProduction'))['impactProduction__avg']
    avg_impactFinance = scenarios.aggregate(Avg('impactFinance'))['impactFinance__avg']
    avg_impactReputation = scenarios.aggregate(Avg('impactReputation'))['impactReputation__avg']
    avg_impactEnvironment = scenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg']
    avg_impactRegulation = scenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg']
    avg_impactData = scenarios.aggregate(Avg('impactData'))['impactData__avg']
    avg_uel = scenarios.aggregate(Avg('UEL'))['UEL__avg']
    avg_rru = scenarios.aggregate(Avg('RRU'))['RRU__avg']
    avg_sm = scenarios.aggregate(Avg('SM'))['SM__avg']
    avg_mel = scenarios.aggregate(Avg('MEL'))['MEL__avg']
    avg_rrm = scenarios.aggregate(Avg('RRM'))['RRM__avg']
    avg_sa = scenarios.aggregate(Avg('SA'))['SA__avg']
    avg_MELa = scenarios.aggregate(Avg('MELA'))['MELA__avg']
    avg_rra = scenarios.aggregate(Avg('RRa'))['RRa__avg']

    return render(request, 'scenarioreport.html', {
        'scenarios': scenarios,
        'scenarioheader': scenarioheader,
        'avg_impactsafety': avg_impactsafety,
        'avg_impactDanger': avg_impactDanger,
        'avg_impactProduction': avg_impactProduction,
        'avg_impactFinance': avg_impactFinance,
        'avg_impactReputation': avg_impactReputation,
        'avg_impactEnvironment': avg_impactEnvironment,
        'avg_impactRegulation': avg_impactRegulation,
        'avg_impactData': avg_impactData,
        'avg_uel': avg_uel,
        'avg_sm': avg_sm,
        'avg_rru': avg_rru,
        'avg_mel': avg_mel,
        'avg_rrm': avg_rrm,
        'avg_sa': avg_sa,
        'avg_MELa': avg_MELa,
        'avg_rra': avg_rra
    })


def save_or_update_cyberpha(request):
    print(f"{request.POST}")
    if request.method == 'POST':
        # Get the form data
        cyberphaid = request.POST.get('cyberpha')
        scenario = request.POST.get('scenario')
        threatclass = request.POST.get('threatSource')
        threataction = request.POST.get('threatAction')
        countermeasures = request.POST.get('mitigationMeasures')
        riskcategory = request.POST.get('riskCategory')
        consequence = request.POST.get('consequence')
        impactsafety = request.POST.get('safety')
        impactdanger = request.POST.get('life')
        impactproduction = request.POST.get('production')
        impactfinance = request.POST.get('financial')
        impactreputation = request.POST.get('reputation')
        impactenvironment = request.POST.get('environment')
        impactregulation = request.POST.get('regulatory')
        impactdata = request.POST.get('data')
        sm = request.POST.get('sm')
        mel = request.POST.get('mel')
        rrm = request.POST.get('rrm')
        sa = request.POST.get('sa')
        mela = request.POST.get('mela')
        rra = request.POST.get('rra')
        recommendations = request.POST.get('recommendations')
        controlrecs = request.POST.get('controls')
        justifySafety = request.POST.get('justifySafety')
        justifyLife = request.POST.get('justifyLife')
        justifyProduction = request.POST.get('justifyProduction')
        justifyFinance = request.POST.get('justifyFinance')
        justifyReputation = request.POST.get('justifyReputation')
        justifyEnvironment = request.POST.get('justifyEnvironment')
        justifyRegulation = request.POST.get('justifyRegulation')
        justifyData = request.POST.get('dataRegulation')
        sle_string = request.POST.get('sle')
        sle = int(sle_string.replace('$', '').replace(',', ''))
        deleted = 0

        cyberpha_entry, created = tblCyberPHAScenario.objects.update_or_create(
            CyberPHA=cyberphaid,
            Scenario=scenario,
            ThreatClass=threatclass,
            defaults={
                'ThreatAction': threataction,
                'Countermeasures': countermeasures,
                'RiskCategory': riskcategory,
                'Consequence': consequence,
                'impactSafety': impactsafety,
                'impactDanger': impactdanger,
                'impactProduction': impactproduction,
                'impactFinance': impactfinance,
                'impactReputation': impactreputation,
                'impactEnvironment': impactenvironment,
                'impactRegulation': impactregulation,
                'impactData': impactdata,
                'recommendations': recommendations,
                'SM': sm,
                'MEL': mel,
                'RRM': rrm,
                'SA': sa,
                'MELA': mela,
                'RRa': rra,
                'Deleted': deleted,
                'control_recommendations': controlrecs,
                'justifySafety': justifySafety,
                'justifyLife': justifyLife,
                'justifyProduction': justifyProduction,
                'justifyFinancial': justifyFinance,
                'justifyReputation': justifyReputation,
                'justifyEnvironment': justifyEnvironment,
                'justifyRegulation': justifyRegulation,
                'justifyData': justifyData,
                'userID': request.user,
                'sle': sle
            }
        )

        scenarioID = cyberpha_entry.pk
        request.session['cyberPHAID'] = cyberphaid  # Set the session variable

        # Call the assess_cyberpha function
        return assess_cyberpha(request)


def set_active_cyberpha(request):
    active_cyberpha = request.POST.get('active_cyberpha')
    request.session['active_cyberpha'] = active_cyberpha
    request.session.save()
    return JsonResponse({'status': 'success'})


def update_session(request):
    active_cyberpha = request.POST.get('active_cyberpha')
    request.session['active-cyberpha'] = active_cyberpha
    return JsonResponse({'status': 'success'})


def get_mitigation_measures(request):
    mitigation_measures = tblMitigationMeasures.objects.values_list('ControlObjective', flat=True)
    return JsonResponse(list(mitigation_measures), safe=False)


def edit_cyberpha(request, cyberpha_id):
    # Retrieve the existing CyberPHA assessment from the database based on the provided ID
    cyberpha = tblCyberPHA.objects.get(id=cyberpha_id)

    if request.method == 'POST':
        # Update the CyberPHA assessment based on the form submission
        # Retrieve the form data and save it to the database
        # Perform necessary validations and error handling

        return redirect('assessment_success')

    return render(request, 'edit_cyberpha.html', {'cyberpha': cyberpha})


def assess_cyberpha(request):
    active_cyberpha = request.GET.get('active_cyberpha', None)
    if active_cyberpha is None:
        active_cyberpha = request.session.get('cyberPHAID', 0)
    scenarios = tblScenarios.objects.all()
    control_objectives = tblControlObjectives.objects.all()
    mitigation_measures = tblMitigationMeasures.objects.all()
    threat_intelligence = tblThreatIntelligence.objects.all().order_by('ThreatDescription')
    risk_categories = tblRiskCategories.objects.all().order_by('CategoryName')
    safeguards = tblSafeguards.objects.order_by('Safeguard').values('Safeguard').distinct()
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    threatactions = tblThreatActions.objects.all().order_by('ThreatAction')
    consequenceList = tblConsequence.objects.all().order_by('Consequence')
    standardslist = tblStandards.objects.all().order_by('standard')

    control_objectives = [json.loads(obj.ControlObjective) for obj in control_objectives]
    active_cyberpha_id = request.GET.get('active_cyberpha')
    description = ''
    print(f"{active_cyberpha_id}")
    if active_cyberpha_id is not None:
        try:
            # Retrieve the Description value from the database based on the active-cyberpha_id
            description = tblCyberPHAHeader.objects.get(ID=active_cyberpha_id).Description
        except tblCyberPHAHeader.DoesNotExist:
            pass

    if request.method == 'POST':
        # Process form submission and save data to the database
        assessment_name = request.POST.get('assessment_name')
        scenarios_data = request.POST.getlist('scenarios[]')

        # Save the data to the database according to your requirements

        # return redirect('assessment_success')

    response = JsonResponse({'message': 'Success'})
    response['Access-Control-Allow-Origin'] = '*'  # Set the CORS header

    clicked_row_facility_name = request.session.get('clickedRowFacilityName', None)
    saved_scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=active_cyberpha, Deleted=0)

    return render(request, 'assess_cyberpha.html', {
        'scenarios': scenarios,
        'control_objectives': control_objectives,
        'mitigation_measures': mitigation_measures,
        'threat_intelligence': threat_intelligence,
        'risk_categories': risk_categories,
        'description': description,
        'safeguards': safeguards,
        'threatsources': threatsources,
        'threatactions': threatactions,
        'clicked_row_facility_name': clicked_row_facility_name,
        'saved_scenarios': saved_scenarios,
        'consequenceList': consequenceList,
        'standardslist': standardslist
    })


def add_team_member(request):
    if request.method == 'POST':
        cyber_pha_id = request.POST.get('cyberPHAID')
        name = request.POST.get('name')
        company = request.POST.get('company')
        title = request.POST.get('title')
        expertise = request.POST.get('expertise')
        experience = request.POST.get('experience')
        comments = request.POST.get('comments')

        # Save the new team member record to tblCyberPHATeam
        team_member = tblCyberPHATeam(
            CyberPHAID_id=cyber_pha_id,
            Name=name,
            Company=company,
            Title=title,
            Expertise=expertise,
            Experience=experience,
            Comments=comments
        )
        team_member.save()

        # Retrieve the related team members
        team_members = tblCyberPHATeam.objects.filter(CyberPHAID=cyber_pha_id)

        # Render the team members table
        rendered_team_members = render_to_string('team_members_table.html', {'team_members': team_members})

        return JsonResponse({'team_members': rendered_team_members})

    return redirect('cyber_pha_manager')


@login_required
def cyber_pha_manager(request):
    tblCyberPHAList = tblCyberPHAHeader.objects.filter(Deleted=0).order_by('ID')[::-1]
    facilityTypes = FacilityType.objects.all().order_by('FacilityType')
    nodes = tblNodes.objects.all().order_by('NodeType')
    units = tblUnits.objects.all().order_by('PlantUnits')
    zones = tblZones.objects.all().order_by('PlantZone')
    industry = tblIndustry.objects.all().order_by('Industry')

    team_members = tblCyberPHATeam.objects.none()  # Empty queryset for initial rendering
    active_cyberpha = request.session.get('active-cyberpha', 0)  # Retrieve the active-cyberpha from session

    if active_cyberpha:
        team_members = tblCyberPHATeam.objects.filter(CyberPHAID=active_cyberpha)

    return render(request, 'CyberPHAManager.html', {'tblCyberPHAList': tblCyberPHAList,
                                                    'team_members': team_members,
                                                    'facilityTypes': facilityTypes,
                                                    'nodes': nodes,
                                                    'units': units,
                                                    'zones': zones,
                                                    'industry': industry})


def get_team_members(request):
    if request.method == 'GET':
        cyber_pha_id = request.GET.get('cyberPHAID')
        team_members = tblCyberPHATeam.objects.filter(CyberPHAID=cyber_pha_id)
        return render(request, 'team_members_table.html', {'team_members': team_members})


def PHAeditmode(request, id):
    print("editmode")
    record = tblCyberPHAHeader.objects.get(ID=id)
    formattedStartDate = record.AssessmentStartDate.strftime('%Y-%m-%d')
    print(f"{formattedStartDate}")
    formattedEndDate = record.AssessmentEndDate.strftime('%Y-%m-%d')
    print(f"{formattedEndDate}")
    data = {
        'PHALeader': record.PHALeader,
        'PHALeaderEmail': record.PHALeaderEmail,
        'FacilityOwner': record.FacilityOwner,
        'Notes': record.Notes,
        'FacilityName': record.FacilityName,
        'AssessmentUnit': record.AssessmentUnit,
        'AssessmentNode': record.AssessmentNode,
        'AssessmentZone': record.AssessmentZone,
        'FacilityType': record.FacilityType,
        'Industry': record.Industry,
        'EmployeesOnSite': record.EmployeesOnSite,
        'AssessmentStartDate': formattedStartDate,
        'AssessmentEndDate': formattedEndDate,
        'facilityAddress': record.facilityAddress,
    }
    print(f"{record.FacilityType}")
    return JsonResponse(data)


def deletecyberpha(request, cyberpha_id):
    # does a virtual delete
    cyber_pha = tblCyberPHAHeader.objects.get(ID=cyberpha_id)
    cyber_pha.Deleted = 1
    cyber_pha.save()
    return redirect('OTRisk:cyber_pha_manager')


def deletescenario(request, scenarioid, cyberPHAID):
    scenario_to_del = tblCyberPHAScenario.objects.get(ID=scenarioid)
    scenario_to_del.Deleted = 1
    scenario_to_del.save()
    saved_scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyberPHAID, Deleted=0)

    return render(request, 'assess_cyberPHA.html', {
        'scenarios': tblScenarios.objects.all(),
        'control_objectives': tblControlObjectives.objects.all(),
        'mitigation_measures': tblMitigationMeasures.objects.all().order_by('ControlObjective'),
        'threat_intelligence': tblThreatIntelligence.objects.all().order_by('ThreatDescription'),
        'threatsources': tblThreatSources.objects.all().order_by('ThreatSource'),
        'threataction': tblThreatActions.objects.all().order_by('ThreatAction'),
        'risk_categories': tblRiskCategories.objects.all(),
        'saved_scenarios': saved_scenarios
    })
    # return redirect('OTRisk:assess_cyberpha')


def save_cyberpha(request):
    if request.method == 'POST':
        recordid = request.POST.get('recordId')
        facility_type = request.POST.get('facilityType')
        facility_name = request.POST.get('plantName')
        phaleader = request.POST.get('leader')
        leader_email = request.POST.get('email')
        facility_owner = request.POST.get('facilityLeader')
        facility_scope = request.POST.get('facilityScope')
        notes = request.POST.get('txtComment')
        assessment_unit = request.POST.get('unit')
        assessment_zone = request.POST.get('zone')
        assessment_node = request.POST.get('node')
        emps = request.POST.get('siteemps')
        startDate = request.POST.get('txtstartdate')
        enddate = request.POST.get('txtenddate')
        userid = request.user
        Industry = request.POST.get('industry')
        facilityAddress = request.POST.get('txtfacilityAddress')

        if recordid and int(recordid) > 0:
            # recordId is present and greater than 0. Update existing record.
            tblCyberPHAHeader.objects.filter(ID=recordid).update(
                FacilityName=facility_name,
                PHALeader=phaleader,
                PHALeaderEmail=leader_email,
                FacilityOwner=facility_owner,
                FacilityScope=facility_scope,
                Notes=notes,
                AssessmentUnit=assessment_unit,
                AssessmentNode=assessment_node,
                AssessmentZone=assessment_zone,
                FacilityType=facility_type,
                Industry=Industry,
                EmployeesOnSite=emps,
                AssessmentStartDate=startDate,
                AssessmentEndDate=enddate,
                UserID=userid,
                AssessmentStatus="Open",
                facilityAddress=facilityAddress,
                Deleted=0
            )
            request.session['active-cyberpha'] = recordid
        else:
            # No valid recordId. Create new record.
            new_cyber_pha = tblCyberPHAHeader(
                FacilityName=facility_name,
                PHALeader=phaleader,
                PHALeaderEmail=leader_email,
                FacilityOwner=facility_owner,
                FacilityScope=facility_scope,
                Notes=notes,
                AssessmentUnit=assessment_unit,
                AssessmentNode=assessment_node,
                AssessmentZone=assessment_zone,
                FacilityType=facility_type,
                Industry=Industry,
                EmployeesOnSite=emps,
                AssessmentStartDate=startDate,
                AssessmentEndDate=enddate,
                UserID=userid,
                AssessmentStatus="Open",
                facilityAddress=facilityAddress,
                Deleted=0
            )
            new_cyber_pha.save()
            request.session['active-cyberpha'] = new_cyber_pha.ID

        return redirect('OTRisk:cyber_pha_manager')

    tblCyberPHAList = tblCyberPHAHeader.objects.all().order_by('ID')[::-1]
    return render(request, 'CyberPHAManager.html', {'tblCyberPHAList': tblCyberPHAList})


from django.shortcuts import get_object_or_404


def save_walkdown_questionnaire(request):
    print(f"{request.POST}")
    if request.method == 'POST':
        walkdown_id = request.POST.get('walkdownid')
        active_cyberPHA = request.POST.get('activecyberpha')

        question_ids = request.POST.get('question_ids[]', '').split(',')
        user_responses = request.POST.get('user_responses[]', '').split(',')
        questions = request.POST.get('question_texts[]', '').split(',')

        for question_id, user_response, question in zip(question_ids, user_responses, questions):
            walkdown_answers = WalkdownAnswers.objects.filter(
                WalkdownID=walkdown_id,
                WalkdownQuestionID=int(question_id)

            )

            if walkdown_answers.exists():
                # Update existing record
                walkdown_answer = walkdown_answers.first()
                walkdown_answer.walkdown_id = walkdown_id
                walkdown_answer.CyberPHA_ID = active_cyberPHA
                walkdown_answer.UserResponse = user_response
                walkdown_answer.questiontext = question
                walkdown_answer.Details = ''
                walkdown_answer.RANeeded = 0
                walkdown_answer.save()
            else:
                # Create new record
                walkdown_answer = WalkdownAnswers.objects.create(
                    WalkdownID=walkdown_id,
                    WalkdownQuestionID=int(question_id),
                    CyberPHA_ID=active_cyberPHA,
                    UserResponse=user_response,
                    questiontext=question,
                    Details='',
                    RANeeded=0
                )

        return JsonResponse({'success': True, 'walkdownID': walkdown_id})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


def update_existing_records(request):
    if request.method == 'POST':
        # Update existing records logic goes here
        walkdown_id = request.POST.get('walkdownID')
        cyberPHA_id = request.POST.get('CyberPHA_ID')

        # Get the updated data from the request and update the records accordingly
        question_ids = request.POST.getlist('question_ids[]')
        user_responses = request.POST.getlist('user_responses[]')

        for question_id, user_response in zip(question_ids, user_responses):
            walkdown_answer = WalkdownAnswers.objects.get(WalkdownID=walkdown_id, WalkdownQuestionID=question_id)
            walkdown_answer.UserResponse = user_response
            walkdown_answer.save()

        return JsonResponse({'success': True})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


def create_new_records(request):
    if request.method == 'POST':
        # Create new records logic goes here
        walkdown_id = request.POST.get('walkdownID')
        cyberPHA_id = request.POST.get('CyberPHA_ID')

        # Get the new data from the request and create new records
        question_ids = request.POST.getlist('question_ids[]')
        user_responses = request.POST.getlist('user_responses[]')

        for question_id, user_response in zip(question_ids, user_responses):
            walkdown_answer = WalkdownAnswers(
                WalkdownID=walkdown_id,
                WalkdownQuestionID=question_id,
                CyberPHA_ID=cyberPHA_id,
                UserResponse=user_response,
                Details='',
                RANeeded=0
            )
            walkdown_answer.save()

        return JsonResponse({'success': True})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


def update_or_create_records(request):
    if request.method == 'POST':
        # Update or create records logic goes here
        walkdown_id = request.POST.get('walkdownID')
        cyberPHA_id = request.POST.get('CyberPHA_ID')

        # Get the data from the request and update or create records accordingly
        question_ids = request.POST.getlist('question_ids[]')
        user_responses = request.POST.getlist('user_responses[]')

        for question_id, user_response in zip(question_ids, user_responses):
            existing_records = WalkdownAnswers.objects.filter(WalkdownID=walkdown_id, WalkdownQuestionID=question_id)
            if existing_records.exists():
                walkdown_answer = existing_records.first()
                walkdown_answer.UserResponse = user_response
                walkdown_answer.save()
            else:
                walkdown_answer = WalkdownAnswers(
                    WalkdownID=walkdown_id,
                    WalkdownQuestionID=question_id,
                    CyberPHA_ID=cyberPHA_id,
                    UserResponse=user_response,
                    Details='',
                    RANeeded=0
                )
                walkdown_answer.save()

        return JsonResponse({'success': True})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


def getFacilityTypes(request):
    facility_types = FacilityType.objects.order_by('FacilityTypes')
    return render(request, 'walkdown.html', {'facility_types': facility_types})


def walkdown(request):
    FacilityNames = tblCyberPHAHeader.objects.values_list('FacilityName', flat=True).distinct().order_by('FacilityName')
    walkdown_list = SiteWalkdown.objects.all()
    question_categories = set(question.Category for question in SiteWalkdownQuestionnaire.objects.all())
    walkdown_questions = SiteWalkdownQuestionnaire.objects.all()
    facility_types = FacilityType.objects.order_by('FacilityType')

    walkdown_session = request.session.get('session_walkdown')
    walkdown_facility = request.session.get('walkdown_facility')
    walkdown_facilityType = request.session.get('walkdown_facilityType')
    walkdown_people = request.session.get('walkdown_people')
    walkdown_leader = request.session.get('walkdown_leader')
    walkdown_contact = request.session.get('walkdown_contact')
    walkdown_start = request.session.get('walkdown_start')
    walkdown_end = request.session.get('walkdown_end')
    walkdown_zones = request.session.get('walkdown_zones')
    walkdown_safetybrief = request.session.get('walkdown_safetybrief')

    return render(request, 'walkdown.html', {
        'walkdown_list': walkdown_list,
        'question_categories': question_categories,
        'walkdown_questions': walkdown_questions,
        'facility_types': facility_types,
        'FacilityNames': FacilityNames,
        'walkdown_facility': walkdown_facility,
        'walkdown_facilityType': walkdown_facilityType,
        'walkdown_people': walkdown_people,
        'walkdown_leader': walkdown_leader,
        'walkdown_contact': walkdown_contact,
        'walkdown_start': walkdown_start,
        'walkdown_end': walkdown_end,
        'walkdown_zones': walkdown_zones,
        'walkdown_safetybrief': walkdown_safetybrief,
        'walkdown_session': walkdown_session
    })


def get_walkdown_data(request, row_id):
    walkdown = SiteWalkdown.objects.get(ID=row_id)
    data = {
        'WalkdownDate': walkdown.WalkdownDate,
        'OrganizationName': walkdown.OrganizationName,
        'LocationAddress': walkdown.LocationAddress,
        'LocationCountry': walkdown.LocationCountry,
        'LocationType': walkdown.LocationType,
        'PeopleOnSite': walkdown.PeopleOnSite,
        'WalkdownLeader': walkdown.WalkdownLeader,
        'OrgContact': walkdown.OrgContact,
        'WalkdownStartTime': walkdown.WalkdownStartTime,
        'WalkdownEndTime': walkdown.WalkdownEndTime,
        'DisallowedZones': walkdown.DisallowedZones,
        'SafetyBriefingGiven': walkdown.SafetyBriefingGiven,
    }
    request.session['session_walkdown'] = row_id  # Update session variable
    return JsonResponse(data)


def save_walkdown(request):
    print(f"{request.POST}")
    if request.method == 'POST':
        data = request.POST

        walkdown = SiteWalkdown()
        walkdown.WalkdownDate = data['WalkdownDate']
        # Check if the value of data('OrganizationName') is "Other"
        if data.get('OrganizationName') == 'Other':
            # Save the value of data('OtherOrganization') to walkdown.OrganizationName
            walkdown.OrganizationName = data.get('OtherOrganization', '')
        else:
            # Save the value of data('OrganizationName') to walkdown.OrganizationName
            walkdown.OrganizationName = data.get('OrganizationName')

        walkdown.LocationAddress = data['LocationAddress']
        request.session['walkdown_address'] = walkdown.LocationAddress
        # walkdown.LocationCountry = data['LocationCountry']
        if data.get('LocationType') == 'Other':
            walkdown.LocationType = data['LocationType']
        else:
            walkdown.LocationType = data.get('OtherFacilityType', [''])[0]

        walkdown.PeopleOnSite = data['PeopleOnSite']

        walkdown.WalkdownLeader = data['WalkdownLeader']

        walkdown.OrgContact = data['OrgContact']

        walkdown.WalkdownStartTime = data['WalkdownStartTime']

        walkdown.WalkdownEndTime = data['WalkdownEndTime']

        walkdown.DisallowedZone = data['DisallowedZone']

        walkdown.SafetyBriefingGiven = data['SafetyBriefingGiven']

        walkdown.save()

        request.session['session_walkdown'] = walkdown.pk  # Set session variable
        request.session['walkdown_facility'] = walkdown.OrganizationName
        request.session['walkdown_facilityType'] = walkdown.LocationType
        request.session['walkdown_people'] = walkdown.PeopleOnSite
        request.session['walkdown_leader'] = walkdown.WalkdownLeader
        request.session['walkdown_contact'] = walkdown.OrgContact
        request.session['walkdown_start'] = walkdown.WalkdownStartTime
        request.session['walkdown_end'] = walkdown.WalkdownEndTime
        request.session['walkdown_zones'] = walkdown.DisallowedZone
        request.session['walkdown_safetybrief'] = walkdown.SafetyBriefingGiven

    return redirect('OTRisk:walkdown')


def create_walkdown_risk_assessment(request):
    if request.method == 'POST':
        walkdown_id = request.POST.get('walkdownId')
        question_id = request.POST.get('questionId')
        yes_no_option = request.POST.get('yesNoOption')
        details_input = request.POST.get('detailsInput')
        orgName = request.POST.get('organizationName')

        walkdown_answers = WalkdownAnswers()
        walkdown_answers.WalkdownID = walkdown_id
        walkdown_answers.WalkdownQuestionID = question_id
        walkdown_answers.YesNo = yes_no_option
        walkdown_answers.Details = details_input
        walkdown_answers.RANeeded = 1  # Set as needed
        walkdown_answers.save()

        # Create a new record in tblRAWorksheet
        walkdown_question = SiteWalkdownQuestionnaire.objects.get(ID=question_id)
        ra_worksheet = RAWorksheet()
        ra_worksheet.RATitle = 'Walkdown of ' + orgName
        ra_worksheet.RADescription = 'Risk assessment for question ' + walkdown_question.WalkdownQuestion
        ra_worksheet.RADate = str(date.today())
        ra_worksheet.StatusFlag = 'Pending'
        ra_worksheet.RATrigger = 'Site Visit/Walkdown'
        ra_worksheet.save()

    return JsonResponse({'success': True})


def home(request):
    ra_worksheets = RAWorksheet.objects.all()
    worksheet_data = []

    for worksheet in ra_worksheets:
        scenario_scores = RAWorksheetScenario.objects.filter(RAWorksheetID=worksheet.ID)

        threat_scores = [scenario.ThreatScore for scenario in scenario_scores if scenario.ThreatScore is not None]
        risk_scores = [scenario.RiskScore for scenario in scenario_scores if scenario.RiskScore is not None]
        vuln_scores = [scenario.VulnScore for scenario in scenario_scores if scenario.VulnScore is not None]
        reputation_scores = [scenario.ReputationScore for scenario in scenario_scores if
                             scenario.ReputationScore is not None]
        operation_scores = [scenario.OperationScore for scenario in scenario_scores if
                            scenario.OperationScore is not None]
        financial_scores = [scenario.FinancialScore for scenario in scenario_scores if
                            scenario.FinancialScore is not None]
        safety_scores = [scenario.SafetyScore for scenario in scenario_scores if scenario.SafetyScore is not None]
        data_scores = [scenario.DataScore for scenario in scenario_scores if scenario.DataScore is not None]

        avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        avg_vuln_score = sum(vuln_scores) / len(vuln_scores) if vuln_scores else 0
        avg_reputation_score = sum(reputation_scores) / len(reputation_scores) if reputation_scores else 0
        avg_operation_score = sum(operation_scores) / len(operation_scores) if operation_scores else 0
        avg_financial_score = sum(financial_scores) / len(financial_scores) if financial_scores else 0
        avg_safety_score = sum(safety_scores) / len(safety_scores) if safety_scores else 0
        avg_data_score = sum(data_scores) / len(data_scores) if data_scores else 0

        worksheet_data.append({
            'id': worksheet.ID,
            'status_flag': worksheet.StatusFlag,
            'ra_date': worksheet.RADate,
            'ra_trigger': worksheet.RATrigger,
            'business_unit': worksheet.BusinessUnit,
            'avg_threat_score': avg_threat_score,
            'avg_risk_score': avg_risk_score,
            'avg_vuln_score': avg_vuln_score,
            'avg_reputation_score': avg_reputation_score,
            'avg_operation_score': avg_operation_score,
            'avg_financial_score': avg_financial_score,
            'avg_safety_score': avg_safety_score,
            'avg_data_score': avg_data_score
        })

    # latest ICS vulnerabilities
    url = 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml'
    response = requests.get(url)
    root = ET.fromstring(response.text)
    items = []
    for item in root.findall('.//item'):
        title = item.find('title').text
        link = item.find('link').text
        description_html = item.find('description').text

        soup = BeautifulSoup(description_html, 'html.parser')
        vulnerability_overview = soup.find('h3', text='3.2 VULNERABILITY OVERVIEW')
        description = ''
        if vulnerability_overview:
            for sibling in vulnerability_overview.find_next_siblings():
                if sibling.name == 'h3':
                    break
                description += str(sibling)

        items.append({'title': title, 'link': link, 'description': description})

        # Fetch and parse Threatpost feed
    threatpost_url = 'https://threatpost.com/feed/'
    threatpost_response = requests.get(threatpost_url)

    threatpost_root = ET.fromstring(threatpost_response.text)
    threatpost_items = []
    for item in threatpost_root.findall('.//item'):
        title = item.find('title').text
        link = item.find('link').text
        description = item.find('description').text
        threatpost_items.append({'title': title, 'link': link, 'description': description})

    # UK NCSC feed
    ncsc_url = 'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml'
    ncsc_response = requests.get(ncsc_url)
    ncsc_root = ET.fromstring(ncsc_response.text)
    ncsc_items = []
    for item in ncsc_root.findall('.//item'):
        title = item.find('title').text
        link = item.find('link').text
        description = item.find('description').text
        ncsc_items.append({'title': title, 'link': link, 'description': description})

    # incident feed
    isssource_url = 'https://www.isssource.com/archive/'
    iss_response = requests.get(isssource_url)
    soup = BeautifulSoup(iss_response.text, 'html.parser')
    iss_items = []

    for div in soup.find_all('div', class_='et_pb_text_inner'):
        title_element = div.find('h2', class_='search-title')
        if title_element is not None:
            title = title_element.text
            link = title_element.find('a')['href']
            post_meta = div.find('div', class_='post-meta')
            if post_meta is not None:
                date = post_meta.contents[0].strip()
                iss_items.append({'title': title, 'date': date, 'link': link})
    for item in iss_items:
        print(item)

    context = {'worksheet_data': worksheet_data, 'items': items, 'threatpost_items': threatpost_items,
               'ncsc_items': ncsc_items, 'iss_items': iss_items}
    return render(request, 'home.html', context)


def fill_raw_from_table(request, id):
    try:
        worksheet = RAWorksheet.objects.get(ID=id)
        data = {
            'RATitle': worksheet.RATitle,
            'RADescription': worksheet.RADescription,
            'RADate': worksheet.RADate,
            'RASynopsis': worksheet.RASynopsis,
            'BusinessUnit': worksheet.BusinessUnit,
            'EmployeeCount': worksheet.EmployeeCount,
            'BusinessUnitType': worksheet.BusinessUnitType,
            'RegulatoryOversight': worksheet.RegulatoryOversight,
            'RATrigger': worksheet.RATrigger,
            'StatusFlag': worksheet.StatusFlag,
        }
        request.session['raworksheetid'] = id
        return JsonResponse(data)
    except RAWorksheet.DoesNotExist:
        return JsonResponse({'error': 'RAWorksheet not found'})


def set_session_variable(request, name, value):
    request.session[name] = value
    return JsonResponse({'success': f'Session variable {name} set'})


def get_actions(request):
    actions = RAActions.objects.filter(RAWorksheetID=request.session['raworksheetid']).values(
        'ID', 'actionTitle', 'actionOwner', 'actionEffort', 'actionCost'
    )
    actions_list = list(actions)

    return JsonResponse(actions_list, safe=False)


# saves a new action item on riskassess.html
def save_raw_actions(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        new_action = RAActions(
            RAWorksheetID=request.session['raworksheetid'],
            actionTitle=data.get('actionTitle', ''),
            actionDescription=data.get('actionDescription', ''),
            actionOwner=data.get('actionOwner', ''),
            actionDate=data.get('actionTargetDate', ''),
            actionEffort=data.get('actionEffort', ''),
            actionCost=data.get('actionCost', ''),
        )
        new_action.save()
        request.session['CurrentAction'] = new_action.ID
        return JsonResponse({"action_id": new_action.ID}, status=201)
    else:
        return JsonResponse({"error": "Invalid method"}, status=400)


def get_scenarios(request):
    raw_id = request.GET.get('raw_id', None)
    scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=raw_id)
    scenarios_json = serializers.serialize('json', scenarios)
    return JsonResponse(json.loads(scenarios_json), safe=False)


# saves a new scenario on riskassess.html
def save_raw_scenario(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        new_scenario = RAWorksheetScenario(
            RAWorksheetID=request.session['raworksheetid'],
            ScenarioDescription=data.get('scenario1', ''),
            ScenarioType=data.get('scenarioType', ''),
            ThreatScore=int(data.get('threatscore', '')),
            VulnScore=int(data.get('vulnerabilityscore', '')),
            ReputationScore=int(data.get('reputationscore', '')),
            OperationScore=data.get('operationalscore', ''),
            SafetyScore=int(data.get('safetyscore', '')),
            DataScore=int(data.get('datascore', '')),
            SupplyChainScore=int(data.get('supplychainscore', '')),
            RiskScore=int(data.get('riskscore', '')),
            RiskStatus=data.get('riskstatus', ''),
        )
        new_scenario.save()
        request.session['CurrentScenario'] = new_scenario.ID
        print(f"new scenarioid={new_scenario.ID}")
        return JsonResponse({"scenario_id": new_scenario.ID}, status=201)
    else:
        return JsonResponse({"error": "Invalid method"}, status=400)


@csrf_exempt
def get_ra_worksheet(request, id):
    ra_worksheet = RAWorksheet.objects.filter(ID=id).first()
    data = serializers.serialize('json', [ra_worksheet])
    return JsonResponse(data, safe=False)


def save_or_update_tblRAWorksheet(request):
    if request.method == 'POST':
        if 'addNewRA' in request.POST:
            # Clear the session variable and redirect to the same view
            request.session['raworksheetid'] = -1
            return redirect('OTRisk:save_or_update_tblRAWorksheet')

        try:
            raworksheetid = request.session.get('raworksheetid', -1)
            if raworksheetid == -1:
                # Creating a new record
                raworksheet = RAWorksheet()
            else:
                # Updating an existing record
                raworksheet = RAWorksheet.objects.get(ID=raworksheetid)

            raworksheet.RATitle = request.POST.get('title', '')
            raworksheet.RADescription = request.POST.get('description', '')
            raworksheet.RADate = request.POST.get('date', '')
            raworksheet.RASynopsis = request.POST.get('synopsis', '')
            raworksheet.UserID = 1
            raworksheet.StatusFlag = request.POST.get('StatusFlag', '')
            raworksheet.RATrigger = request.POST.get('RATrigger', '')
            raworksheet.AssessorName = ""
            raworksheet.BusinessUnit = request.POST.get('BusinessUnit', '')
            raworksheet.BusinessUnitType = request.POST.get('BusinessUnitType', '')
            raworksheet.EmployeeCount = int(request.POST.get('EmployeeCount', '0'))
            raworksheet.RegulatoryOversight = request.POST.get('RegulatoryOversight', '')
            raworksheet.save()

            # Updating session variable
            request.session['raworksheetid'] = raworksheet.ID

        except Exception as e:
            # Production ready error handling would be more specific to your application
            return HttpResponse(f"An error occurred: {str(e)}")

    raworksheetid = request.session.get('raworksheetid', -1)
    if raworksheetid != -1:
        raworksheet = RAWorksheet.objects.get(ID=raworksheetid)
    else:
        raworksheet = None
    print(f"{raworksheetid}")
    context = {'raworksheet': raworksheet, }
    return render(request, 'OTRisk/riskassess.html', context)


def risk_register_data(request):
    with connection.cursor() as cursor:
        cursor.execute('''
            SELECT
                tblRAWorksheet.ID,
                tblRAWorksheet.RATitle,
                tblRAWorksheet.RADate,
                tblRAWorksheet.BusinessUnit,
                tblRAWorksheet.StatusFlag,
                COUNT(*) AS scenario_count,
                AVG(tblRAWorksheetScenario.RiskScore) AS Risk
            FROM
                tblRAWorksheet
            LEFT JOIN
                tblRAWorksheetScenario ON tblRAWorksheetScenario.RAWorksheetID = tblRAWorksheet.ID
            GROUP BY
                tblRAWorksheet.ID, tblRAWorksheet.RATitle, tblRAWorksheet.RADate, tblRAWorksheet.StatusFlag
        ''')
        data = cursor.fetchall()

    # Format the data into a list of dictionaries
    result = []
    for row in data:
        risk = row[6]
        risk_status = "--"  # Default value

        if risk is not None and risk >= 0:
            if risk > 85:
                risk_status = "H"
            elif risk > 65:
                risk_status = "M/H"
            elif risk > 40:
                risk_status = "M"
            elif risk > 25:
                risk_status = "L/M"
            else:
                risk_status = "L"

        item = {
            'ID': row[0],
            'RATitle': row[1],
            'RADate': row[2],
            'BusinessUnit': row[3],
            'StatusFlag': row[4],
            'scenario_count': row[5],
            'risk_status': risk,
            'RiskStatus': risk_status
        }
        result.append(item)

    return JsonResponse(result, safe=False)


def risk_assessment(request):
    data = {}
    if request.method == 'POST':
        if 'saveData' in request.POST:
            rawsaved = request.session.get('rawsaved', 0)
            if rawsaved == 0:
                # Create new RAWorksheet record
                ra_title = request.POST.get('title', '')
                ra_description = request.POST.get('description', '')
                ra_date = request.POST.get('date', '')
                ra_synopsis = request.POST.get('synopsis', '')
                ra_trigger = request.POST.get('RATrigger', '')
                ra_status = request.POST.get('StatusFlag', '')

                # Save RAWorksheet record
                raw_worksheet = RAWorksheet(
                    RATitle=ra_title,
                    RADescription=ra_description,
                    RADate=ra_date,
                    RASynopsis=ra_synopsis,
                    RATrigger=ra_trigger,
                    StatusFlag=ra_status
                )
                raw_worksheet.save()

                raw_current_record = raw_worksheet.ID

                # Save the first row (index 1) separately

                scenario_description = request.POST.get('scenario1', '')

                threat_code = request.POST.get('threat1', '')
                print(f"{threat_code}")
                vuln_code = request.POST.get('vulnerability1', '')
                reputation_code = request.POST.get('reputation1', '')
                financial_code = request.POST.get('financial1', '')
                operational_code = request.POST.get('operational1', '')
                safety_code = request.POST.get('safety1', '')
                risk_score = float(request.POST.get('risk1', ''))
                comments = request.POST.get('comments1', '')
                scenario_priority = request.POST.get('weight1', '')

                ra_worksheet_scenario = RAWorksheetScenario(
                    RAWorksheetID=raw_current_record,
                    ScenarioDescription=scenario_description,
                    ThreatCode=threat_code,
                    VulnCode=vuln_code,
                    ReputationCode=reputation_code,
                    FinancialCode=financial_code,
                    OperationalCode=operational_code,
                    SafetyCode=safety_code,
                    RiskScore=risk_score,
                    Comments=comments,
                    ScenarioPriority=scenario_priority
                )
                ra_worksheet_scenario.save()

                # Save RAWorksheetScenario records
                row_count = int(request.POST.get('hdnRowCount'))

                for i in range(2, row_count + 2):
                    print(f"saving scenario {i}")
                    scenario_description = request.POST.get('scenario{}'.format(i), '')
                    threat_code = request.POST.get('threat{}'.format(i), '')
                    vuln_code = request.POST.get('vulnerability{}'.format(i), '')
                    reputation_code = request.POST.get('reputation{}'.format(i), '')
                    financial_code = request.POST.get('financial{}'.format(i), '')
                    operational_code = request.POST.get('operational{}'.format(i), '')
                    safety_code = request.POST.get('safety{}'.format(i), '')
                    risk_score = float(request.POST.get('risk{}'.format(i), ''))
                    comments = request.POST.get('comments{}'.format(i), '')
                    scenario_priority = request.POST.get('weight{}'.format(i), '')

                    ra_worksheet_scenario = RAWorksheetScenario(
                        RAWorksheetID=raw_current_record,
                        ScenarioDescription=scenario_description,
                        ThreatCode=threat_code,
                        VulnCode=vuln_code,
                        ReputationCode=reputation_code,
                        FinancialCode=financial_code,
                        OperationalCode=operational_code,
                        SafetyCode=safety_code,
                        RiskScore=risk_score,
                        Comments=comments,
                        ScenarioPriority=scenario_priority
                    )
                    ra_worksheet_scenario.save()

                request.session['rawsaved'] = 1
                request.session['rawcurrentrecord'] = raw_current_record
                data['saved_label'] = f"New risk assessment saved with record id: {raw_current_record}"

            else:
                # Update existing RAWorksheet and RAWorksheetScenario records
                raw_current_record = request.session.get('rawcurrentrecord', None)
                if raw_current_record:
                    ra_title = request.POST.get('title', '')
                    ra_description = request.POST.get('description', '')
                    ra_date = request.POST.get('date', '')
                    ra_synopsis = request.POST.get('synopsis', '')

                    RAWorksheet.objects.filter(ID=raw_current_record).update(
                        RATitle=ra_title,
                        RADescription=ra_description,
                        RADate=ra_date,
                        RASynopsis=ra_synopsis
                    )

                    row_count = int(request.POST.get('rowCount', 0))
                    for i in range(2, row_count + 2):
                        scenario_description = request.POST.get('scenario{}'.format(i), '')
                        threat_code = request.POST.get('threat{}'.format(i), '')
                        vuln_code = request.POST.get('vulnerability{}'.format(i), '')
                        reputation_code = request.POST.get('reputation{}'.format(i), '')
                        financial_code = request.POST.get('financial{}'.format(i), '')
                        operational_code = request.POST.get('operational{}'.format(i), '')
                        safety_code = request.POST.get('safety{}'.format(i), '')
                        risk_score = request.POST.get('risk{}'.format(i), '')
                        comments = request.POST.get('comments{}'.format(i), '')
                        scenario_priority = request.POST.get('weight{}'.format(i), '')

                        scenario = get_object_or_404(RAWorksheetScenario, RAWorksheetID=raw_current_record, ID=i)
                        scenario.ScenarioDescription = scenario_description
                        scenario.ThreatCode = threat_code
                        scenario.VulnCode = vuln_code
                        scenario.ReputationCode = reputation_code
                        scenario.FinancialCode = financial_code
                        scenario.OperationalCode = operational_code
                        scenario.SafetyCode = safety_code
                        scenario.RiskScore = risk_score
                        scenario.Comments = comments
                        scenario.ScenarioPriority = scenario_priority
                        scenario.save()

    else:
        # Initialize session variables
        request.session['rawsaved'] = 0
        request.session['rawcurrentrecord'] = None

    # Retrieve the data to be displayed back to the user
    data['ra_title'] = request.POST.get('title', '')
    data['ra_description'] = request.POST.get('description', '')
    data['ra_date'] = request.POST.get('date', '')
    data['ra_synopsis'] = request.POST.get('synopsis', '')
    data['ra_trigger'] = request.POST.get('RATrigger', '')
    data['ra_status'] = request.POST.get('StatusFlag', '')
    data['scenarios'] = RAWorksheetScenario.objects.filter(RAWorksheetID=request.session.get('rawcurrentrecord'))

    return render(request, 'riskassess.html', data)


def site_walkdown(request):
    # questionnaires = SiteWalkdownQuestionnaire.objects.all()
    # context = {'questionnaires': questionnaires}
    # return render(request, 'site_walkdown.html', context)
    questionnaires = SiteWalkdownQuestionnaire.objects.all()
    categories = SiteWalkdownQuestionnaire.objects.values_list('Category', flat=True).distinct()
    context = {'questionnaires': questionnaires, 'categories': categories}
    return render(request, 'site_walkdown.html', context)


def save_threat(request):
    if request.method == 'POST':
        threat_update_flag = int(request.POST.get('ThreatUpdateFlag', '0'))
        threat_id = int(request.POST.get('ThreatAssessmentID'))

        if threat_update_flag == 0:
            # Add a new record
            threat = ThreatAssessment()
        elif threat_update_flag == 1:
            # Update an existing record
            threat = ThreatAssessment.objects.get(ThreatAssessmentID=threat_id)
        else:
            # Invalid update flag, handle as needed
            return redirect('threat_form')  # Redirect back to the form

        # threat.ThreatAssessmentID = threat_id
        threat.post_id = request.session.get('post_id')
        threat.ThreatType = request.POST.get('ThreatType')
        threat.ThreatImpactDescription = request.POST.get('ThreatImpactDescription')
        threat.ThreatImpactScore = int(request.POST.get('ThreatImpactScore'))
        threat.ThreatLikelihoodDescription = request.POST.get('ThreatLikelihoodDescription')
        threat.ThreatLikelihoodScore = int(request.POST.get('ThreatLikelihoodScore'))
        threat.IndustryAttackHistory = request.POST.get('IndustryAttackHistory')
        threat.HasAttackedYesNo = request.POST.get('HasAttackedYesNo')
        threat.HasBusinessImpactYesNo = request.POST.get('HasBusinessImpactYesNo')
        threat.AttackExpectedYesNo = request.POST.get('AttackExpectedYesNo')
        threat.KnownExposureYesNo = request.POST.get('KnownExposureYesNo')
        threat.Comments = request.POST.get('Comments')
        threat.OverallThreatRatingHML = request.POST.get('OverallThreatRatingHML')

        threat.save()

    return render(request, 'OTRisk/threatassess.html')


@csrf_exempt
def save_scenario(request):
    if request.method == 'POST':
        # Retrieve the scenario data from the POST request
        scenario_description = request.POST.get('scenario_description')
        consequence_analysis = request.POST.get('consequence_analysis')
        threat_source = request.POST.get('threat_source')
        threat_action = request.POST.get('threat_action')
        countermeasures = request.POST.get('countermeasures')
        severity = request.POST.get('severity')
        frequency = request.POST.get('frequency')
        exposure = request.POST.get('exposure')
        resilience = request.POST.get('resilience')
        input_rru = request.POST.get('input_rru')
        unmitigated_likelihood = request.POST.get('unmitigated_likelihood')
        severity_index = request.POST.get('severity_index')
        mitigate_severity = request.POST.get('mitigate_severity')
        mitigated_exposure = request.POST.get('mitigated_exposure')
        residual_risk_mitigated = request.POST.get('residual_risk_mitigated')
        after_action_severity = request.POST.get('after_action_severity')
        after_action_exposure = request.POST.get('after_action_exposure')
        residual_risk_after_action = request.POST.get('residual_risk_after_action')

        # Retrieve the post_id from the session variable
        post_id = request.session.get('post_id')
        print(post_id)

        if post_id is not None:
            try:
                scenario = RiskScenario.objects.get(post_id=post_id)

                # Update the existing scenario record
                scenario.ScenarioDescription = scenario_description
                scenario.ConsequenceAnalysis = consequence_analysis
                scenario.ThreatScore = threat_source
                scenario.ThreatAction = threat_action
                scenario.Countermeasures = countermeasures
                scenario.Severity = severity
                scenario.Frequency = frequency
                scenario.Exposure = exposure
                scenario.Resilience = resilience
                scenario.RRu = input_rru
                scenario.UEL = unmitigated_likelihood
                scenario.SI = severity_index
                scenario.Sm = mitigate_severity
                scenario.MEL = mitigated_exposure
                scenario.RRm = residual_risk_mitigated
                scenario.Sa = after_action_severity
                scenario.MELa = after_action_exposure
                scenario.RRa = residual_risk_after_action
                scenario.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario': scenario.id})

            except RiskScenario.DoesNotExist:
                # Create a new scenario record
                scenario = RiskScenario(
                    post_id=post_id,
                    ScenarioDescription=scenario_description,
                    ConsequenceAnalysis=consequence_analysis,
                    ThreatScore=threat_source,
                    ThreatAction=threat_action,
                    Countermeasures=countermeasures,
                    Severity=severity,
                    Frequency=frequency,
                    Exposure=exposure,
                    Resilience=resilience,
                    RRu=input_rru,
                    UEL=unmitigated_likelihood,
                    SI=severity_index,
                    Sm=mitigate_severity,
                    MEL=mitigated_exposure,
                    RRm=residual_risk_mitigated,
                    Sa=after_action_severity,
                    MELa=after_action_exposure,
                    RRa=residual_risk_after_action
                )
                scenario.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario': scenario.id})

        else:
            # Handle the post_id not set in session variable
            return JsonResponse({'success': False, 'message': 'post_id not set in session variable.'})

    else:
        # Handle invalid request method
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})


@csrf_exempt
def save_recommendation(request):
    if request.method == 'POST':
        recommendation = request.POST.get('recommendation')
        post_id = request.session.get('post_id')

        if recommendation and post_id:
            try:
                current_scenario = RiskScenario.objects.get(post_id=post_id)
                current_scenario_id = current_scenario.id

                # Save the recommendation for the current scenario
                scenario_recommendation = tblScenarioRecommendations(
                    RiskPostID=current_scenario_id,
                    Recommendation=recommendation
                )
                scenario_recommendation.save()

                # Return success response
                return JsonResponse({'success': True, 'current_scenario_id': current_scenario_id})

            except RiskScenario.DoesNotExist:
                # Handle scenario not found
                return JsonResponse({'success': False, 'message': 'Scenario not found.'})

        else:
            # Handle missing recommendation or post_id
            return JsonResponse({'success': False, 'message': 'Missing recommendation or post_id.'})

    else:
        # Handle invalid request method
        return JsonResponse({'success': False, 'message': 'Invalid request method.'})


def add_team_members(request):
    post_id = request.session.get('post_id')
    post = get_object_or_404(Post, id=post_id)

    if request.method == 'POST':
        form = AssessmentTeamForm(request.POST)

        if form.is_valid():
            team_member = form.save(commit=False)
            team_member.RiskID = post
            team_member.save()

            return redirect('OTRisk:add_team_members')
    else:
        form = AssessmentTeamForm()

    team_members = AssessmentTeam.objects.filter(RiskID=post)

    return render(request, 'OTRisk/team_member.html', {
        'post_form': PostForm(instance=post),
        'team_member_form': form,
        'team_members': team_members,
        'saved': True
    })


def workshop_setup(request):
    if request.method == 'POST':
        workshop_type = request.POST.get('workshoptype')
        workshop_start_date = request.POST.get('workshopstartdate')
        workshop_name = request.POST.get('workshopname')
        workshop_objectives = request.POST.get('workshopobjectives')

        new_workshop = tblWorkshopInformation(
            WorkshopStartDate=workshop_start_date,
            WorkshopName=workshop_name,
            WorkshopObjectives=workshop_objectives,
            WorkshopType=workshop_type
        )

        new_workshop.save()
        new_workshop_id = new_workshop.ID

        return redirect('OTRisk:workshop', workshop_id=new_workshop_id)

    workshops = tblWorkshopInformation.objects.all()
    return render(request, 'OTRisk/workshop.html', {'workshops': workshops})


def workshop(request, workshop_id=None):
    # Get all distinct TopSections
    top_sections = tblWorkshopNarrative.objects.values('TopSection').distinct()

    sections = []
    for top_section in top_sections:
        # For each TopSection, get all related questions
        if workshop_id is not None:
            # If a workshop_id is provided, filter questions for that workshop
            questions = tblWorkshopNarrative.objects.filter(TopSection=top_section['TopSection'],
                                                            WorkshopID=workshop_id)
        else:
            # If no workshop_id is provided, get all questions for the TopSection
            questions = tblWorkshopNarrative.objects.filter(TopSection=top_section['TopSection'])

        # Append a dictionary to the sections list for each TopSection
        sections.append({
            'TopSection': top_section['TopSection'],
            'questions': questions,
        })

    return render(request, 'OTRisk/workshop.html', {'sections': sections})
    # return render(request, 'OTRisk/workshop.html', {'workshop': workshop, 'sections': sections})


def raworksheets(request):
    scenarios = tblScenario.objects.order_by('InitiatingEvent')
    consequences = tblConsequence.objects.order_by('Consequence')

    post_id = request.session.get('post_id')

    if post_id is not None:
        post = get_object_or_404(Post, id=post_id)
    else:
        post = None

    if post_id is not None:
        current_scenario = post_id
        request.session['Current_Scenario'] = current_scenario

    context = {
        'scenarios': scenarios,
        'consequences': consequences,
        'post': post,
    }

    return render(request, 'raworksheets.html', context)
    # return render(request, 'raworksheets.html', {'scenarios': scenarios, 'Consequences': Consequences})


def walkthrough(request):
    query_results = Questionnaire.objects \
        .values('id', 'title', 'description', 'questiontheme__QuestionTheme',
                'questions__questionnumber', 'questions__questiontext') \
        .filter(fkFacilityType_id=9)

    facility_type = get_object_or_404(FacilityType, id=facility_type_id)

    return render(request, 'OTRisk/walkthrough.html', {'query_results': query_results})


def add_walkthrough(request):
    facility_types = FacilityType.objects.all()
    return render(request, 'OTRisk/walkthrough.html', {'facility_types': facility_types})


def walkthrough_questionnaire(request, facility_type_id):
    print("called 1")
    query_results = Questionnaire.objects \
        .values('id', 'title', 'description', 'questionthemes__QuestionTheme',
                'questionthemes__questions__questionnumber', 'questionthemes__questions__questiontext') \
        .filter(id=F('questionthemes__fkQuestionnaireID'),
                questionthemes__id=F('questionthemes__questions__ThemeID'),
                fkFacilityType_id=facility_type_id) \
        .distinct()
    row_count = len(query_results)
    print("Row count:", row_count)
    facility_type = get_object_or_404(FacilityType, id=facility_type_id)

    return render(request, 'OTRisk/walkthroughQuestionnaire.html',
                  {'facility_type': facility_type, 'query_results': query_results})


def walkthrough_questionnaire_details(request, questionnaire_id):
    # Add your logic here to retrieve the questionnaire details and render the template
    return render(request, 'OTRisk/walkthroughQuestionnaire.html', {'questionnaire_id': questionnaire_id})


class PostCreateView(CreateView):
    model = Post
    form_class = PostForm
    template_name = 'OTRisk/post_create.html'
    success_url = reverse_lazy('OTRisk:post_list')


# Scenario Detail View

def scenario_detail(request, pk):
    scenario = get_object_or_404(RiskScenario, pk=pk)
    return render(request, 'OTRisk/post/scenario_detail.html', {'scenario': scenario})


class ScenarioDetailView(View):
    template_name = 'OTRisk/post/scenario_detail.html'

    def get(self, request, *args, **kwargs):
        scenario = get_object_or_404(RiskScenario, pk=self.kwargs['pk'])
        form = RiskScenarioForm(instance=scenario)
        return render(request, self.template_name, {'scenario': scenario, 'form': form})


class ScenarioUpdateView(View):
    def post(self, request, *args, **kwargs):
        scenario = get_object_or_404(RiskScenario, pk=self.kwargs['pk'])
        form = RiskScenarioForm(request.POST, instance=scenario)
        if form.is_valid():
            form.save()
            return redirect('OTRisk:scenario_detail', pk=self.kwargs['pk'])
        else:
            return render(request, 'OTRisk/post/scenario_edit.html', {'form': form})


# Scenario Delete View
class ScenarioDeleteView(DeleteView):
    model = RiskScenario
    template_name = 'scenario_delete.html'
    success_url = reverse_lazy('OTRisk:post_list')  # Update this with the appropriate URL


class PostListView(generic.ListView):
    model = Post
    context_object_name = 'posts'
    template_name = 'OTRisk/post/list.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        submit_status_counts = (
            Post.objects
            .values('submit_status')
            .annotate(count=Count('submit_status'))
            .order_by()
        )
        # Prepare the data for the pie chart
        submit_status_data = {
            'labels': [status['submit_status'] for status in submit_status_counts],
            'counts': [status['count'] for status in submit_status_counts],
        }

        # unique_business_units = Post.objects.order_by('business_unit').values_list('business_unit', flat=True).distinct()
        unique_business_units = (
            Post.objects
            .values('business_unit')
            .annotate(count=Count('business_unit'))
            .order_by()
        )
        business_unit_data = [unit['business_unit'] for unit in unique_business_units]
        business_unit_counts = [unit['count'] for unit in unique_business_units]

        unique_submit_statuses = Post.objects.order_by('submit_status').values_list('submit_status',
                                                                                    flat=True).distinct()
        context['unique_business_units'] = unique_business_units
        context['unique_submit_statuses'] = unique_submit_statuses
        context['submit_status_data'] = submit_status_data
        context['business_unit_data'] = business_unit_data
        context['business_unit_counts'] = business_unit_counts
        return context


# class PostDetailView(generic.DetailView):
#    model = Post
#    template_name = 'OTRisk/post/detail.html'


# def post_detail(request, pk):
#    post = get_object_or_404(Post, pk=pk)
#    return render(request, 'OTRisk/post/detail.html', {'post': post})

class PostDetailView(generic.DetailView):
    model = Post
    template_name = 'raworksheets.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['scenarios'] = tblScenario.objects.order_by('InitiatingEvent')
        return context


def post_detail(request, pk):
    post = get_object_or_404(Post, pk=pk)
    scenarios = tblScenario.objects.order_by('InitiatingEvent')
    return render(request, 'raworksheets.html', {'post': post, 'scenarios': scenarios})


# Add or edit a record to the OTRisk_post table as the header for a new CyberPHA
def add_post(request):
    if request.method == 'POST':
        post_form = PostForm(request.POST)
        if post_form.is_valid():
            editflag = request.POST.get('editflag')

            post_risk = post_form.save(commit=False)
            print(f"postform= {post_form}")
            if editflag == '0':

                post_risk.process_description = post_form.cleaned_data.get('process_description')
                post_risk.hazardous_events = post_form.cleaned_data.get('hazardous_events')
                post_risk.facility = post_form.cleaned_data.get('facility')
                post_risk.project_name = post_form.cleaned_data.get('project_name')
                post_risk.scope = post_form.cleaned_data.get('scope')
                post_risk.objective = post_form.cleaned_data.get('objective')
                post_risk.assumptions = post_form.cleaned_data.get('assumptions')
                post_risk.trigger_event = post_form.cleaned_data.get('trigger_event')
                post_risk.SystemName = post_form.cleaned_data.get('SystemName')
                post_risk.SystemDescription = post_form.cleaned_data.get('SystemDescription')
                post_risk.SystemOwner = post_form.cleaned_data.get('SystemOwner')
                post_risk.SystemScope = post_form.cleaned_data.get('SystemScope')
                post_risk.riskauthor_id = 1  # post_form.cleaned_data.get('riskauthor')
                post_risk.save()
                post_id = post_risk.id
                # set session IDs
                request.session['post_id'] = post_id
                request.session['CyberPHATitle'] = post_risk.process_description
                request.session['Location'] = post_risk.facility
                request.session['PHAScope'] = post_risk.scope
                request.session['SystemName'] = post_risk.SystemName
                request.session['WorkflowStep'] = 2

            elif editflag == '1':

                post_id = request.session.get('post_id')
                if post_id:
                    try:

                        existing_post = Post.objects.get(id=post_id)
                        existing_post.process_description = post_form.cleaned_data.get('process_description')
                        existing_post.hazardous_events = post_form.cleaned_data.get('hazardous_events')
                        existing_post.facility = post_form.cleaned_data.get('facility')
                        existing_post.project_name = post_form.cleaned_data.get('project_name')
                        existing_post.scope = post_form.cleaned_data.get('scope')
                        existing_post.objective = post_form.cleaned_data.get('objective')
                        existing_post.assumptions = post_form.cleaned_data.get('assumptions')
                        existing_post.trigger_event = post_form.cleaned_data.get('trigger_event')
                        existing_post.SystemName = post_form.cleaned_data.get('SystemName')
                        existing_post.SystemDescription = post_form.cleaned_data.get('SystemDescription')
                        existing_post.SystemOwner = post_form.cleaned_data.get('SystemOwner')
                        existing_post.SystemScope = post_form.cleaned_data.get('SystemScope')
                        existing_post.save()
                        request.session['post_id'] = post_id
                        request.session['CyberPHATitle'] = existing_post.process_description
                        request.session['Location'] = existing_post.facility
                        request.session['PHAScope'] = existing_post.scope
                        request.session['SystemName'] = existing_post.SystemName
                    except Post.DoesNotExist:
                        pass

            context = {
                'post_form': post_form,
                'saved': True,
            }

            return render(request, 'OTRisk/post_create.html', context)
    else:
        post_form = PostForm()

    context = {
        'post_form': post_form,
        'saved': False,
    }

    return render(request, 'OTRisk/post_create.html', context)


# ------End of adding or editing a new cyberPHA header record

def post_create(request):
    # get the threat list
    threats = ThreatAssessment.objects.all()
    print(f' {threats} ')
    context = {
        'threats': threats
    }
    return render(request, 'OTRisk/post_create.html', context)


def add_riskscenario(request, pk):
    post = get_object_or_404(Post, pk=pk)

    if request.method == 'POST':
        post_form = PostForm(request.POST)
        risk_scenario_form = RiskScenarioForm(request.POST)
        if post_form.is_valid() and risk_scenario_form.is_valid():
            post = post_form.save(commit=False)
            post.riskauthor = request.user  # Set the riskauthor to the current user
            post.save()

            risk_scenario = risk_scenario_form.save(commit=False)
            risk_scenario.post = post
            risk_scenario.save()

            return redirect('OTRisk:post_detail', pk=pk)

        else:
            post_form = PostForm()
            risk_scenario_form = RiskScenarioForm()

        scenario_name = request.POST.get('scenario_name')
        probability = request.POST.get('probability')
        scenario_description = request.POST.get('scenario_description')
        consequence_analysis = request.POST.get('consequence_analysis')
        initiating_event = request.POST.get('initiating_event')
        risk_evaluation = request.POST.get('risk_evaluation')
        risk_ranking = request.POST.get('risk_ranking')
        RiskScore = request.POST.get('RiskScore')
        weight = request.POST.get('weight')
        OverallRiskScore = request.POST.get('OverallRiskScore')
        ThreatScore = request.POST.get('ThreatScore')
        VulnScore = request.POST.get('VulnScore')
        FinancialImpact = request.POST.get('FinancialImpact')
        OperationalImpact = request.POST.get('OperationalImpact')
        ReputationImpact = request.POST.get('RepuationImpact')

        # Create a new RiskScenario object and associate it with the post
        risk_scenario = RiskScenario(
            post=post,
            ScenarioName=scenario_name,
            ScenarioDescription=scenario_description,
            ConsequenceAnalysis=consequence_analysis,
            InitiatingEvent=initiating_event,
            risk_evaluation=risk_evaluation,
            risk_ranking=risk_ranking,
            probability=probability,
            RiskScore=RiskScore,
            Weight=weight,
            OverallRiskScore=OverallRiskScore,
            ThreatScore=ThreatScore,
            VulnScore=VulnScore,
            FinancialImpact=FinancialImpact,
            OperationalImpact=OperationalImpact,
            ReputationImpact=ReputationImpact,
        )
        risk_scenario.save()

        # Redirect to the post detail page
        return redirect('OTRisk:post_detail', pk=pk)

    # If the request method is not POST, render a default form
    return render(request, 'OTRisk/post/add_riskscenario.html', {'post': post})


def write_to_audit(user_id, user_action, user_ip):
    auditlog_entry = auditlog(userID=user_id, timestamp=timezone.now(), user_action=user_action, user_ipaddress=user_ip)
    auditlog_entry.save()
