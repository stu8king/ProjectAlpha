import openai
import os

from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions, MitreICSMitigations, MitreICSTechniques
from django.contrib.auth.decorators import login_required
from OTRisk.models.questionnairemodel import FacilityType
from OTRisk.models.Model_CyberPHA import tblIndustry, tblThreatSources, auditlog
from OTRisk.models.Model_Mitre import MitreICSTactics
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from datetime import date
from django.views import View
from django.http import JsonResponse

import nvdlib
import requests


@login_required()
def qraw(request):
    print(f"{request.POST}")
    if request.method == 'POST':
        edit_mode = int(request.POST.get('edit_mode', 0))
        print(f'edit_mode={edit_mode}')
        if edit_mode == 0:
            print('adding new')
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
                    scenario = RAWorksheetScenario(
                        RAWorksheetID=ra_worksheet.pk,
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
                        notes=request.POST.get(f'txtJustify_{i}')
                    )
                    scenario.save()
        elif edit_mode == 1:
            print('editing')
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
            for i in range(1, scenario_count):
                scenario_id = int(request.POST.get(f'hdnScenarioID_{i}'))
                scenario = RAWorksheetScenario.objects.get(ID=scenario_id)
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
                scenario.notes = request.POST.get(f'txtJustify_{i}')
                scenario.save()

    raws = RAWorksheet.objects.all()
    # scenarios = RAWorksheetScenario.objects.all()
    # reply = openai_assess_risk(request, request.POST)

    facilities = FacilityType.objects.all().order_by('FacilityType')
    industries = tblIndustry.objects.all().order_by('Industry')
    threatsources = tblThreatSources.objects.all().order_by('ThreatSource')
    mitreTactics = MitreICSTactics.objects.all().order_by('tactic')
    mitreMitigations = MitreICSMitigations.objects.all().order_by('id')

    user_ip = request.META.get('REMOTE_ADDR', '')
    user_action = "qraw"
    write_to_audit(request.user.id, user_action, user_ip)

    return render(request, 'qraw.html',
                  {'raws': raws,
                   'facilities': facilities,
                   'industries': industries,
                   'threatsources': threatsources,
                   'mitreTactics': mitreTactics,
                   'mitreMitigations': mitreMitigations})


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

        # Prepare the request data for the OpenAI GPT-3 API in the chat format
        message = [
            {"role": "system",
             "content": f"As a cybersecurity risk assessment professional, I need you to assess the risk of {threat_source} using the threat tactic {threat_tactic} on a scenario relating to {scenario} in a {facility_type} in the {industry} industry."},
            {"role": "user",
             "content": f"Provide, without any commentary or additional information only the three specific pieces of information that are asked for. Provide the overall risk rating as one of the following values: Low, Low/Medium, Medium, Medium/High or High, depending on your assessment of the risk based on the information gvien then offer a risk score in the range of 1  to 10 where 1 would be a very low overall risk and 10 would be a catatrophic risk,  based on the following information:\nThreat source - {threat_source}, Threat tactic - {threat_tactic}, Safety impact - {safety_impact}/10, Life impact - {life_impact}/10, Production impact - {production_impact}/10, Financial impact - {financial_impact}/10, Reputation impact - {reputation_impact}/10, Environment impact - {environment_impact}/10, Regulatory impact - {regulatory_impact}/10, Data impact - {data_impact}/10, Vulnerability exposure - {vulnerability_exposure}/10, Threat exposure - {threat_exposure}/10, Industry - {industry}, Type of facility - {facility_type}. “The third piece of information is <summary> which must be a one sentence summary of the key pieces of information used to make the assessment: in particular the weighting given to the industry type, the facility type and the other factors that were given the highest weighting. Provide only the three pieces of information that have been requested. No title or header. The output must be given as simply <overall_risk_rating_value>|<overall_risk_score>|<summary>."
             }
        ]

        openai.api_key = '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'

        # Make the API call to the OpenAI GPT-3 API using the message
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use the GPT-3 engine
            messages=message,
            temperature=0,
            max_tokens=256
        )

        # Extract the generated response from the API
        generated_response = response['choices'][0]['message']['content']
        risk_summary = generated_response.split('|')[2].strip()
        risk_score = generated_response.split('|')[1].strip()
        risk_rating = generated_response.split('|')[0].strip()

        # Create an array to return to the user interface
        result_array = [risk_rating, risk_score, risk_summary]
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
    raw_actions = RAActions.objects.all()
    return render(request, 'raw_action.html', {
        'raw_actions': raw_actions
     })
