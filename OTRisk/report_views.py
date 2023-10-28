from django.db.models import Count, Avg, F, ExpressionWrapper, FloatField, Value, CharField, Func, Sum
from django.db.models.functions import Cast, Substr, Length, math
from math import ceil
from django.forms import IntegerField
from django.shortcuts import get_object_or_404
from django.core import serializers
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario, vulnerability_analysis, \
    MitreControlAssessment
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario
from OTRisk.models.raw import RAActions
from .pha_views import calculate_effectiveness, get_overall_control_effectiveness_score

from django.shortcuts import render


def pha_reports(request, cyber_pha_header_id):
    # Get the related records using the function we defined earlier
    context = get_pha_records(cyber_pha_header_id)

    # Render the pha_report.html template with the context
    return render(request, 'pha_report.html', context)


def get_pha_records(cyber_pha_header_id):
    # Retrieve the main record from tblCyberPHAHeader
    cyber_pha_header = get_object_or_404(tblCyberPHAHeader, ID=cyber_pha_header_id)

    other_summary_list = cyber_pha_header.otherSummary.split('\n')
    other_summary_html = ''.join(f'<p>{item.strip()}</p>' for item in other_summary_list if item)
    chemical_summary_list = cyber_pha_header.chemicalSummary.split('\n')
    chemical_summary_html = ''.join(f'<p>{item.strip()}</p>' for item in chemical_summary_list if item)
    safety_summary_list = cyber_pha_header.safetySummary.split('\n')
    safety_summary_html = ''.join(f'<p>{item.strip()}</p>' for item in safety_summary_list if item)
    compliance_summary_list = cyber_pha_header.complianceSummary.split('\n')
    compliance_summary_html = ''.join(f'<p>{item.strip()}</p>' for item in compliance_summary_list if item)
    physical_summary_list = cyber_pha_header.physicalSummary.split('\n')
    physical_summary_html = ''.join(f'<p>{item.strip()}</p>' for item in physical_summary_list if item)

    # Retrieve related records from tblCyberPHAScenario
    cyber_pha_scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=cyber_pha_header)
    total_cost_impact = format_currency(cyber_pha_scenarios.aggregate(Sum('sle'))['sle__sum'])

    total_cost_impact_low = format_currency(cyber_pha_scenarios.aggregate(Sum('sle_low'))['sle_low__sum'])

    total_cost_impact_high = format_currency(cyber_pha_scenarios.aggregate(Sum('sle_high'))['sle_high__sum'])

    # Summarize RiskCategory
    risk_category_summary = cyber_pha_scenarios.values('RiskCategory').annotate(count=Count('RiskCategory'))

    impact_fields = [f.name for f in tblCyberPHAScenario._meta.get_fields() if f.name.startswith('impact')]
    impact_summary = {}
    for field in impact_fields:
        avg_value = cyber_pha_scenarios.aggregate(avg_value=Avg(field))['avg_value']
        custom_name = field.replace('impact', '')
        impact_summary[custom_name] = avg_value

    # Fetch all probability values, strip the % sign, and convert to integers
    try:
        probabilities = [float(prob.probability.rstrip('%')) for prob in cyber_pha_scenarios.only('probability')]

        # Calculate the average probability
        average_probability = round(sum(probabilities) / len(probabilities) if probabilities else 0)
    except:
        average_probability = 0

    # Retrieve related records from vulnerability_analysis
    vulnerability_analyses = vulnerability_analysis.objects.filter(scenario__CyberPHA=cyber_pha_header)

    # Retrieve related records from RAActions where phaID matches the given cyber_pha_header_id
    ra_actions = RAActions.objects.filter(phaID=cyber_pha_header_id)
    ra_actions_json = serializers.serialize('json', ra_actions)
    # Retrieve related records from MitreControlAssessment
    mitre_control_assessments = MitreControlAssessment.objects.filter(cyberPHA=cyber_pha_header)

    overall_control_effectiveness = int(ceil(get_overall_control_effectiveness_score(cyber_pha_header_id)))

    # Fetch all user-defined likelihood values
    user_likelihoods = [scenario.likelihood for scenario in cyber_pha_scenarios]

    # Calculate the average user-defined likelihood
    average_user_likelihood = sum(user_likelihoods) / len(user_likelihoods) if user_likelihoods else 0

    # Calculate the overall likelihood
    # This is a weighted average where we give equal weight to user-defined likelihood and calculated likelihood
    overall_likelihood = round((average_probability + average_user_likelihood) / 2 * (
            1 - (overall_control_effectiveness / 100)))

    return {
        'cyber_pha_header': cyber_pha_header,
        'cyber_pha_scenarios': cyber_pha_scenarios,
        'average_probability': average_probability,
        'risk_category_summary': risk_category_summary,
        'impact_summary': impact_summary,
        'vulnerability_analyses': vulnerability_analyses,
        'ra_actions_json': ra_actions_json,
        'mitre_control_assessments': mitre_control_assessments,
        'total_cost_impact': total_cost_impact,
        'total_cost_impact_low': total_cost_impact_low,
        'total_cost_impact_high': total_cost_impact_high,
        'compliance_summary_html': compliance_summary_html,
        'safety_summary_html': safety_summary_html,
        'chemical_summary_html': chemical_summary_html,
        'physical_summary_html': physical_summary_html,
        'other_summary_html': other_summary_html,
        'overall_control_effectiveness': overall_control_effectiveness,
        'overall_likelihood': overall_likelihood
    }


class Replace(Func):
    function = 'REPLACE'
    template = "%(function)s(%(expressions)s, %(value_1)s, %(value_2)s)"


def format_currency(value):
    if value is None:
        return "$0.00"  # or whatever default or placeholder you want to use

    if value >= 1_000_000_000:  # Billions
        return "${:.1f}b".format(value / 1_000_000_000)
    elif value >= 1_000_000:  # Millions
        return "${:.1f}m".format(value / 1_000_000)
    elif value >= 1_000:  # Thousands
        return "${:.1f}k".format(value / 1_000)
    else:
        return "${:.2f}".format(value)


from django.http import JsonResponse


def get_scenario_report_details(request):
    scenario_id = request.GET.get('id')
    scenario = tblCyberPHAScenario.objects.get(ID=scenario_id)
    control_effectiveness = int(ceil(get_overall_control_effectiveness_score(scenario.CyberPHA)))
    controls = scenario.controls.all().values('control', 'score', 'reference')
    sle = format_currency(scenario.sle)

    sle_low = format_currency(scenario.sle_low)

    sle_high = format_currency(scenario.sle_high)
    # calculate the overall likelihood of the scenario
    probability_value = int(round(float(scenario.probability.rstrip('%'))))

    inherent_likelihood = scenario.likelihood / 100.0  # Convert percentage to a fraction
    residual_likelihood = probability_value / 100.0  # Convert percentage to a fraction

    scenario_likelihood = categorize_likelihood((inherent_likelihood * residual_likelihood) * 100)

    data = {
        'impactSafety': scenario.impactSafety,
        'impactDanger': scenario.impactDanger,
        'impactProduction': scenario.impactProduction,
        'impactFinance': scenario.impactFinance,
        'impactReputation': scenario.impactReputation,
        'impactEnvironment': scenario.impactEnvironment,
        'impactRegulation': scenario.impactRegulation,
        'impactData': scenario.impactData,
        'impactSupply': scenario.impactSupply,
        'RRU': scenario.RRU,
        'UEL': scenario.UEL,
        'SM': scenario.SM,
        'MEL': scenario.MEL,
        'RRM': scenario.RRM,
        'Consequence': scenario.Consequence,
        'ThreatClass': scenario.ThreatClass,
        'RiskCategory': scenario.RiskCategory,
        'RRa': scenario.RRa,
        'recommendations': scenario.recommendations,
        'standards': scenario.standards,
        'sle': sle,
        'sle_low': sle_low,
        'sle_high': sle_high,
        'residual_risk': scenario.RRa,
        'control_effectiveness': control_effectiveness,
        'scenario_likelihood': scenario_likelihood,
        'controls': list(controls)
    }
    return JsonResponse(data)


def categorize_likelihood(likelihood_percentage):
    if 0 <= likelihood_percentage <= 20:
        return "Low"
    elif 21 <= likelihood_percentage <= 40:
        return "Low/Medium"
    elif 41 <= likelihood_percentage <= 60:
        return "Medium"
    elif 61 <= likelihood_percentage <= 80:
        return "Medium/High"
    else:
        return "High"


def qraw_reports(request, qraw_id):
    # Get the related records using the function we defined earlier
    context = get_qraw_records(qraw_id)

    # Render the pha_report.html template with the context
    return render(request, 'qraw_report.html', context)


def get_qraw_records(qraw_id):
    # Retrieve the main record from tblRAWorksheet
    qraw_header = get_object_or_404(RAWorksheet, ID=qraw_id)

    # Retrieve related records from tblCyberPHAScenario
    qraw_scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=qraw_id)

    total_cost_impact = format_currency(qraw_scenarios.aggregate(Sum('event_cost_median'))['event_cost_median__sum'])

    total_cost_impact_low = format_currency(qraw_scenarios.aggregate(Sum('event_cost_low'))['event_cost_low__sum'])

    total_cost_impact_high = format_currency(qraw_scenarios.aggregate(Sum('event_cost_high'))['event_cost_high__sum'])

    # Summarize RiskCategory
    risk_category_summary = qraw_scenarios.values('threatSource').annotate(count=Count('threatSource'))

    model_class = RAWorksheetScenario

    # Define a set of fields to exclude
    exclude_fields = {'RiskScore', 'ThreatScore', 'VulnScore', 'OperationScore'}

    # Adjust the list comprehension to exclude the unwanted fields
    impact_fields = [f.name for f in model_class._meta.get_fields() if
                     'score' in f.name.lower() and f.name not in exclude_fields]

    impact_summary = {}
    for field in impact_fields:
        avg_value = qraw_scenarios.aggregate(avg_value=Avg(field))['avg_value']
        custom_name = field.replace('Score', '')
        custom_name = custom_name.title()
        impact_summary[custom_name] = avg_value

    # Retrieve related records from RAActions where phaID matches the given cyber_pha_header_id
    ra_actions = RAActions.objects.filter(RAWorksheetID=qraw_id)

    overall_scores = qraw_scenarios.aggregate(
        avg_vulnerability=Avg('VulnScore'),
        avg_threat=Avg('ThreatScore'),
        avg_inherent_risk=Avg('RiskScore'),
        avg_residual_risk=Avg('residual_risk')
    )

    # Normalize the scores to be out of 10
    normalized_scores = {
        'overall_vulnerability_score': overall_scores['avg_vulnerability'] ,
        'overall_threat_score': overall_scores['avg_threat'] ,
        'overall_inherent_risk_score': overall_scores['avg_inherent_risk'] ,
        'overall_residual_risk_score': overall_scores['avg_residual_risk']
    }

    return {
        'risk_category_summary': risk_category_summary,
        'qraw_header': qraw_header,
        'impact_summary': impact_summary,
        'ra_actions': ra_actions,
        'total_cost_impact': total_cost_impact,
        'total_cost_impact_low': total_cost_impact_low,
        'total_cost_impact_high': total_cost_impact_high,
        'qraw_scenarios': qraw_scenarios,
        **normalized_scores
    }


def get_qraw_scenario_report_details(request):
    scenario_id = request.GET.get('id')

    scenario = RAWorksheetScenario.objects.get(ID=scenario_id)
    # Retrieve associated controls for the scenario
    controls = scenario.controls.all().values('control', 'score')

    event_cost_low = format_currency(scenario.event_cost_low)

    event_cost_median = format_currency(scenario.event_cost_median)

    event_cost_high = format_currency(scenario.event_cost_high)

    data = {
        'impactSafety': scenario.SafetyScore,
        'impactDanger': scenario.lifeScore,
        'impactProduction': scenario.productionScore,
        'impactFinance': scenario.FinancialScore,
        'impactReputation': scenario.ReputationScore,
        'impactEnvironment': scenario.environmentScore,
        'impactRegulation': scenario.regulatoryScore,
        'impactData': scenario.DataScore,
        'impactSupply': scenario.SupplyChainScore,
        'risk_summary': scenario.riskSummary,
        'residual_risk': scenario.residual_risk,
        'inherent_risk_score': scenario.RiskScore,
        'inherent_risk_status': scenario.RiskStatus,
        'outage': scenario.outage,
        'event_cost_low': event_cost_low,
        'event_cost_median': event_cost_median,
        'event_cost_high': event_cost_high,
        'vulnerability_score': scenario.VulnScore,
        'threat_score': scenario.ThreatScore,
        'threat_source': scenario.threatSource,
        'controls': list(controls)

    }
    return JsonResponse(data)
