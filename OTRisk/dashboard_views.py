from collections import defaultdict

from django.http import JsonResponse
from django.shortcuts import render
from django.core.serializers import serialize
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from OTRisk.models.raw import RAWorksheet, RAWorksheetScenario, RAActions
from django.contrib.auth.decorators import login_required
from OTRisk.models.Model_CyberPHA import tblCyberPHAHeader, tblCyberPHAScenario, OrganizationDefaults, auditlog, \
    CyberPHAModerators, CyberPHA_Group
from django.db.models import Count, Sum, Q, Case, When, Value, CharField
from django.db.models import Avg
from accounts.models import Organization, UserProfile
import feedparser
from bs4 import BeautifulSoup
import json
import requests
from django.db.models import Max, F


def fetch_weather_alerts(latitude, longitude, api_key):
    """Fetch weather alerts for a specific latitude and longitude using OpenWeatherMap API."""
    url = f"https://api.openweathermap.org/data/2.5/onecall?lat={latitude}&lon={longitude}&appid={api_key}&exclude=current,minutely,daily,hourly"
    response = requests.get(url)
    data = response.json()
    alerts = data.get('alerts', [])
    return alerts


def enhance_facilities_with_alerts(facilities_data, api_key):
    """Append weather alerts to each facility record after cleaning text fields."""
    for facility in facilities_data:
        # Clean each text field in the facility data
        for key in ['FacilityName', 'facilityAddress', 'facilityCity', 'facilityState', 'facilityCode', 'country']:
            if key in facility:
                facility[key] = clean_text(facility[key])

        # Fetch weather alerts for each facility based on its latitude and longitude
        alerts = fetch_weather_alerts(facility['facilityLat'], facility['facilityLong'], api_key)

        # Add alert information to the facility data
        facility['WeatherAlerts'] = alerts
    return facilities_data


def process_summary_html(summary):
    # Parse the summary HTML
    soup = BeautifulSoup(summary, 'html.parser')

    # Find all <a> tags and add the desired attributes
    for link in soup.find_all('a'):
        link['target'] = '_blank'
        link['rel'] = 'noopener noreferrer'

    # Return the modified HTML as a string
    return str(soup)


def fetch_darkreading_news():
    # RSS feed URL
    feed_url = 'https://www.darkreading.com/rss.xml'

    # Fetch and parse the feed
    feed = feedparser.parse(feed_url)

    # Extract and return news items with modified summaries
    news_items = []
    for entry in feed.entries:
        # Process the summary to add target="_blank" and rel="noopener noreferrer" to links
        processed_summary = process_summary_html(entry.summary)

        news_items.append({
            'title': entry.title,
            'link': entry.link,
            'published': entry.published,  # You might want to format this as needed
            'summary': processed_summary,
        })

    return news_items


def fetch_securityweek_news():
    # RSS feed URL
    feed_url = 'https://feeds.feedburner.com/securityweek'

    # Fetch and parse the feed
    feed = feedparser.parse(feed_url)

    # Extract and return news items with modified summaries
    news_items = []
    for entry in feed.entries:
        # Process the summary to add target="_blank" and rel="noopener noreferrer" to links
        processed_summary = process_summary_html(entry.summary)

        news_items.append({
            'title': entry.title,
            'link': entry.link,
            'published': entry.published,  # You might want to format this as needed
            'summary': processed_summary,
        })

    return news_items


def get_user_organization_id(request):
    """Fetch organization ID for the logged-in user."""
    user_profile = UserProfile.objects.get(user=request.user)
    request.session['user_organization'] = user_profile.organization.id
    return user_profile.organization.id


def get_organization_users(organization_id):
    """Fetch users for the given organization ID."""
    return UserProfile.objects.filter(organization_id=organization_id).values_list('user', flat=True)


def parse_compliance_map(compliance_maps):
    """
    Parses the ComplianceMap strings and aggregates the data for regulation names and URLs.
    Args:
        compliance_maps (Iterable[str]): An iterable of compliance map strings.
    Returns:
        List of dictionaries: Each dictionary contains {regulation name, count, url}.
    """
    regulation_dict = {}
    for compliance_map in compliance_maps:
        if compliance_map and compliance_map != "No Compliance Map Saved":
            items = compliance_map.split("||")
            for item in items:
                parts = item.split(">")
                if len(parts) >= 3:
                    regulation = parts[1].strip()
                    url = parts[2].strip()
                    key = (regulation, url)
                    if key in regulation_dict:
                        regulation_dict[key]['count'] += 1
                    else:
                        regulation_dict[key] = {'regulation': regulation, 'url': url, 'count': 1}

    # Convert the dictionary to a list of dictionaries and sort by count in descending order
    sorted_regulation_list = sorted(regulation_dict.values(), key=lambda x: x['count'], reverse=True)
    return sorted_regulation_list


def clean_text(text):
    """Clean string by escaping problematic characters."""
    if text is None:
        return text
    return text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').strip()


@login_required()
def dashboardhome(request):
    user_organization_id = get_user_organization_id(request)

    organization_users = get_organization_users(user_organization_id)
    # Set the session variable
    request.session['user_organization'] = user_organization_id

    try:
        org_defaults = OrganizationDefaults.objects.get(organization_id=user_organization_id)
        # Set organization defaults in the session
        request.session['organization_defaults'] = {
            'industry': org_defaults.industry_id,
            'language': org_defaults.language,
            'annual_revenue': org_defaults.annual_revenue,
            'cyber_insurance': org_defaults.cyber_insurance,
            'insurance_deductible': org_defaults.insurance_deductible,
            'employees': org_defaults.employees,
        }
    except OrganizationDefaults.DoesNotExist:
        # Handle the case where the organization does not have defaults set
        request.session['organization_defaults'] = {}

    # Filters added to all model queries to respect the organization of the user
    filters = {'organization_id': user_organization_id, 'deleted': 0}
    records_by_business_unit_type = RAWorksheet.objects.filter(**filters).values('BusinessUnitType').annotate(
        count=Count('ID'))
    records_by_status_flag = RAWorksheet.objects.filter(**filters).values('StatusFlag').annotate(count=Count('ID'))
    records_by_trigger = RAWorksheet.objects.filter(**filters).values('RATrigger').annotate(count=Count('ID'))
    records_by_industry = RAWorksheet.objects.filter(**filters).values('industry').annotate(count=Count('ID'))

    scenarios = RAWorksheetScenario.objects.select_related('RAWorksheetID').filter(
        RAWorksheetID__organization_id=user_organization_id)

    records_by_risk_score = scenarios.values('RiskScore').annotate(count=Count('ID'))
    scenario_risk_status = scenarios.values('RiskStatus').annotate(count=Count('ID'))

    open_raws_count = RAWorksheet.objects.filter(**filters).exclude(StatusFlag="Closed").count()

    total_scenario_cost = scenarios.aggregate(sum_scenarioCost=Sum('scenarioCost'))['sum_scenarioCost']

    try:
        if total_scenario_cost >= 1000000:
            formatted_scenario_cost = "${:.2f}M".format(total_scenario_cost / 1000000)
        elif total_scenario_cost >= 1000:
            formatted_scenario_cost = "${:.2f}K".format(total_scenario_cost / 1000)
        else:
            formatted_scenario_cost = "${:.2f}".format(total_scenario_cost)
    except Exception:
        formatted_scenario_cost = "$--"

    raw_count = RAWorksheet.objects.filter(**filters).count()

    bia_summary = defaultdict(int)
    raws = RAWorksheet.objects.filter(**filters)
    for raw in raws:
        business_impact_score = calculate_business_impact_score(raw.ID)
        bia_text = map_score_to_text(business_impact_score)
        bia_summary[bia_text] += 1
    bia_summary = json.dumps(dict(bia_summary))

    pha_bia_summary = defaultdict(int)
    phas = tblCyberPHAHeader.objects.filter(UserID__in=organization_users, Deleted=0)
    pha_ids = phas.values_list('ID', flat=True)

    # Fetching the latest updates from the audit log
    latest_updates = auditlog.objects.filter(cyberPHAID_id__in=pha_ids).annotate(
        latest_update=Max('timestamp'),
        updater_first_name=F('user__first_name'),
        updater_last_name=F('user__last_name')
    ).values('cyberPHAID_id', 'latest_update', 'updater_first_name', 'updater_last_name')

    # Convert query result into a dictionary for easy lookup
    latest_updates_dict = {update['cyberPHAID_id']: update for update in latest_updates}

    # Iterating over saved scenarios to append additional information
    for pha in phas:
        id_str = str(pha.ID)
        formatted_id = f"{id_str[:3]}-{id_str[3:6]}-{id_str[6:]}"
        pha.formatted_id = formatted_id

        # Retrieve update info if available
        update_info = latest_updates_dict.get(pha.ID, {})

        # Extract and format the last update timestamp if available
        if 'latest_update' in update_info:
            pha.last_update = update_info['latest_update'].strftime('%m/%d/%Y %H:%M') if update_info[
                'latest_update'] else ''
        else:
            pha.last_update = ''

        # Concatenate user names if available
        if 'updater_first_name' in update_info and 'updater_last_name' in update_info:
            pha.updater_name = f"{update_info.get('updater_first_name', '')} {update_info.get('updater_last_name', '')}".strip()
        else:
            pha.updater_name = ''

    for pha in phas:
        business_impact_score = calculate_pha_business_impact_score(pha.ID)
        bia_text = map_score_to_text(business_impact_score)
        pha_bia_summary[bia_text] += 1
    pha_bia_summary = json.dumps(dict(pha_bia_summary))

    pha_risk_summary = defaultdict(int)
    pha_risks = tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
    for pha_risk in pha_risks:
        risk_text = pha_risk.RRa
        pha_risk_summary[risk_text] += 1
    pha_risk_summary = json.dumps(dict(pha_risk_summary))
    compliance_maps = pha_risks.values_list('compliance_map', flat=True)
    compliance_summary = parse_compliance_map(compliance_maps)
    # raw_scenarios = RAWorksheetScenario.objects.all()
    scenarios_count = RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).count()

    cyberpha_count = tblCyberPHAHeader.objects.filter(UserID__in=organization_users, Deleted=0).count()
    cyberpha_scenario_count = tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0).count()

    safety_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'SafetyScore').annotate(count=Count('ID')).order_by('SafetyScore'))
    life_scores_list = list(RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
        'lifeScore').annotate(count=Count('ID')).order_by('lifeScore'))

    # Query RAWorksheets along with a count of related RAWorksheetScenario records
    ra_worksheets_with_scenario_count = RAWorksheet.objects.filter(**filters).annotate(
        scenario_count=Count('raworksheetscenario')
    ).values(
        'RATitle', 'StatusFlag', 'RATrigger', 'scenario_count', 'RADescription', 'BusinessUnit'
    )

    # Convert QuerySet to a list of dictionaries for the context
    ra_worksheets_with_scenario_count_list = list(ra_worksheets_with_scenario_count)

    pha_safety_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactSafety')
        .annotate(count=Count('ID'))
        .order_by('impactSafety')
    )

    pha_danger_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactDanger')
        .annotate(count=Count('ID'))
        .order_by('impactDanger')
    )

    pha_environment_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactEnvironment')
        .annotate(count=Count('ID'))
        .order_by('impactEnvironment')
    )

    pha_finance_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactFinance')
        .annotate(count=Count('ID'))
        .order_by('impactFinance')
    )

    pha_production_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactProduction')
        .annotate(count=Count('ID'))
        .order_by('impactProduction')
    )

    pha_reputation_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactReputation')
        .annotate(count=Count('ID'))
        .order_by('impactReputation')
    )

    pha_regulation_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactRegulation')
        .annotate(count=Count('ID'))
        .order_by('impactRegulation')
    )

    pha_data_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactData')
        .annotate(count=Count('ID'))
        .order_by('impactData')
    )

    pha_supply_scores_list = list(
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('impactSupply')
        .annotate(count=Count('ID'))
        .order_by('impactSupply')
    )

    pha_threat_class = (
        tblCyberPHAScenario.objects.filter(userID__in=organization_users, Deleted=0)
        .values('ThreatClass')
        .annotate(total=Count('ThreatClass'))
    )

    environment_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'environmentScore').annotate(count=Count('ID')).order_by('environmentScore'))

    production_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'productionScore').annotate(count=Count('ID')).order_by('productionScore'))

    regulatory_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'regulatoryScore').annotate(count=Count('ID')).order_by('regulatoryScore'))

    data_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'DataScore').annotate(count=Count('ID')).order_by('DataScore'))

    financial_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'FinancialScore').annotate(count=Count('ID')).order_by('FinancialScore'))

    reputation_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'ReputationScore').annotate(count=Count('ID')).order_by('ReputationScore'))

    supply_scores_list = list(
        RAWorksheetScenario.objects.filter(RAWorksheetID__organization=user_organization_id).values(
            'SupplyChainScore').annotate(count=Count('ID')).order_by('SupplyChainScore'))

    # risk assessment facilities
    raw_facilities = RAWorksheet.objects.filter(organization=user_organization_id).values_list('ID', 'BusinessUnit',
                                                                                               'BusinessUnitType')

    # cyberPHA facilities
    pha_facilities = tblCyberPHAHeader.objects.filter(UserID__in=organization_users).values_list('ID', 'FacilityName',
                                                                                                 'FacilityType')

    total_sle = tblCyberPHAScenario.objects.filter(userID__in=organization_users).aggregate(sum_sle=Sum('sle'))[
        'sum_sle']

    #  try:
    #    formatted_sle = "${:,.0f}".format(total_sle)
    #    formatted_sle= "$--"

    # total_scenario_cost = scenarios.aggregate(sum_scenarioCost=Sum('scenarioCost'))['sum_scenarioCost']

    try:
        if total_sle >= 1000:
            formatted_sle = "${:.2f}M".format(total_sle / 1000000)
        elif total_scenario_cost >= 1000:
            formatted_sle = "${:.2f}K".format(total_sle / 1000)
        else:
            formatted_sle = "${:.2f}".format(total_sle)
    except Exception:
        formatted_sle = "$--"

    ra_actions_records_count = RAActions.objects.filter(organizationid=user_organization_id).exclude(
        actionStatus="Closed").count()

    num_records = raw_facilities.count()
    categories = ["Low", "Low/Medium", "Medium", "Medium/High", "High", "Very High"]

    # Convert the likelihood to one of the required categories
    def get_likelihood_category(likelihood):
        if likelihood < 20:
            return "Low"
        elif likelihood < 40:
            return "Low/Medium"
        elif likelihood < 60:
            return "Medium"
        elif likelihood < 80:
            return "Medium/High"
        elif likelihood <= 95:
            return "High"
        else:
            return "Very High"

    # Create a defaultdict to hold the counts
    heatmap_counts = defaultdict(int)

    scenarios = tblCyberPHAScenario.objects.filter(userID__in=organization_users)
    for scenario in scenarios:
        likelihood_category = get_likelihood_category(scenario.likelihood)
        heatmap_counts[(scenario.RRa, likelihood_category)] += 1

    heatmap_data = {}
    for key, value in heatmap_counts.items():
        if key[0] not in heatmap_data:
            heatmap_data[key[0]] = {}
        heatmap_data[key[0]][key[1]] = value

    # Query the last 100 audit logs for this organization
    last_100_logs = auditlog.objects.filter(
        user_profile__organization_id=user_organization_id
    ).order_by('-timestamp')[:100]

    # get the moderation tasks for the current user
    moderation_tasks = CyberPHAModerators.objects.filter(moderator=request.user)
    moderation_details = []

    for task in moderation_tasks:
        # Get the related CyberPHAHeader
        pha_header = task.pha_header

        # Count the number of draft scenarios for this CyberPHA
        draft_scenario_count = tblCyberPHAScenario.objects.filter(
            CyberPHA=pha_header, scenario_status='Draft'
        ).count()

        # Add the details to the list
        moderation_details.append({
            'cyberpha_title': pha_header.title,
            'target_date': task.target_date,
            'draft_scenario_count': draft_scenario_count
        })

    groups_with_cyberphas = []
    for group in CyberPHA_Group.objects.all():
        cyberphas = group.tblcyberphaheader_set.filter(UserID__in=organization_users)
        # Only append the group if it has associated tblCyberPHAHeader records within the organization
        if cyberphas.exists():
            groups_with_cyberphas.append({
                'id': group.id,
                'group_name': group.name,
                'cyberphas': [{'facility_name': cyberpha.FacilityName} for cyberpha in cyberphas]
            })
    worksheets_to_approve = RAWorksheet.objects.filter(
        Q(approver=request.user),
        Q(approval_status='Pending') | Q(approval_status='Rejected')
    )

    # Check if there are any worksheets to approve
    if worksheets_to_approve.count != 0:
        worksheets_to_approve_list = list(worksheets_to_approve.values('ID', 'RATitle', 'RADate', 'StatusFlag'))
    else:
        worksheets_to_approve_list = "No approvals for action"

    # Fetch facilities data
    facilities_data = tblCyberPHAHeader.objects.filter(UserID__in=organization_users, Deleted=0).values(
        'ID', 'FacilityName', 'facilityLat', 'facilityLong', 'facilityAddress',
        'facilityCity', 'facilityState', 'facilityCode', 'country'
    )

    # Convert QuerySet to a list of dictionaries
    facilities_list = list(facilities_data)
    enhanced_facilities = enhance_facilities_with_alerts(facilities_list, '8236a6bcf0f655f403719ef41eeb516b')

    facilities_aggregate = tblCyberPHAHeader.objects.filter(
        UserID__in=organization_users,
        Deleted=0
    ).values('FacilityName').annotate(
        TotalRevenue=Sum('annual_revenue')
    ).aggregate(
        UniqueFacilities=Count('FacilityName', distinct=True),
        TotalFacilityRevenue=Sum('TotalRevenue')
    )
    # Format total revenue in millions with 'm' suffix
    if facilities_aggregate['TotalFacilityRevenue']:
        total_facility_revenue = "${:,.0f}m".format(facilities_aggregate['TotalFacilityRevenue'] / 1_000_000)
    else:
        total_facility_revenue = "$0m"

    # Serialize data for JavaScript usage using json.dumps
    facilities_json = json.dumps(enhanced_facilities)
    context = {
        'records_by_business_unit_type': list(records_by_business_unit_type),
        'records_by_status_flag': list(records_by_status_flag),
        'records_by_trigger': list(records_by_trigger),
        'records_by_industry': list(records_by_industry),
        'scenario_risk_status': list(scenario_risk_status),
        'records_by_risk_score': records_by_risk_score,
        'raw_count': raw_count,
        'scenarios_count': scenarios_count,
        'cyberpha_count': cyberpha_count,
        'cyberpha_scenario_count': cyberpha_scenario_count,
        'doughnut_data': safety_scores_list,
        'formatted_sle': formatted_sle,
        'formatted_scenario_cost': formatted_scenario_cost,
        'ra_actions_records_count': ra_actions_records_count,
        'open_raws_count': open_raws_count,
        'pha_threat_class': pha_threat_class,
        'total_sle': total_sle,
        'total_scenario_cost': total_scenario_cost,
        'heatmap_data': json.dumps(heatmap_data),
        'bia_summary': bia_summary,
        'pha_bia_summary': pha_bia_summary,
        'pha_risk_summary': pha_risk_summary,
        'scenarios': scenarios,
        'phas': phas,
        'last_100_logs': last_100_logs,
        'moderation_tasks': moderation_details,
        'groups_with_cyberphas': groups_with_cyberphas,
        'worksheets_to_approve': worksheets_to_approve_list,
        'ra_worksheets_with_scenario_count': ra_worksheets_with_scenario_count_list,
        'compliance_summary': compliance_summary,
        'facilities_data': facilities_json,
        'unique_facility_count': facilities_aggregate['UniqueFacilities'],
        'total_facility_revenue': total_facility_revenue
    }

    return render(request, 'dashboard.html', context)


def process_data(data):
    hierarchy = {}

    for entry in data:
        country = entry['country']
        industry = entry['Industry']
        facility = entry['FacilityType']

        if country not in hierarchy:
            hierarchy[country] = {}

        if industry not in hierarchy[country]:
            hierarchy[country][industry] = {}

        if facility not in hierarchy[country][industry]:
            hierarchy[country][industry][facility] = 1
        else:
            hierarchy[country][industry][facility] += 1

    return hierarchy_to_list(hierarchy)


def hierarchy_to_list(hierarchy):
    result = []
    for country, industries in hierarchy.items():
        country_node = {"name": country, "children": []}
        for industry, facilities in industries.items():
            industry_node = {"name": industry, "children": []}
            for facility, count in facilities.items():
                facility_node = {"name": facility, "value": count}
                industry_node["children"].append(facility_node)
            country_node["children"].append(industry_node)
        result.append(country_node)

    return result


def calculate_business_impact_score(ra_worksheet_id):
    # Define the weights for each field
    field_weights = {
        'ReputationScore': 1,
        'SafetyScore': 2,
        'lifeScore': 2,
        'FinancialScore': 1,
        'DataScore': 1,
        'SupplyChainScore': 1,
        'productionScore': 1,
        'environmentScore': 1,
        'regulatoryScore': 1,
    }

    try:
        # Retrieve the RAWorksheet with the given ID
        ra_worksheet = RAWorksheet.objects.get(ID=ra_worksheet_id)

        # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
        scenarios = RAWorksheetScenario.objects.filter(RAWorksheetID=ra_worksheet)

        # Initialize a total score
        total_score = 0

        # Calculate the total score based on weighted fields for each scenario
        for scenario in scenarios:
            scenario_score = 0
            for field, weight in field_weights.items():
                # Get the value of the field from the scenario
                field_value = getattr(scenario, field)
                # Convert it to a numeric score (assuming it's an integer out of 10)
                numeric_score = int(field_value)
                # Add the weighted score to the scenario score
                scenario_score += numeric_score * weight

            # Add the scenario score to the total score
            total_score += scenario_score

        return total_score

    except RAWorksheet.DoesNotExist:
        return None


def calculate_pha_business_impact_score(pha_id):
    # Define the weights for each field
    field_weights = {
        'impactReputation': 1,
        'impactSafety': 2,
        'impactDanger': 2,
        'impactFinance': 1,
        'impactData': 1,
        'impactSupply': 1,
        'impactProduction': 1,
        'impactEnvironment': 1,
        'impactRegulation': 1,
    }

    # Retrieve the RAWorksheet with the given ID
    pha_header = tblCyberPHAHeader.objects.get(ID=pha_id)

    # Retrieve all associated RAWorksheetScenario instances for this RAWorksheet
    scenarios = tblCyberPHAScenario.objects.filter(CyberPHA=pha_header)

    # Initialize a total score
    total_score = 0

    # Calculate the total score based on weighted fields for each scenario
    for scenario in scenarios:
        scenario_score = 0
        for field, weight in field_weights.items():
            # Get the value of the field from the scenario
            field_value = getattr(scenario, field)
            # Convert it to a numeric score (assuming it's an integer out of 10)
            numeric_score = int(field_value)
            # Add the weighted score to the scenario score
            scenario_score += numeric_score * weight

        # Add the scenario score to the total score
        total_score += scenario_score

    return total_score


def map_score_to_text(score):
    if score < 20:
        return 'Low'
    elif score < 40:
        return 'Low/Medium'
    elif score < 60:
        return 'Medium'
    elif score < 80:
        return 'Medium/High'
    elif score < 95:
        return 'High'
    else:
        return 'Very High'


def get_current_user_organization_id(user):
    try:
        user_profile = UserProfile.objects.get(user=user)
        return user_profile.organization_id
    except UserProfile.DoesNotExist:
        # Return None or handle it as per your application's requirement
        return None


def get_likelihood_category(likelihood):
    if likelihood < 20:
        return "Low"
    elif likelihood < 40:
        return "Low/Medium"
    elif likelihood < 60:
        return "Medium"
    elif likelihood < 80:
        return "Medium/High"
    elif likelihood <= 95:
        return "High"
    else:
        return "Very High"


def get_heatmap_records(request):
    x = request.GET.get('x')  # Likelihood category
    y = request.GET.get('y')  # RRa

    user_organization_id = get_user_organization_id(request)
    organization_users = get_organization_users(user_organization_id)
    # Filter scenarios based on the RRa and the likelihood category
    scenarios = tblCyberPHAScenario.objects.filter(RRa=y, userID__in=organization_users).annotate(
        likelihood_category=Case(
            When(likelihood__lt=20, then=Value('Low')),
            When(likelihood__lt=40, then=Value('Low/Medium')),
            When(likelihood__lt=60, then=Value('Medium')),
            When(likelihood__lt=80, then=Value('Medium/High')),
            When(likelihood__lte=95, then=Value('High')),
            default=Value('Very High'),
            output_field=CharField(),
        )
    ).filter(likelihood_category=x)

    # Prepare the data to be returned
    data = []
    for scenario in scenarios:
        header = scenario.CyberPHA
        data.append({
            'tblCyberPHAHeader_ID': header.ID,
            'title': header.title,
            'FacilityName': header.FacilityName,
            'scenario': scenario.Scenario,
            'RRA': scenario.RRa
        })

    return JsonResponse({'data': data})


@login_required
def get_scenarios_for_regulation(request):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and request.method == "GET":
        regulation_name = request.GET.get('regulation_name', '')
        user_id_str = str(request.user.id)  # Convert user ID to string

        # Filter scenarios by the current user's ID and the compliance map containing the regulation name
        scenarios = tblCyberPHAScenario.objects.filter(
            compliance_map__icontains=regulation_name,
            CyberPHA__UserID=user_id_str  # Filter by the user ID
        ).select_related('CyberPHA').values(
            'CyberPHA__ID', 'CyberPHA__title', 'Scenario'
        )

        scenarios_list = list(scenarios)

        return JsonResponse(scenarios_list, safe=False)
    return JsonResponse({"error": "Invalid request"}, status=400)


from django.contrib.auth.models import User


@login_required
def get_all_groups_scores(request):
    user = request.user  # Get the currently logged-in user
    user_organization_id = get_user_organization_id(request)  # Retrieve organization ID using the custom function

    # Fetch all groups that belong to the user's organization
    all_groups = CyberPHA_Group.objects.filter(organization_id=user_organization_id).distinct()
    print(all_groups)
    all_groups_data = []

    for group in all_groups:
        # Fetch related tblCyberPHAHeader IDs for the group
        # Ensuring we are filtering CyberPHA headers based on organization users
        organization_users = User.objects.filter(userprofile__organization_id=user_organization_id).values_list('id',
                                                                                                                flat=True)
        cyberpha_ids = tblCyberPHAHeader.objects.filter(groups=group, UserID__in=organization_users).values_list('ID',
                                                                                                                 flat=True)

        # Fetch scenarios related to those CyberPHAHeader IDs
        scenarios = tblCyberPHAScenario.objects.filter(CyberPHA_id__in=cyberpha_ids)

        if scenarios.exists():
            avg_scores = {
                'id': group.id,
                'group_name': group.name,
                'avg_scores': [
                    {'name': 'Safety',
                     'value': round(scenarios.aggregate(Avg('impactSafety'))['impactSafety__avg'] or 0, 2)},
                    {'name': 'Danger',
                     'value': round(scenarios.aggregate(Avg('impactDanger'))['impactDanger__avg'] or 0, 2)},
                    {'name': 'Production',
                     'value': round(scenarios.aggregate(Avg('impactProduction'))['impactProduction__avg'] or 0, 2)},
                    {'name': 'Finance',
                     'value': round(scenarios.aggregate(Avg('impactFinance'))['impactFinance__avg'] or 0, 2)},
                    {'name': 'Reputation',
                     'value': round(scenarios.aggregate(Avg('impactReputation'))['impactReputation__avg'] or 0, 2)},
                    {'name': 'Environment',
                     'value': round(scenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg'] or 0, 2)},
                    {'name': 'Regulation',
                     'value': round(scenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg'] or 0, 2)},
                    {'name': 'Data', 'value': round(scenarios.aggregate(Avg('impactData'))['impactData__avg'] or 0, 2)},
                    {'name': 'Supply',
                     'value': round(scenarios.aggregate(Avg('impactSupply'))['impactSupply__avg'] or 0, 2)}
                ]
            }
            all_groups_data.append(avg_scores)
            print(all_groups_data)

    return JsonResponse({'allGroupsData': all_groups_data})


def get_group_report(request):
    group_id = request.GET.get('group_id')
    group = CyberPHA_Group.objects.get(id=group_id)
    group_name = group.name
    cyberphas = tblCyberPHAHeader.objects.filter(groups=group)

    # Fetch the required fields for each tblCyberPHAHeader in the selected group
    cyberphas_details = cyberphas.values(
        'title', 'FacilityName', 'FacilityType', 'Industry', 'EmployeesOnSite'
    )

    # Get IDs of tblCyberPHAHeader objects to filter tblCyberPHAScenario
    cyberpha_ids = cyberphas.values_list('ID', flat=True)
    avg_pha_Score = round(cyberphas.aggregate(Avg('pha_score'))['pha_score__avg'] or 0, 2)
    avg_assessment_Score = round(cyberphas.aggregate(Avg('assessment'))['assessment__avg'] or 0, 2)
    scenarios = tblCyberPHAScenario.objects.filter(CyberPHA_id__in=cyberpha_ids)
    avg_impactSafety = round(scenarios.aggregate(Avg('impactSafety'))['impactSafety__avg'] or 0, 2)
    avg_impactDanger = round(scenarios.aggregate(Avg('impactDanger'))['impactDanger__avg'] or 0, 2)
    avg_impactProduction = round(scenarios.aggregate(Avg('impactProduction'))['impactProduction__avg'] or 0, 2)
    avg_impactFinance = round(scenarios.aggregate(Avg('impactFinance'))['impactFinance__avg'] or 0, 2)
    avg_impactReputation = round(scenarios.aggregate(Avg('impactReputation'))['impactReputation__avg'] or 0, 2)
    avg_impactEnvironment = round(scenarios.aggregate(Avg('impactEnvironment'))['impactEnvironment__avg'] or 0, 2)
    avg_impactRegulation = round(scenarios.aggregate(Avg('impactRegulation'))['impactRegulation__avg'] or 0, 2)
    avg_impactData = round(scenarios.aggregate(Avg('impactData'))['impactData__avg'] or 0, 2)
    avg_impactSupply = round(scenarios.aggregate(Avg('impactSupply'))['impactSupply__avg'] or 0, 2)
    avg_sle = round(scenarios.aggregate(Avg('sle'))['sle__avg'] or 0, 0)

    return JsonResponse({
        'cyberphas': list(cyberphas_details),
        'avg_scores': [
            {'name': 'Safety', 'value': avg_impactSafety},
            {'name': 'Danger', 'value': avg_impactDanger},
            {'name': 'Production', 'value': avg_impactProduction},
            {'name': 'Finance', 'value': avg_impactFinance},
            {'name': 'Reputation', 'value': avg_impactReputation},
            {'name': 'Environment', 'value': avg_impactEnvironment},
            {'name': 'Regulation', 'value': avg_impactRegulation},
            {'name': 'Data', 'value': avg_impactData},
            {'name': 'Supply', 'value': avg_impactSupply},
        ],
        'avg_pha_Score': avg_pha_Score,
        'avg_sle': avg_sle,
        'group_name': group_name
    })
