from celery import shared_task
import json
import openai

from accounts.models import UserProfile  # Adjust based on your actual model paths
from OTRisk.models.Model_CyberPHA import ScenarioBuilder_AnalysisResult

from .pha_views import get_api_key, is_inappropriate


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


@shared_task
def analyze_scenario_task(user_id, scenario, investments_data, facility_type, industry):
    openai_api_key = get_api_key('openai')
    openai.api_key = openai_api_key
    existing_results = ScenarioBuilder_AnalysisResult.objects.filter(user_id=user_id)
    if existing_results.exists():
        # If results exist, no further processing is needed
        return
    try:
        user_profile = UserProfile.objects.get(user_id=user_id)
        organization_id = user_profile.organization.id
    except UserProfile.DoesNotExist:
        organization_id = None

    investments = json.loads(investments_data) if investments_data else []

    investment_statement = "Investments have been made in:\n"
    for idx, investment in enumerate(investments, start=1):
        investment_statement += f"{idx}: Investment Type:{investment['type']}, Vendor:{investment['vendor_name']}, Product:{investment['product_name']}, Investment date:{investment['date']}.\n"

    if is_inappropriate(scenario):
        return {'error': 'Scenario contains inappropriate terms'}

    validation_prompt = f"""
    Evaluate if the following text represents a coherent and plausible cybersecurity scenario, or OT incident scenario, or industrial incident scenario: '{scenario}'. Respond yes if valid, no if invalid.
    """

    validation_response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "system", "content": validation_prompt}],
        max_tokens=50,
        temperature=0.7
    )

    if "yes" in validation_response.choices[0].message.content.lower():
        system_message = f"""
        Analyze the following cybersecurity scenario at a {facility_type} in the {industry} industry: '{scenario}'. For each factor listed below, provide a score out of 10 for impact severity and a very concise narrative of 30 words or less. Format your response with clear delimiters as follows: 'Factor: [Factor Name] | Score: X/10 | Narrative: [Explanation]'.

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

        response = openai.ChatCompletion.create(
            model=get_api_key('OpenAI_Model'),
            messages=[{"role": "system", "content": system_message}],
            max_tokens=2000,
            temperature=0.1
        )

        consequence_text = response.choices[0].message.content

        parsed_consequences = parse_consequences(
            consequence_text)  # Ensure this utility function is implemented to parse the response

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

        investment_impact_response = openai.ChatCompletion.create(
            model=get_api_key('OpenAI_Model'),
            messages=[{"role": "system", "content": investment_impact_prompt}],
            max_tokens=400,
            temperature=0.1
        )

        investment_impact_text = investment_impact_response.choices[0].message.content

        ScenarioBuilder_AnalysisResult.objects.create(
            user_id=user_id,
            scenario=scenario,
            consequences=json.dumps(parsed_consequences),  # Assuming this is a JSON-serializable object
            investment_impact=investment_impact_text
        )
    else:
        return {'error': 'Not a valid scenario'}
