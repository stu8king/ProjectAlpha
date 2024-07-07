import datetime
from typing import Any, Dict, Optional, List
from .darktrace import Darktrace


class IntelFeed:

    def __init__(self, session: Darktrace):
        self.session = session
        self.BASE_ENDPOINT = "/intelfeed"

    def get_watched_domains(self) -> List[Dict[str, Any]]:
        """
            Returns:
                List[Dict[str, Any]]: Watched Domains.
        """
        result = self.session.get(self.BASE_ENDPOINT)
        if result and isinstance(result, dict) and "watched_domains" in result:
            return result["watched_domains"]
        return []

    def post_watched_domain(self, endpoint: str):
        """
            Summary:
                    Post to Watched Domain List.
            Input:
                    str: endpoint.
        """
        self.session.post(
            self.BASE_ENDPOINT,
            f"addentry={endpoint}")

    def get_risk_indicators_for_business(self, business_name: str, init_date: datetime.datetime) -> List[
        Dict[str, Any]]:
        """
        Summary:
            Get risk indicators for a given business name.
        Input:
            str: business_name - The name of the business to look up.
            datetime: init_date - The start date for searching incidents.
        Returns:
            List[Dict[str, Any]]: List of risk indicators related to the business name.
        """
        incidents = self.session.get_aianalyst_incidents(init_date)
        risk_indicators = []

        if incidents and isinstance(incidents, dict) and "incidents" in incidents:
            for incident in incidents["incidents"]:
                if business_name.lower() in incident.get("description", "").lower():
                    risk_indicators.append(incident)

        return risk_indicators