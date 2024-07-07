import logging
import hmac
import hashlib
from urllib.error import HTTPError

import requests
import datetime
from typing import Dict, Optional, List, Any
from OTRisk.darktrace_integration import Darktrace
from OTRisk.darktrace_integration.device import Device


class DarktraceAPI:
    TIMEOUT = 5  # per request, in seconds

    @classmethod
    def initialize_from_string(
            cls,
            host: str,
            public_token: str,
            private_token: str,
            ssl: bool = False,
            timeout: int = TIMEOUT) -> "DarktraceAPI":
        return cls(host, public_token, private_token, ssl)

    def __init__(
            self,
            host: str,
            public_token: str,
            private_token: str,
            ssl: bool = False,
            timeout: int = TIMEOUT
    ):
        if host.startswith("http://"):
            host = host.replace("http", "https", 1)
        if not host.startswith("https://"):
            host = f"https://{host}"
        self.host = host
        self.public_token = public_token
        self.private_token = private_token
        self.verify_ssl = ssl
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {self.public_token}:{self.private_token}'
        })

    def create_signature(
            self,
            public_token: str,
            private_token: str,
            query_uri: str,
            date: str
    ) -> str:
        return hmac.new(
            private_token.encode("ASCII"),
            f"{query_uri}\n{public_token}\n{date}".encode("ASCII"),
            hashlib.sha1
        ).hexdigest()

    def create_headers(self, query_uri: str) -> Dict[str, str]:
        date = datetime.datetime.utcnow().isoformat(timespec="auto")
        signature = self.create_signature(
            self.public_token,
            self.private_token,
            query_uri,
            date
        )
        return {
            "DTAPI-Token": self.public_token,
            "DTAPI-Date": date,
            "DTAPI-Signature": signature
        }

    def _request(
            self,
            query_uri: str,
            data: Optional[str] = None,
            headers: Optional[Dict[str, str]] = None,
            method: str = "GET"
    ) -> Optional[dict]:

        logging.debug(f"{method} {self.host}{query_uri}")
        response = self.session.request(
            method=method,
            url=self.host + query_uri,
            data=data,
            headers={
                **self.create_headers(query_uri),
                **(headers or {})
            },
            verify=self.verify_ssl,
            timeout=self.TIMEOUT
        )

        logging.debug(f"Response Status Code: {response.status_code}")
        logging.debug(f"Response Content: {response.text}")

        if response.status_code == 200:
            try:
                return response.json()
            except requests.exceptions.JSONDecodeError:
                logging.error("JSON Decode Error - Response content is not JSON")
                return None
        elif response.status_code == 302:
            if response.text == "Found. Redirecting to /login":
                raise HTTPError("Invalid Endpoint. Please contact your Darktrace representative.")
            elif response.text == "Found. Redirecting to /403":
                raise HTTPError("User has insufficient permissions to access the API endpoint.")
        elif response.status_code == 404:
            raise HTTPError("Error 404. Please contact your Darktrace representative.")
        elif response.status_code == 400:
            values = response.json().values()
            if "API SIGNATURE ERROR" in values:
                raise HTTPError("API Signature Error. You have invalid credentials in your config.")
            elif "API DATE ERROR" in values:
                raise HTTPError(
                    "API Date Error. Check that the time on this machine matches that of the Darktrace instance.")
        elif response.status_code >= 300:
            print("Error {}".format(response.status_code))
            print("An error occurred. Please contact your Darktrace representative.")
        response.raise_for_status()

    def get(self, query_uri: str) -> Optional[dict]:
        return self._request(query_uri)

    def post(self, query: str, data: str) -> Optional[dict]:
        query_uri = f"{query}?{data}"
        return self._request(
            query_uri, method="POST", data=data, headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})

    def test_connection(self):
        try:
            test = self.get("/status?format=json")
            if test:
                logging.info(
                    "Good Connection to the Darktrace Platform. Ready to use more functions")
            else:
                logging.error("Connection test failed: No data returned")
        except Exception:
            logging.error(
                "An error occurred while testing your connection. Please confirm your config is correct and any proxies setup.")

    def get_aianalyst_incidents(self, init_date):
        query_uri = f"/aianalyst/incidents?from={init_date.isoformat()}"
        return self.get(query_uri)

    # Add this method to the Darktrace class
    def get_assets(self):
        return self.get("/devices")

    def get_device_details(self, device_id: str) -> Optional[dict]:
        query_uri = f"/devices/{device_id}"
        return self.get(query_uri)

    def get_model_breaches(self, device_id: str) -> List[dict]:
        query_uri = f"/modelbreaches?did={device_id}"
        response = self.get(query_uri)
        if response and isinstance(response, list):
            return response
        return []

    def get_incident_details(self, incident_id: str) -> Optional[dict]:
        query_uri = f"/aianalyst/incidents/{incident_id}"
        return self.get(query_uri)


class AIAnalystIncident:

    def __init__(
            self,
            session: Darktrace,
            id: str,
            summary: str,
            score: int,
            details: Optional[List[dict]],
            related_breaches: Optional[List[dict]],
            breach_identifiers: Optional[List[str]],
            raw: Dict[str, Any]
    ):
        self.id = id
        self.summary = summary
        self.score = score
        self.details = details
        self.related_breaches = related_breaches
        self.breach_identifiers = breach_identifiers
        self._raw = raw
        self.session = session

    @classmethod
    def from_json(cls,
                  session: Darktrace,
                  incident: Dict[str, Any]) -> 'AIAnalystIncident':
        return cls(
            session,
            incident["id"],
            incident.get("summary", ""),
            incident["aiaScore"],
            incident.get("details"),
            incident.get("relatedBreaches"),
            [device.get("identifier") for device in incident.get("breachDevices", [])],
            incident
        )

    @classmethod
    def get_incidents(
            cls,
            session: Darktrace,
            init_date: datetime,
            end_date: datetime
    ) -> List['AIAnalystIncident']:
        epoch = datetime.utcfromtimestamp(0)
        from_time = int((init_date - epoch).total_seconds() * 1000)
        to_time = int((end_date - epoch).total_seconds() * 1000)

        query = session.get(f"/aianalyst/incidents?from={from_time}&to={to_time}")
        return [cls.from_json(session, incident) for incident in query]

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

    def get_risk_indicators_for_business(self, business_name: str, init_date: datetime.datetime) -> List[Dict[str, Any]]:
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