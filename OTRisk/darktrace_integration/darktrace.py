# darktrace.py
import logging
import hmac
import hashlib
from urllib.error import HTTPError

import requests
import datetime
from typing import Dict, Optional, List


class Darktrace:
    TIMEOUT = 5  # per request, in seconds

    @classmethod
    def initialize_from_string(
            cls,
            host: str,
            public_token: str,
            private_token: str,
            ssl: bool = False,
            timeout: int = TIMEOUT) -> "Darktrace":
        return cls(host, public_token, private_token, ssl, timeout)

    def __init__(
            self,
            host: str,
            public_token: str,
            private_token: str,
            ssl: bool = False,
            timeout: int = TIMEOUT
    ):
        ...
        self.timeout = timeout  # Set the timeout here
        ...
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

    def get_aianalyst_incidents(self, init_date):
        query_uri = f"/aianalyst/incidents?from={init_date.isoformat()}"
        return self.get(query_uri)
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
            timeout=self.timeout
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
