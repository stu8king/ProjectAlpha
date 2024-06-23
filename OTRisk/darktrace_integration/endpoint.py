# endpoint.py
from typing import Dict, Any
from .darktrace import Darktrace
import logging

class Endpoint:
    @classmethod
    def get_details(cls, session: Darktrace, ip: str) -> Dict[str, Any]:
        query_uri = f"/endpointdetails?ip={ip}"
        response = session.get(query_uri)
        if not isinstance(response, dict):
            logging.error(f"Invalid response for get_details: {response}")
            return {}
        return response

    @classmethod
    def get_largest_data_transfers(cls, session: Darktrace, ip: str) -> Dict[str, Any]:
        query_uri = f"/network?ip={ip}"
        response = session.get(query_uri)
        if not isinstance(response, dict):
            logging.error(f"Invalid response for get_largest_data_transfers: {response}")
            logging.error(f"Raw Response for get_largest_data_transfers: {response}")
            return {}
        return response


