import random

from django.shortcuts import render
from django.http import HttpResponse
from urllib3.exceptions import InsecureRequestWarning

from OTRisk.models.darktraceapi import Darktrace
import logging
import datetime
import requests
from django.shortcuts import render
from django.http import JsonResponse
import openai

import urllib3
import logging

from accounts.models import UserProfile


def network_risk_profile(request):
    darktrace = Darktrace.initialize_from_string(
        host='https://usw1-54655-01.cloud.darktrace.com',
        public_token='89521fffc67850d258904a64730556204dea6d3d',
        private_token='ba60376e3dff79ad2396bbccd1591ea0f14c23c7',
        ssl=True
    )

    try:
        # Test the connection to ensure it's working
        darktrace.test_connection()

        # Fetch AI Analyst incidents
        init_date = datetime.datetime.strptime("2023-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
        incidents = darktrace.get(f"/aianalyst/incidents?from={init_date.isoformat()}")

        if incidents is None:
            raise ValueError(
                "No data returned from Darktrace API. Possible authentication issue or incorrect endpoint.")

        # Fetch network assets
        assets = darktrace.get("/devices")
        breaches = darktrace.get_model_breaches()
        if assets is None:
            raise ValueError(
                "No data returned from Darktrace API for assets. Possible authentication issue or incorrect endpoint.")

        # Process incidents to display
        incident_list = process_incidents(incidents)
        asset_list, asset_attributes, asset_values = process_assets(assets)

        if breaches is None:
            raise ValueError(
                "No data returned from Darktrace API. Possible authentication issue or incorrect endpoint.")

            # Process breaches to display
        breach_list = process_breaches(breaches)

        return render(request, 'darktrace_risk_profile.html', {
            'incident_list': incident_list,
            'asset_list': asset_list,
            'asset_attributes': asset_attributes,
            'asset_values': asset_values,
            'breach_list': breach_list
        })
    except Exception as e:

        return HttpResponse(f"An error occurred: {e}", status=500)


def process_incidents(incidents):
    # Example processing logic
    return incidents


def process_assets(assets):
    # Get all unique attributes across all assets
    asset_attributes = set()
    for asset in assets:
        asset_attributes.update(asset.keys())

    # Convert the set to a sorted list for consistent ordering
    asset_attributes = sorted(asset_attributes)

    # Ensure each asset has all attributes
    asset_values = []
    for asset in assets:
        row = []
        for attribute in asset_attributes:
            row.append(asset.get(attribute, None))
        asset_values.append(row)

    return assets, asset_attributes, asset_values

def process_breaches(breaches):
    # Process breaches if necessary
    return breaches

