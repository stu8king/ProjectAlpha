# middleware.py

from datetime import datetime, timedelta
from django.conf import settings
from django.contrib import auth


class SessionIdleTimeout:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is authenticated and there's a last request timestamp
        if request.user.is_authenticated and 'last_request' in request.session:
            elapsed_time = datetime.now() - datetime.strptime(request.session['last_request'], "%Y-%m-%d %H:%M:%S.%f")

            # If elapsed time is greater than session timeout, log out the user
            if elapsed_time > timedelta(seconds=settings.SESSION_COOKIE_AGE):
                auth.logout(request)

        # Update the last request timestamp
        request.session['last_request'] = str(datetime.now())

        response = self.get_response(request)
        return response
