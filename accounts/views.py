import json
import os
from datetime import timedelta, date

import stripe
import stripe.error
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.views import LogoutView
from django.contrib.sessions.models import Session
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db.models import Q, F
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.core.mail import send_mail, get_connection
import string
import random
import phonenumbers
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from accounts.models import UserProfile, SubscriptionType, Organization, LoginAttempt, ActiveUserSession
from OTRisk.models.Model_CyberPHA import auditlog, APIKey
from .forms import CustomUserCreationForm, PasswordChangeForm, SetPasswordForm, \
    SubscriptionForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .forms import PasswordResetRequestForm, PasswordResetForm, Verify2FAForm
from .models import PasswordResetCode
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
from django_otp.plugins.otp_totp.models import TOTPDevice
from .forms import TwoFactorSetupForm, TwoFactorVerifyForm, AuthAppSetupForm, AuthAppVerifyForm
import io
import base64
import pyotp
import qrcode
from django.core.mail import send_mail
from django import forms
from twilio.rest import Client
from io import BytesIO
from django.core.files.base import ContentFile

stripe.api_key = settings.STRIPE_SECRET_KEY


def generate_otp_secret():
    return pyotp.random_base32()


def generate_qr_code_base64(user, otp_secret):
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user.email, issuer_name="AnzenOT"
    )
    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return qr_code_base64


class CustomLogoutView(LogoutView):
    def get(self, request, *args, **kwargs):
        self.next_page = '/'
        return self.post(request, *args, **kwargs)


def send_verification_code_bak(phone_number):
    twilio_sid = get_api_key('twilliosid')
    twilio_token = get_api_key('twilliotoken')
    twilio_number = get_api_key('twillionumber')
    messaging_service_sid = get_api_key('twillio_message_sid')
    code = random.randint(100000, 999999)  # Generate a 6-digit code
    client = Client(twilio_sid, twilio_token)
    message = client.messages.create(
        body=f"Your AnzenOT verification code is: {code}",
        messaging_service_sid=messaging_service_sid,
        from_=twilio_number,
        to=phone_number
    )
    return code


def send_verification_code(phone_number):
    twilio_sid = get_api_key('twilliosid')
    twilio_token = get_api_key('twilliotoken')
    verify_service_sid = get_api_key('twilio_verify_service_sid')  # Your Twilio Verify Service SID

    client = Client(twilio_sid, twilio_token)
    verification = client.verify \
        .services(verify_service_sid) \
        .verifications \
        .create(to=phone_number, channel='sms')  # 'sms' can be replaced with 'call' or other supported channels

    return verification.sid  # Optionally return verification SID for tracking


def two_factor_auth_app_verify(request):
    if request.method == 'POST':
        form = AuthAppVerifyForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            user_profile = UserProfile.objects.get(user=request.user)
            totp = pyotp.TOTP(user_profile.otp_secret)
            if totp.verify(otp_code):
                request.session['two_factor_authenticated'] = True
                return redirect('OTRisk:dashboardhome')  # Change this to the appropriate post-login redirect
            else:
                messages.error(request, "Invalid code. Please try again.")
    else:
        form = AuthAppVerifyForm()

    return render(request, 'accounts/two_factor_auth_app_verify.html', {'form': form})
def two_factor_setup(request):
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            phone_number = form.cleaned_data['phone_number']
            # Generate a TOTP key and send it to the user's phone
            # This is just a basic example, you might want to use services like Twilio to send SMS
            key = TOTPDevice.objects.create(user=request.user, name='default', confirmed=False)
            # Send key to user's phone
            # ...
            return redirect('accounts/two_factor_verify')
    else:
        form = TwoFactorSetupForm()
    return render(request, 'accounts/two_factor_setup.html', {'form': form})


@login_required()
def two_factor_verify(request):

    if request.method == 'GET':
        # Display the form for GET requests
        form = TwoFactorVerifyForm()
        return render(request, 'accounts/verify_2fa.html', {'form': form})

    elif request.method == 'POST':
        # Determine if the request is AJAX based on the Content-Type header
        is_ajax = request.headers.get('Content-Type') == 'application/json'

        if is_ajax:
            # Handle AJAX request with JSON data
            data = json.loads(request.body)
            token = data.get('token')
        else:
            # Handle standard form submission
            form = TwoFactorVerifyForm(request.POST)
            if not form.is_valid():
                messages.error(request, "Invalid form submission.")
                return render(request, 'accounts/verify_2fa.html', {'form': form})
            token = form.cleaned_data['token']

        # Assuming you have a function `get_api_key` to retrieve Twilio API keys
        twilio_sid = get_api_key('twilliosid')
        twilio_token = get_api_key('twilliotoken')
        verify_service_sid = get_api_key('twilio_verify_service_sid')
        client = Client(twilio_sid, twilio_token)

        try:
            verification_check = client.verify.services(verify_service_sid) \
                .verification_checks.create(to=request.user.userprofile.phone_number, code=token)

            if verification_check.status == "approved":
                user_profile = request.user.userprofile
                if not user_profile.two_factor_confirmed:
                    user_profile.two_factor_confirmed = True
                    user_profile.save()

                if is_ajax:
                    # For AJAX requests, return JSON response
                    return JsonResponse(
                        {"message": "2FA verification successful!", "redirect": "/OTRisk/dashboardhome"})
                else:
                    # For non-AJAX requests, use Django's messaging and redirection
                    messages.success(request, "2FA verification successful!")
                    return redirect('OTRisk:dashboardhome')
            else:
                if is_ajax:
                    return JsonResponse({"error": "Invalid token. Please try again."}, status=400)
                else:
                    messages.error(request, "Invalid token. Please try again.")
                    return render(request, 'accounts/verify_2fa.html', {'form': TwoFactorVerifyForm()})
        except Exception as e:
            if is_ajax:
                return JsonResponse({"error": f"Error during verification: {e}"}, status=500)
            else:
                messages.error(request, f"Error during verification: {e}")
                return render(request, 'accounts/verify_2fa.html', {'form': TwoFactorVerifyForm()})


@csrf_exempt
def two_factor_verify_bak(request):
    if request.method == 'POST':

        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():

            token = form.cleaned_data['token']
            try:

                user = User.objects.get(email=request.user)

                device = TOTPDevice.objects.get(user=user.id)

                write_to_audit(user, 'Verify 2FA', get_client_ip(request))

                if device.verify_token(token):

                    device.confirmed = True
                    device.save()
                    return redirect('OTRisk:dashboardhome')
                else:

                    messages.error(request, 'Invalid token.')
            except TOTPDevice.DoesNotExist:

                messages.error(request, 'No 2FA device found for your account.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
        else:
            messages.error(request, 'Invalid form')
    else:
        form = TwoFactorVerifyForm()

    return render(request, 'accounts/two_factor_verify.html', {'form': form})


import logging


@csrf_exempt
def password_reset_request(request):
    email_host = get_api_key("email_host")
    email_port = int(get_api_key("email_port"))
    email_use_tls = True
    email_host_user = get_api_key("email_host_user")
    email_host_password = get_api_key("email_host_password")
    default_from_email = get_api_key("email_from")

    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')

            try:
                user = User.objects.get(email=email)
                code = get_random_string(length=6, allowed_chars='0123456789')
                PasswordResetCode.objects.create(user=user, code=code)
                subject = 'Password Reset Code'
                message = 'Your one-time code is: {code}. Please verify you\'re really you by entering this 6-digit code when you sign in. Just a heads up, this code will expire in 30 minutes for security reasons.'
                html_message = """
                    <strong>Your one-time code is: {code}</strong>.<br><br>
                    Please verify you're really you by entering this 6-digit code when you sign in. Just a heads up, this code will expire in 30 minutes for security reasons.
                """.format(code=code)

                send_mail(
                    subject,
                    message,
                    default_from_email,
                    [email],
                    fail_silently=False,
                    html_message=html_message,
                    auth_user=email_host_user,
                    auth_password=email_host_password,
                    connection=get_connection(
                        host=email_host,
                        port=email_port,
                        username=email_host_user,
                        password=email_host_password,
                        use_tls=True
                    )
                )

                messages.success(request, 'A reset code has been sent to your email.')
                return redirect(f'/accounts/password_reset/{user.id}/')
            except Exception as e:
                messages.error(request, 'Failed to send reset code. Please try again later.')
            except User.DoesNotExist:
                messages.error(request, 'Email not found.')
    else:
        form = PasswordResetRequestForm()

    return render(request, 'accounts/password_reset_request.html', {'form': form})


def home_view(request):
    return render(request, 'accounts/home.html')


@csrf_exempt
def password_reset(request, uid):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data.get('token')
            new_password = form.cleaned_data.get('new_password')

            # Verify the token
            try:
                reset_code = PasswordResetCode.objects.get(user__id=uid, code=token)
                # Check if the code has expired
                time_difference = timezone.now() - reset_code.timestamp
                if time_difference.total_seconds() > 1800:  # 1800 seconds = 30 minutes
                    messages.error(request, 'The reset code has expired. Please request a new one.')
                    return redirect('accounts:password_reset_request')

                # If the code is valid and not expired, reset the password
                user = reset_code.user
                user.set_password(new_password)
                user.save()

                # Delete the used reset code
                reset_code.delete()

                messages.success(request, 'Password reset successful. You can now login with your new password.')
                return redirect('accounts:home')
            except PasswordResetCode.DoesNotExist:
                messages.error(request, 'Invalid reset code. Please check and try again.')
    else:
        form = PasswordResetForm()

    return render(request, 'accounts/password_reset.html', {'form': form})


def verify_reset_code(user, submitted_code):
    try:
        reset_code = PasswordResetCode.objects.get(user=user, code=submitted_code)
        time_difference = timezone.now() - reset_code.timestamp
        if time_difference.total_seconds() > 1800:  # 1800 seconds = 30 minutes
            return False
        return True
    except PasswordResetCode.DoesNotExist:
        return False


def check_organization_name(request):
    organization_name = request.GET.get('organization_name', None)
    data = {
        'is_taken': Organization.objects.filter(name__iexact=organization_name).exists()
    }
    return JsonResponse(data)


def check_email(request):
    email = request.GET.get('email', None)
    data = {
        'is_taken': User.objects.filter(Q(email__iexact=email) | Q(username__iexact=email)).exists()
    }
    return JsonResponse(data)


def about_view(request):
    return render(request, 'accounts/about.html')


def faq_view(request):
    return render(request, 'accounts/faq.html')


def contact_view(request):
    return render(request, 'accounts/contact.html')


def get_client_ip(request):
    """Get client IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
def profile_view(request):
    user = request.user
    profile = UserProfile.objects.get(user=user)
    org_data = get_organization_details(request)

    # Calculate the number of days from the start to the end of the subscription
    total_days = (org_data['subscription_end'] - org_data['subscription_start']).days

    # Calculate the number of days from today to the end of the subscription
    days_remaining = (org_data['subscription_end'] - date.today()).days

    # Calculate the percentage of the subscription that's completed
    percentage_complete = ((total_days - days_remaining) / total_days) * 100

    context = {
        'user': user,
        'profile': profile,
        'org_data': org_data,
        'percentage_complete': percentage_complete,
        'days_remaining': days_remaining
    }
    return render(request, 'accounts/profile.html', context)


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.first_name = form.cleaned_data['first_name']
            user.last_name = form.cleaned_data['last_name']
            user.email = form.cleaned_data['email']
            user.organization = form.cleaned_data['organization']
            user.is_superuser = form.cleaned_data['is_superuser']
            user.save()

            # Log in the user after successful registration
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(username=username, password=password)
            login(request, user)

            return redirect('login')  # Redirect to the login page
    else:
        form = CustomUserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})


@csrf_exempt
def setup_2fa(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')

    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            phone_number = form.cleaned_data['phone_number']

            # Validate the phone number format
            try:
                parsed_number = phonenumbers.parse(phone_number)
                if not phonenumbers.is_valid_number(parsed_number):
                    raise ValidationError("Invalid phone number format")

                phone_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)

                user_profile = UserProfile.objects.get(user__id=request.user.id)
                user_profile.phone_number = phone_number
                user_profile.save()
                # Send verification code to the user's phone
                code = send_verification_code(phone_number)
                request.session['verification_code'] = code
                request.session['phone_number'] = phone_number
                return redirect('two_factor_verify')
            except phonenumbers.NumberParseException:
                form.add_error('phone_number', 'Invalid phone number format')
            except ValidationError as e:
                form.add_error('phone_number', str(e))
            except Exception as e:
                messages.error(request, f"Error sending verification code: {e}")

    else:
        form = TwoFactorSetupForm()

    return render(request, 'accounts/setup_2fa.html', {'form': form})


def setup_auth_app(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if not user_profile.otp_secret:
        user_profile.otp_secret = generate_otp_secret()
        user_profile.save()

    if request.method == 'POST':
        form = AuthAppSetupForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            totp = pyotp.TOTP(user_profile.otp_secret)
            if totp.verify(otp_code):
                user_profile.two_factor_confirmed = True
                user_profile.save()
                messages.success(request, "Authentication app successfully configured!")
                return redirect('OTRisk:dashboardhome')
            else:
                messages.error(request, "Invalid code. Please try again.")
    else:
        form = AuthAppSetupForm()

    qr_code_base64 = generate_qr_code_base64(request.user, user_profile.otp_secret)

    return render(request, 'accounts/setup_auth_app.html', {'form': form, 'qr_code': qr_code_base64})


def setup_2fa_bak(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')

    # Check if the user already has a TOTPDevice set up and confirmed
    if TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
        messages.info(request, "2FA is already set up for your account.")
        return redirect('accounts:dashboard')  # or wherever you want to redirect

    totp = pyotp.TOTP(pyotp.random_base32())
    uri = totp.provisioning_uri(name=request.user.email,
                                issuer_name="AnzenOT")  # Replace "YourAppName" with your app's name

    # Generate QR code from the URI
    img = qrcode.make(uri)
    img_buffer = io.BytesIO()
    img.save(img_buffer, format="PNG")
    qr_code_b64 = base64.b64encode(img_buffer.getvalue()).decode()

    # Convert the base32 secret key to hexadecimal
    hex_key = base64.b32decode(totp.secret).hex()

    # Check for an existing unconfirmed TOTPDevice record
    device, created = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False,
                                                       defaults={'key': hex_key})

    if not created:
        # If an unconfirmed record already exists, update its secret key
        device.key = hex_key
        device.save()

    context = {
        'qr_code_url': f"data:image/png;base64,{qr_code_b64}",
        'verify_2fa': reverse('accounts:verify_2fa')
    }
    return render(request, 'accounts/setup_2fa.html', context)


def verify_2fa(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')

    # Check if the user already has a TOTPDevice set up and confirmed
    if TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
        messages.info(request, "2FA is already set up and verified for your account.")
        return redirect('OTRisk:dashboardhome')

    form = Verify2FAForm(request.POST or None)
    if request.method == "POST" and form.is_valid():

        token = form.cleaned_data['code']
        try:

            device = TOTPDevice.objects.get(user=request.user, confirmed=False)
            # Convert the hexadecimal key back to base32
            base32_key = base64.b32encode(bytes.fromhex(device.key)).decode()

            totp = pyotp.TOTP(base32_key)
            if totp.verify(token):

                device.confirmed = True
                device.save()
                messages.success(request, "2FA setup and verification successful!")
                return redirect('OTRisk:dashboardhome')
            else:

                messages.error(request, "Invalid token. Please try again.")
        except TOTPDevice.DoesNotExist:

            messages.error(request, "No unconfirmed 2FA setup found for your account. Please set up 2FA first.")
        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")

    context = {'form': form}
    return render(request, 'accounts/verify_2fa.html', context)


@csrf_exempt
def login_view(request):
    MAX_ATTEMPTS = 5
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        ip = get_client_ip(request)  # Assuming get_client_ip is a function you have defined
        username = request.POST.get('username')
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            user_profile = UserProfile.objects.get(user=user)

            write_to_audit(user, 'Logged in', ip)  # Assuming write_to_audit is a function you have defined
            user_profile.failed_login_attempts = 0
            user_profile.save()
            if user_profile.must_change_password:
                request.session['user_id_for_password_change'] = user.id
                return redirect('accounts:password_change', user_id=user.id)

            # Check if the user has 2FA set up and confirmed
            if user_profile.two_factor_confirmed:
                try:
                    # Check if the user is using an authentication app or SMS
                    if user_profile.otp_secret:
                        # Direct to authentication app verification
                        return redirect('accounts:two_factor_auth_app_verify')
                    else:
                        # Send 2FA code via SMS
                        verification_sid = send_verification_code(user_profile.phone_number)
                        # Store the verification SID in the session for tracking (optional)
                        request.session['verification_sid'] = verification_sid
                        return redirect('accounts:two_factor_verify')
                except Exception as e:
                    messages.error(request,
                                   f"Error sending verification code - please check your Internet connection and try again")
                    # Log the error
                    write_to_audit(user, f'Error sending verification code: {e}', ip)
            else:
                # If the user hasn't set up 2FA, redirect them to the setup page
                return redirect('accounts:setup_2fa')
        else:
            messages.error(request, 'Invalid login credentials.')
            # Record failed login attempt
            LoginAttempt.objects.create(
                ip_address=ip,
                was_successful=False,
                reason="Invalid credentials"
            )
            write_to_audit(None, 'Failed login - Invalid credentials', ip)

            try:
                user_profile = UserProfile.objects.get(user__username=username)
                user_profile.failed_login_attempts += 1
                user_profile.save()

                # Check if failed attempts exceed max limit
                if user_profile.failed_login_attempts >= MAX_ATTEMPTS:
                    user_profile.user.is_active = False
                    user_profile.user.save()
                    messages.error(request, 'Your account has been locked due to too many failed login attempts.')
            except UserProfile.DoesNotExist:
                # Handle case where the user profile does not exist
                pass
    else:
        form = AuthenticationForm()

    return render(request, 'accounts/home.html', {'form': form})


def add_user_to_organization(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']

        # Check if user with this email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already in use.')
            return redirect('profile')  # Redirect back to the profile page

        # Create the new user
        user = User.objects.create_user(username=email, email=email, password=password, first_name=first_name,
                                        last_name=last_name)

        user_profile, created = UserProfile.objects.get_or_create(
            user=user,
            defaults={'organization': request.user.userprofile.organization}
        )
        if not created:
            user_profile.organization = request.user.userprofile.organization
            user_profile.save()

        messages.success(request, 'New user added successfully!')
        return redirect(reverse('accounts/profile'))

    return redirect(reverse('accounts/profile'))


# If not a POST request, redirect back to the profile page

def password_change_view(request, user_id):
    user_to_change_password_for = User.objects.get(id=user_id)

    if request.method == 'POST':
        form = PasswordChangeForm(user=user_to_change_password_for, data=request.POST)

        if form.is_valid():
            form.save()
            # Update the must_change_password field
            user_profile = UserProfile.objects.get(user=user_to_change_password_for)
            user_profile.must_change_password = False
            user_profile.save()
            messages.success(request, 'Password changed successfully.')
            return redirect('OTRisk:dashboardhome')
    else:
        form = PasswordChangeForm(user=user_to_change_password_for)

    return render(request, 'accounts/password_change.html', {'form': form})


def subscription_view(request):
    subscription_types = SubscriptionType.objects.all()
    if request.method == "POST":
        form = SubscriptionForm(request.POST)

        if form.is_valid():
            # Store the data in session
            request.session['email'] = form.cleaned_data['email']
            request.session['first_name'] = form.cleaned_data['first_name']
            request.session['last_name'] = form.cleaned_data['last_name']
            request.session['organization_name'] = form.cleaned_data['organization_name']
            request.session['organization_address1'] = form.cleaned_data['organization_address']
            request.session['organization_address2'] = form.cleaned_data['organization_address2']
            request.session['organization_city'] = form.cleaned_data['organization_city']
            request.session['organization_state'] = form.cleaned_data['organization_state']
            request.session['organization_zip'] = form.cleaned_data['organization_zip']
            request.session['organization_country'] = form.cleaned_data['organization_country']
            request.session['subscription_type'] = form.cleaned_data['subscription_type'].id
            # Store the duration in session
            selected_subscription = form.cleaned_data['subscription_type']
            request.session['duration'] = selected_subscription.duration

            # Redirect to Stripe payment
            return redirect('accounts:payment_view')
    else:
        form = SubscriptionForm()

    return render(request, 'accounts/subscription.html', {'form': form, 'subscription_types': subscription_types})


def set_password_view(request):
    # Generate a strong random password
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    user = User.objects.create_user(username=request.session['email'], first_name=request.session['first_name'],
                                    last_name=request.session['last_name'],
                                    password=password, email=request.session['email'])

    # Calculate subscription start and end dates
    subscription_start = timezone.now().date()
    duration = request.session.get('duration', 30)  # Default to 30 days if duration not found in session
    subscription_end = subscription_start + timedelta(days=duration)

    subscription_type = SubscriptionType.objects.get(id=request.session['subscription_type'])
    organization = Organization.objects.create(
        name=request.session['organization_name'],
        subscription_type=subscription_type,
        subscription_start=subscription_start,
        subscription_end=subscription_end,
        subscription_status=1,
        address=request.session['organization_address1'],
        address2=request.session['organization_address2'],
        city=request.session['organization_city'],
        country=request.session['organization_country'],
        state=request.session['organization_state'],
        zip=request.session['organization_zip']
    )
    organization.save()

    # Ensure organization is saved and has an id
    if organization.id:
        # Create UserProfile
        UserProfile.objects.create(user_id=user.id, organization_id=organization.pk, must_change_password=1)
    else:
        # Handle error: organization not saved correctly
        return HttpResponse("Error: Organization not saved correctly.")

    return password


def success_view(request):
    messages.success(request,
                     'Thank you for purchasing iOTa. Check your email for your temporary password and then click on Customer Login to get started. To get the best out of iOTa, we recommend that you read the user guide. Click on help after logging in for the latest information.')
    return render(request, 'accounts/home.html')


def get_subscription_details(request, subscription_id):
    try:
        subscription = SubscriptionType.objects.get(id=subscription_id)
        data = {
            'max_users': subscription.max_users,
            'duration': subscription.duration,
            'description': subscription.description,
            'price': float(subscription.price)
        }
        return JsonResponse(data)
    except SubscriptionType.DoesNotExist:
        return JsonResponse({'error': 'Subscription not found'}, status=404)


def payment_view(request):
    if 'subscription_type' not in request.session:
        # Redirect to subscription selection if not chosen
        return redirect('accounts:subscription_view')

    subscription_id = request.session['subscription_type']
    subscription = SubscriptionType.objects.get(id=subscription_id)

    if request.method == "POST":
        receipt_email = request.POST.get('email')
        token = request.POST.get("stripeToken")
        try:
            customer = stripe.Customer.create(
                email=request.session['email'],
                source=token
            )

            if subscription.price == 0:
                subscription.price = 1

            # Create the charge using the customer ID
            charge = stripe.Charge.create(
                amount=int(subscription.price * 100),  # Convert to cents
                currency="usd",
                customer=customer.id,  # Use the customer ID here
                description=f"Payment for {subscription.name} subscription",
                receipt_email=receipt_email  # Send a receipt to this email
            )

            if charge.paid:
                password = set_password_view(request)
                first_name = request.session['first_name']
                # Email the password to the user
                send_mail(
                    'Welcome to iOTa',
                    f'Dear {first_name},\n\nThank you for purchasing iOTa. Your temporary password is: {password}. You will be prompted to change this password the first time you access iOTa.',
                    'info@anzenot.ai',  # Replace with your email
                    [request.session['email']],
                    fail_silently=False,
                )
                # Clear the session
                del request.session['email']
                del request.session['organization_name']
                del request.session['subscription_type']
                del request.session['duration']  # Clear the duration from the session
                return redirect('accounts:success_view')
            else:
                # Handle payment errors
                messages.error(request, 'Payment was unsuccessful. Please try again.')
        except stripe.error.StripeError as e:
            # Handle Stripe errors
            messages.error(request, f"An error occurred: {e}")

    context = {
        'stripe_public_key': os.environ.get('STRIPE_PUBLIC_KEY'),
        'subscription': subscription
    }
    return render(request, 'accounts/payment.html', context)


class ContactForm(forms.Form):
    first_name = forms.CharField(max_length=100, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'First name'}))
    last_name = forms.CharField(max_length=100, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'Last name'}))
    business_email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'styled-input form-control', 'placeholder': 'Business Email'}))
    company = forms.CharField(max_length=100, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'Company'}))
    job_title = forms.CharField(max_length=100, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'Job Title'}))
    country = forms.CharField(max_length=100, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'Country'}))
    phone = forms.CharField(max_length=15, widget=forms.TextInput(
        attrs={'class': 'styled-input form-control', 'placeholder': 'Phone'}))
    comments = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'styled-input form-control', 'placeholder': 'Comments'}))


def contact_form(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)

        if form.is_valid():
            # Send email
            subject = f"Contact Form Submission from {form.cleaned_data['first_name']} {form.cleaned_data['last_name']}"
            message = f"""
            First Name: {form.cleaned_data['first_name']}
            Last Name: {form.cleaned_data['last_name']}
            Email: {form.cleaned_data['business_email']}
            Company: {form.cleaned_data['company']}
            Job Title: {form.cleaned_data['job_title']}
            Country: {form.cleaned_data['country']}
            Phone: {form.cleaned_data['phone']}
            Comments: {form.cleaned_data['comments']}
            """
            send_mail(subject, message, 'support@iotarisk.com', ['support@iotarisk.com'])

            messages.success(request, "Thank you for your message. We'll be in contact shortly.")
            return redirect('accounts:contact_form')

    else:
        form = ContactForm()

    return render(request, 'accounts/contact.html', {'form': form})


def eula(request):
    return render(request, 'accounts/Terms.html')


def privacy(request):
    return render(request, 'accounts/Privacy.html')


@login_required()
def get_organization_details(request):
    # Retrieve the organization instance from the user profile

    org_id = request.user.userprofile.organization_id

    org = Organization.objects.get(id=org_id)

    # Count the number of users in the organization
    user_count = UserProfile.objects.filter(organization=org).count()

    # Construct the data dictionary
    data = {
        'id': org.id,  # This will give you the organization ID
        'name': org.name,
        'address': org.address,
        'address2': org.address2,
        'city': org.city,
        'state': org.state,
        'zip': org.zip,
        'country': org.country,
        'max_users': org.max_users,
        'subscription_status': org.subscription_status,
        'subscription_start': org.subscription_start,
        'subscription_end': org.subscription_end,
        'user_count': user_count
    }

    return data


def write_to_audit(user_id, user_action, user_ip):
    try:
        user_profile = UserProfile.objects.get(user=user_id)

        audit_log = auditlog(
            user=user_id,
            timestamp=timezone.now(),
            user_action=user_action,
            user_ipaddress=user_ip,
            user_profile=user_profile
        )
        audit_log.save()
    except UserProfile.DoesNotExist:
        # Handle the case where UserProfile does not exist for the user
        pass


def get_api_key(service_name):
    try:
        key_record = APIKey.objects.get(service_name=service_name)
        return key_record.key
    except ObjectDoesNotExist:
        # Handle the case where the key is not found
        return None

def autocompletetest(request):
    return render(request, 'accounts/autocompletetest.html')