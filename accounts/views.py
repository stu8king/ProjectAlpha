import os
from datetime import timedelta

import stripe
import stripe.error
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.core.mail import send_mail
import string
import random
from accounts.models import UserProfile, SubscriptionType, Organization, LoginAttempt, ActiveUserSession
from .forms import CustomUserCreationForm, PasswordChangeForm, SetPasswordForm, \
    SubscriptionForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .forms import PasswordResetRequestForm, PasswordResetForm
from .models import PasswordResetCode
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta

stripe.api_key = settings.STRIPE_SECRET_KEY


def password_reset_request(request):
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
                    'support@iotarisk.com',
                    [email],
                    fail_silently=False,
                    html_message=html_message
                )
                messages.success(request, 'A reset code has been sent to your email.')
                return redirect(f'/accounts/password_reset/{user.id}/')
            except User.DoesNotExist:
                messages.error(request, 'Email not found.')
    else:
        form = PasswordResetRequestForm()

    return render(request, 'accounts/password_reset_request.html', {'form': form})


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
                    return redirect('accounts;password_reset_request')

                # If the code is valid and not expired, reset the password
                user = reset_code.user
                user.set_password(new_password)
                user.save()

                # Delete the used reset code
                reset_code.delete()

                messages.success(request, 'Password reset successful. You can now login with your new password.')
                return redirect('login')
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

    context = {
        'user': user,
        'profile': profile,
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


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        ip = get_client_ip(request)

        if form.is_valid():
            user = form.get_user()

            # Check if user has an active session
            ## active_session = ActiveUserSession.objects.filter(user=user).first()
            ## if active_session:
            ##     # Check if the session is still valid
            ##     try:
            ##         session = Session.objects.get(session_key=active_session.session_key)
            ##         if session.expire_date > timezone.now():
            ##             messages.error(request, 'This account is already logged in from another location.')
            ##             return render(request, 'accounts/login.html', {'form': form})
            ##     except Session.DoesNotExist:
            ##        # If the session does not exist, delete the record from ActiveUserSession
            ##         active_session.delete()

            login(request, user)
            # Add a new record to ActiveUserSession
            ## ActiveUserSession.objects.create(user=user, session_key=request.session.session_key)

            # Record successful login attempt
            LoginAttempt.objects.create(
                user=user,
                ip_address=ip,
                was_successful=True
            )

            # Set organization details in session
            try:
                user_profile = UserProfile.objects.get(user=user)
                organization_name = user_profile.organization.name
                request.session['organization_id'] = user_profile.organization.id
                request.session['organization_name'] = organization_name
                if user_profile.must_change_password:
                    return redirect('accounts:password_change')

                return redirect('OTRisk:dashboardhome')
            except UserProfile.DoesNotExist:
                messages.error(request, 'UserProfile does not exist for this user.')
                return redirect('accounts:login')

        else:
            messages.error(request, 'Invalid login credentials.')

            # Record failed login attempt
            LoginAttempt.objects.create(
                ip_address=ip,
                was_successful=False,
                reason="Invalid credentials"
            )

    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})


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

def password_change_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            # Update the must_change_password field
            user_profile = UserProfile.objects.get(user=request.user)
            user_profile.must_change_password = False
            user_profile.save()
            messages.success(request, 'Password changed successfully.')
            return redirect('OTRisk:dashboardhome')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'accounts/password_change.html', {'form': form})


def subscription_view(request):
    print(request.POST)
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
    return render(request, 'accounts/login.html', {'message': 'Password set successfully!'})


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
                    'support@iotarisk.com',  # Replace with your email
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
