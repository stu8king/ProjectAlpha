from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from django.contrib.auth.models import User
from .models import customer, UserProfile, FailedLoginAttempt
from django.contrib import messages
from django.db import connection
from accounts.models import UserProfile, SubscriptionType, Organization, LoginAttempt, FailedLoginAttempt
from django.utils import timezone
from django.contrib.auth import login
from django.urls import reverse
from django.dispatch import receiver
from django.db.models.signals import post_save


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()


def about_view(request):
    return render(request, 'accounts/about.html')


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
    print(f"Profile: {profile}")
    print(f"Organization: {profile.organization.name}")
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
            login(request, user)

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

                return redirect('OTRisk:dashboardhome')
            except UserProfile.DoesNotExist:
                messages.error(request, 'UserProfile does not exist for this user.')
                return redirect('accounts:login')

        else:
            messages.error(request, 'Invalid login credentials.')

            # Record failed login attempt
            LoginAttempt.objects.create(
                username=request.POST.get('username'),
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
