from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from .forms import CustomUserCreationForm
from django.contrib.auth.models import User
from .models import customer
from django.contrib import messages
from django.db import connection
from accounts.models import UserProfile, SubscriptionType, Organization


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
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            # Get the organization name
            profile = UserProfile.objects.get(user=user)
            organization_name = profile.organization.name
            # Save organization in session
            request.session['organization_id'] = profile.organization.id
            request.session['organization_name'] = organization_name
            return redirect('OTRisk:dashboardhome')
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})
