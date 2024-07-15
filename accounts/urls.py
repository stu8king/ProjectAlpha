from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from accounts import views
from .views import login_view
from two_factor.urls import urlpatterns as tf_urls
from django.contrib.auth.views import LogoutView

app_name = 'accounts'

urlpatterns = [
    # path('admin/', admin.site.urls),
    path('', views.home_view, name='home'),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('login/', views.login_view, name='login'),
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile_view, name='profile'),
    path('add_user_to_organization/', views.add_user_to_organization, name='add_user_to_organization'),
    path('about/', views.about_view, name='about'),
    path('faq/', views.faq_view, name='faq'),
    path('contact/', views.contact_view, name='contact'),
    path('faq/', views.faq_view, name='faq'),
    path('password_change/<int:user_id>/', views.password_change_view, name='password_change'),
    path('subscription/', views.subscription_view, name='subscription_view'),
    path('payment/', views.payment_view, name='payment_view'),
    path('set-password/', views.set_password_view, name='set_password_view'),
    path('get_subscription_details/<int:subscription_id>/', views.get_subscription_details, name='get_subscription_details'),
    path('success/', views.success_view, name='success_view'),
    path('check_email/', views.check_email, name='check_email'),
    path('check_organization/', views.check_organization_name, name='check_organization_name'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset/<uid>/', views.password_reset, name='password_reset_form'),
    path('two_factor_setup/', views.two_factor_setup, name='two_factor_setup'),
    ## path('two_factor_verify/', views.two_factor_verify, name='two_factor_verify'),
    path('setup_2fa/', views.setup_2fa, name='setup_2fa'),
    path('verify_2fa/', views.verify_2fa, name='verify_2fa'),
    path('contact_form/', views.contact_form, name='contact_form'),
    path('eula/', views.eula, name='eula'),
    path('privacy/', views.privacy, name='privacy'),
    path('setup-auth-app/', views.setup_auth_app, name='setup_auth_app'),
    path('two-factor-verify/', views.two_factor_verify, name='two_factor_verify'),  # Assuming this view exists for SMS verification
    path('two-factor-auth-app-verify/', views.two_factor_auth_app_verify, name='two_factor_auth_app_verify'),
    path('autocompletetest/', views.autocompletetest, name='autocompletetest'),
]


