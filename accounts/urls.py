from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from accounts import views
from .views import login_view

urlpatterns = [
    # path('admin/', admin.site.urls),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile_view, name='profile'),
    path('add_user_to_organization/', views.add_user_to_organization, name='add_user_to_organization'),
    path('about/', views.about_view, name='about'),
    path('faq/', views.faq_view, name='faq'),
    path('contact/', views.contact_view, name='contact'),
    path('password_change/', views.password_change_view, name='password_change'),
    path('subscription/', views.subscription_view, name='subscription_view'),
    path('payment/', views.payment_view, name='payment_view'),
    path('set-password/', views.set_password_view, name='set_password_view'),
    path('get_subscription_details/<int:subscription_id>/', views.get_subscription_details, name='get_subscription_details'),
    path('success/', views.success_view, name='success_view'),
    path('check_email/', views.check_email, name='check_email'),
    path('check_organization/', views.check_organization_name, name='check_organization_name'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset/<uid>/', views.password_reset, name='password_reset_form'),

]

