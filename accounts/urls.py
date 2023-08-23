from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from accounts import views
from .views import login_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile_view, name='profile'),
    path('add_user_to_organization/', views.add_user_to_organization, name='add_user_to_organization'),
    path('accounts/about/', views.about_view, name='about'),
]

