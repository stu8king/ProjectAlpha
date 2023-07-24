from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from accounts import views
from .views import login_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('register/', views.register, name='register'),
    path('profile/', views.profile_view, name='profile'),
]

