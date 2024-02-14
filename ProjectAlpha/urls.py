from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import RedirectView
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView

from accounts import views

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='accounts/home.html'), name='root_login'),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('accounts/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    # Remove the direct path to 'accounts/login/' to avoid redundancy
    path('logout/', auth_views.LogoutView.as_view(next_page='/'), name='logout'),
    path('token/', views.two_factor_verify, name='two_factor_verify'),
    path('logout/', views.CustomLogoutView.as_view(), name='logout'),
]


if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

