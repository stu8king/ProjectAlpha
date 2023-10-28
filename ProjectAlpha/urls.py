from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import RedirectView
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', RedirectView.as_view(url='/accounts/login/', permanent=True), name='root_redirect'),
    path('OTRisk/', include('OTRisk.urls', namespace='OTRisk')),
    path('accounts/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='accounts/home.html'), name='login'),
    path('logout/', LogoutView.as_view(next_page='/accounts/login/'), name='logout'),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

