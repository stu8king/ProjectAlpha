from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile
from .forms import \
    UserAdminForm  # Assuming you placed the UserAdminForm in a file named forms.py in the same app directory
from django.contrib import admin


# Register your models here.
class UserAdmin(DefaultUserAdmin):
    form = UserAdminForm
    fieldsets = DefaultUserAdmin.fieldsets + (
        ('Organization Info', {'fields': ('organization',)}),
    )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if 'organization' in form.cleaned_data and form.cleaned_data['organization']:
            profile, created = UserProfile.objects.get_or_create(user=obj)
            profile.organization = form.cleaned_data['organization']
            profile.save()


# Unregister the default User admin and register the customized one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
