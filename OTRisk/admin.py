from django.contrib import admin
from OTRisk.models.post import Post
from OTRisk.models.asset import Asset



class AssetInline(admin.StackedInline):
    model = Asset
    extra = 1





@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ['title', 'version', 'ip_address', 'post']
    fieldsets = [
        ('Asset Details', {'fields': ['title', 'version', 'ip_address', 'post']}),
    ]




admin.site.unregister(Asset)




# @admin.register(Asset)
# class AssetAdmin(admin.ModelAdmin):
#    list_display = ['title', 'version', 'ip_address', 'post']


# Register your models here.

def get_post_process_description(self, obj):
    return obj.post.process_description


get_post_process_description.short_description = 'Process Description'
