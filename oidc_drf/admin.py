from django.contrib import admin
from oidc_drf.models import OIDCExtraData
import json


class OIDCExtraDataAdmin(admin.ModelAdmin):
    list_display = ['user', 'formatted_oidc_data']
    readonly_fields = ('formatted_oidc_data',)
    exclude = ('data',)  # Exclude the original oidc_data field

    def formatted_oidc_data(self, obj):
        oidc_data = json.loads(obj.data)
        formatted_data = json.dumps(oidc_data, indent=4)
        return formatted_data

    formatted_oidc_data.short_description = 'OIDC Data'


admin.site.register(OIDCExtraData, OIDCExtraDataAdmin)
