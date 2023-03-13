from django.contrib import admin

from .models import RequestCounter, User, DeviceGrant

admin.site.register(User)
admin.site.register(DeviceGrant)
admin.site.register(RequestCounter)
