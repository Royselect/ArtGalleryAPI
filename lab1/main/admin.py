from django.contrib import admin

from .models import User, CustomRole, CustomPermission, Artwork

admin.site.register(User)
admin.site.register(CustomRole)
admin.site.register(CustomPermission)
admin.site.register(Artwork)