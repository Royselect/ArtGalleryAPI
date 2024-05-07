from rest_framework import permissions
from django.contrib.auth import get_user_model
User = get_user_model()
from .models import *
from django.shortcuts import get_object_or_404
import jwt
from rest_framework.exceptions import AuthenticationFailed


# Проверка разрешения на чтение
class ReadForAll(permissions.BasePermission):
    def has_permission(self, request, view):
        user_permission = get_user_permissions(custom_get_user(request))
        if "read_all" in user_permission or "read_access" in user_permission:
            return True
        else:
            return False

# Проверка разрешения на создание
class CreateForAll(permissions.BasePermission):
    def has_permission(self, request, view):
        user_permission = get_user_permissions(custom_get_user(request))
        if "create_all" in user_permission or "create_access" in user_permission:
            return True
        else:
            return False

# Проверка на разрешение создания
class AdminOnly():
    def has_permission(self, request, view):
        admin_role = CustomRole.objects.get(title="admin")
        user = custom_get_user(request)
        if admin_role in user.roles.all():
            return True
        else:
            return False

# Муз. исполнитель или админ\модер могут удалять, изменять, добавлять песни
class ArtistOrAdmin():
    def has_permission(self, request, view):
        user_permissions = get_user_permissions(custom_get_user(request))
        art = get_object_or_404(Artwork, pk=request.data['pk'])
        SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS']
        if request.method == "PUT" or request.method == "PATCH":
            if "update_all" in user_permissions or ("update_access" in user_permissions and request.user in art.artists.all()):
                return True
            else:
                return False
        elif request.method == "DELETE":
            if "delete_all" in user_permissions or ("delete_access" in user_permissions and request.user in art.artists.all()):
                return True
            else:
                return False
        elif request.method == "POST":
            if "create_all" in user_permissions or ("create_access" in user_permissions and request.user in art.artists.all()):
                return True
            else:
                return False
        elif request.method in SAFE_METHODS:
            if "read_all" in user_permissions or ("read_access" in user_permissions and request.user in art.artists.all()):
                return True
            else:
                return False


# Получаем все разрешения юзера
def get_user_permissions(user):
    roles = user.roles.all()
    user_permissions = []
    for role in roles:
        role_permissions = role.permissions.all()
        for role_permission in role_permissions:
            if role_permission.title not in user_permissions:
                user_permissions.append(role_permission.title)

    return user_permissions

def custom_get_user(request):
    token = request.COOKIES.get('jwt', False)
    if not token:
        return None
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    user = User.objects.filter(id=payload['user_id']).first()
    return user
