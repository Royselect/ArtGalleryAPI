from .models import User, Token, TwoFactorAuthCode, CustomSession, Artwork
from django.http import JsonResponse
import jwt
from django.conf import settings
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from .serializers import *
from django.conf import settings
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt import token_blacklist
from datetime import datetime
from pytz import utc
import pyotp
import qrcode
from .permissions import *
from django.db.models.signals import post_save, post_delete, pre_save
from django.core.exceptions import ObjectDoesNotExist

# после регистрации, юзеру дается дефолтная роль
@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        try:
            role = CustomRole.objects.get(title='looker')
            instance.roles.add(role)
            instance.save()
        except ObjectDoesNotExist as e:
            AuthenticationFailed('Роль не была дана!')
            

# метод проверки токена
def check_token(token):
    if not token:
        raise AuthenticationFailed('Не прошел проверку!')
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Токен умер :(')
    
    token_from_bd = Token.objects.filter(user_id=payload['user_id']).all()
    result_token = False
    for tok in token_from_bd:
        if token != str(tok.token):
            pass
        else:
            result_token = True
            break
    if result_token == False:
        raise AuthenticationFailed('Токен не полностью соответствует!')
    

# защищенное представление
class SecureClass(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        check_token(token)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.filter(id=payload['user_id']).first()
        # if not user.is_authenticated:
        #     raise AuthenticationFailed('Пользователь не в системе!!!')
        serializer = UserSerializer(user)
        return Response(serializer.data)

# класс создания новых пользователей
class Register(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# Метод создания и сохранения токена
def TokenObtainView(user, data_user):
    check_original_token = True
    while(check_original_token):
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        exist = Token.objects.filter(token=access_token).exists()
        if (~exist):
            break

    token_data = {'user': data_user.id, 'token': access_token}
    serializer = TokenSerializer(data=token_data)
    serializer.is_valid(raise_exception=True)
    serializer.save()

    response = Response()
    response.set_cookie(key='jwt', value=access_token, httponly=True)
    response.data = {
        'access_token':access_token,
    }
    return response

# Класс авторизации пользователя
class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('Пользователь не найден!!!')

        if not user.check_password(password):
            raise AuthenticationFailed('Неправильный пароль!!!')
        
        # Выдача токена и перенаправление на код подтверждения
        data_user = user
        response = Response()
        response = TokenObtainView(user, data_user)
        secondAuth(user)
        return response
    
def DeleteOldSessions():
    # удаляю все просроченные сессии
    sessions = CustomSession.objects.all()
    for session in sessions:
        try:
            UntypedToken(session.token)
        except:
            session.delete()
    
# Представление 2FA
class ConfirmLoginView(APIView):
    def post(self, request):
        # На страницу подтверждения двухфакторки нельзя без первичного токена
        token = request.COOKIES.get('jwt')
        check_token(token)

        # Получаем почту, код и запись кода юзера из бд
        email = request.data['email']
        code = request.data['code']
        user_info = User.objects.filter(email=email).first()
        code_info = TwoFactorAuthCode.objects.filter(user=user_info).first()
        
        # Проверка кода на подлинность и срок действия
        if code != code_info.code:
            raise AuthenticationFailed('Введен неверный код подтверждения!')


        if datetime.now(utc) > code_info.expires_at:
            raise AuthenticationFailed('Срок действия кода подтверждения истек!')
        
        # Удаляем использованный первичный токен доступа
        response_for_del = Response()
        response_for_del.delete_cookie('jwt')

        # Удаляем просроченные сессии
        DeleteOldSessions()
        # Создаем новый основной токен и выдаем пользователю
        data_user = user_info
        response = Response()
        response = TokenObtainView(user_info, data_user)

        user_sessions = CustomSession.objects.filter(user=user_info)
        if len(user_sessions) >= settings.SESSIONS_COUNT:
            response.data['warning'] = "Вы превышаете количество допустимых сессий, пожалуйста, отзовите предыдущие"
        token = request.COOKIES.get('jwt')
        CustomSession.objects.create(user=user_info, token=token)
        return response

    
# метод генерации и сохранения кода для 2FA
def secondAuth(user):
    # Генерация qr-кода для перемещения в приложение-аутентификатор
    key = pyotp.random_base32()
    uri = pyotp.totp.TOTP(key).provisioning_uri(name="Pavel", issuer_name="Uhahaha")
    qrcode.make(uri).save("qrcode.png")

    # Удаляем старые коды подтверждения
    all_codes = TwoFactorAuthCode.objects.all()
    for code in all_codes:
        code.delete()

    #Сохраняем новый сгенерированный код в бд
    trans_code = pyotp.parse_uri(uri)
    code = trans_code.now()
    time_now = datetime.now()
    expiration_time = time_now + settings.CONFIRM_CODE_TIME
    TwoFactorAuthCode.objects.create(user=user, code=code, created_at=time_now, expires_at=expiration_time)

# Выход из всех сессий кроме текущей
class LogoutFromAllView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        check_token(token)
        DeleteOldSessions()
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.filter(id=payload['user_id']).first()
        sessions = CustomSession.objects.filter(user = user)
        for session in sessions:
            if session.token != token:
                session.delete()

        return Response({"Сообщение": "Вы прервали все сеансы кроме текущей"})

# Класс выхода из системы, тут удаляется токен
class LogoutView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')
        check_token(token)
        token_delete = Token.objects.filter(token=token).first()
        token_delete.delete()

        Blacklist.add_token(token_delete)

        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Bye bye!!!'
        }
        return response
    

class Blacklist:
    @classmethod
    def add_token(cls, token):
        outstanding_token = OutstandingToken.objects.filter(token=token).first()
        
        if outstanding_token:
            outstanding_token.blacklisted = True
            outstanding_token.blacklist_timestamp = datetime.now()
            outstanding_token.save()
        else:
            new_outstanding_token = OutstandingToken(token=token, expires_at=datetime.now())
            new_outstanding_token.save()

    @classmethod
    def check_token(cls, token):
        return OutstandingToken.objects.filter(token=token, blacklisted=True).exists() or BlacklistedToken.objects.filter(token=token).exists()
    
# Выводим картины(могут видеть все)
class GetArtworksListView(APIView):
    def get(self, request):
        arts = Artwork.objects.all()
        return Response(ArtworksListSerializer(arts, many=True).data)
    
# Просмотреть подробности у картины (могут только авторизованные с разрашением на чтение)
class LookDetailInfoFromArtworks(APIView):
    permission_classes = [ReadForAll]
    def get(self, request, *args, **kwargs):
        pk = request.data['pk']
        if pk:
            art = get_object_or_404(Artwork, pk=pk)
            return Response(ArtworksDetailListSerializer(art, many=False).data)
        
# Создание картины
class CreateArtworkView(APIView):
    permission_classes = [CreateForAll]
    def post(self, request, *args, **kwargs):
        serializer = ArtworkCreateSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
# изменить книгу могут только либо сам художник, либо админ
class UpdateArtworkView(APIView):
    permission_classes = [ArtistOrAdmin]
    def put(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Ошибка": "Такой картины нет"})
        art = get_object_or_404(Artwork, pk=pk)
        serializer = ArtworkCreateSerializer(data=request.data, instance=art, partial = True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    def delete(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Ошибка": "Такой картины нет"})
        art = get_object_or_404(Artwork, pk=pk)
        art.delete()
        return Response({'Внимание': "Запись о данной картине была удалена"})

# Просмотреть все роли и создать может только админ
class RoleListView(APIView):
    permission_classes = [AdminOnly]
    # список ролей
    def get(self, request, *args, **kwargs):
        roles = CustomRole.objects.all()
        return Response(RoleListSerializer(roles, many=True).data)
    
    # создание роли
    def post(self, request, *args, **kwargs):
        serializer = RoleCreateSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

# Менять роли тоже может только админ    
class UpdateRoleView(APIView):
    permission_classes = [AdminOnly]
    # Изменение роли
    def put(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Ошибка": "такой роли не существует"})
        role = get_object_or_404(CustomRole, pk=pk)
        serializer = RoleCreateSerializer(data=request.data, instance=role, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    # Удаление роли
    def delete(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Ошибка": "такой роли не существует"})
        role = get_object_or_404(CustomRole, pk=pk)
        role.delete()
        return Response({'Сообщение': "Вы только что удалили роль, браво"})

# Присваивание юзерам роли, и их удаление
class RoleAddUsers(APIView):
    permission_classes = [AdminOnly]
    # Добавление юзеров в роль
    def post(self, request, *args, **kwargs):
        pk = request.data["role"]
        users = request.data["users"]
        role = get_object_or_404(CustomRole, pk=pk)
        for user_id in users:
            user = get_object_or_404(User, pk=user_id)
            # role.users.add(user)
            user.roles.add(role)
        return Response({"Сообщение": "Успешно"})

    # Лишаем юзеров роли
    def delete(self, request, *args, **kwargs):
        pk = request.data["role"]
        users = request.data["users"]
        role = get_object_or_404(CustomRole, pk=pk)
        for user_id in users:
            user = get_object_or_404(User, pk=user_id)
            user.roles.remove(role)
        return Response({"Сообщение": "Успешно"})
    
# Разрешения
class PermissionView(APIView):
    permission_classes = [AdminOnly]
    # выдаем список разрешений
    def get(self, request, *args, **kwargs):
        permissions = CustomPermission.objects.all()
        return Response(PermissionSerializer(permissions, many=True).data)

    # создаем новое разрешение
    def post(self, request, *args, **kwargs):
        serializer = PermissionSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
# Изменить разрешение
class ChangePermissionView(APIView):
    # Только для админа
    permission_classes = [AdminOnly]

    def put(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Сообщение": "такого разрешения нет"})
        permission = get_object_or_404(CustomPermission, pk=pk)
        serializer = PermissionSerializer(data=request.data, instance=permission, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        pk = request.data['pk']
        if not pk:
            return Response({"Сообщение": "такого разрешения не существует"})
        permission = get_object_or_404(CustomPermission, pk=pk)
        permission.delete()
        return Response({"Сообщение": "Браво, разрешение удалено"})
