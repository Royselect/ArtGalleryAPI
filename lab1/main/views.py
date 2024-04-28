from .models import User, Token, TwoFactorAuthCode, CustomSession
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
from .serializers import UserSerializer, TokenSerializer
from django.conf import settings
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt import token_blacklist
from datetime import datetime
from pytz import utc
import pyotp
import qrcode

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