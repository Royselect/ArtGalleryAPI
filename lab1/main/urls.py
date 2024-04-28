from django.contrib import admin
from django.urls import path, include
from . import views
from rest_framework.authtoken.views import obtain_auth_token
from .views import LoginView, Register, SecureClass, LogoutView, ConfirmLoginView, LogoutFromAllView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', Register.as_view(), name='reg'),
    path('logout/', LogoutView.as_view(), name='user_out'),
    path('authorization/', LoginView.as_view(), name='auth'),
    path('sec/', SecureClass.as_view(), name='sec'),
    path('confirm/', ConfirmLoginView.as_view(), name='confirm'),
    path('delsessions/', LogoutFromAllView.as_view(), name='delses'),
]