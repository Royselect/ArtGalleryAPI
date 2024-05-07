from typing import Any
from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import AbstractUser, UserManager, AbstractBaseUser, PermissionsMixin
# Create your models here.



class CustomUserManager(UserManager):
    def _create_user(self, email, name, password, **extra_fields):
        if not email:
            raise ValueError("You have not provided a valid e-mail address")
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        # user.set_name(name)
        user.set_password(password)
        user.save(using=self._db)

        return user
    
    def create_user(self, email=None, name=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, name, password, **extra_fields)
    
    def create_superuser(self, email=None,  name=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, name, password, **extra_fields)
    

class CustomPermission(models.Model):
    title = models.CharField(max_length=1000, null=False, unique=True)
    objects = CustomUserManager()
    def __str__(self):
        return f'{self.title}'

class CustomRole(models.Model):
    title = models.CharField(max_length=1000, null=False, unique=True)
    permissions = models.ManyToManyField(CustomPermission, related_name="permissions")
    #users = models.ManyToManyField(User, related_name="roles")
    objects = CustomUserManager()
    def __str__(self):
        return f'{self.title}'
    
class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=255)
    email = models.CharField(verbose_name="Email", max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = None
    roles = models.ManyToManyField(CustomRole, related_name="roles")
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def get_full_name(self):
        return self.name

    

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

class TwoFactorAuthCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

class CustomSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    token = models.CharField(max_length=1000, null=False)
    date_create = models.DateTimeField(auto_now_add=True, null=False)

class Artwork(models.Model):
    title = models.CharField(max_length=1000, null=False)
    description = models.CharField(max_length=1000, null=True, blank=True)
    artists = models.ManyToManyField(User, related_name='artworks')
    objects = CustomUserManager()

    def __str__(self):
        return f'{self.title}'
    
class LogiFromMethods(models.Model):
    method_name = models.CharField(max_length=100, null=False)
    user = models.ForeignKey(User, db_index=True, null=True, on_delete=models.CASCADE)
    usage_time = models.DateTimeField(auto_now_add=True)

    