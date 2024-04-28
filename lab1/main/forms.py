from django.contrib.auth import forms
from django.contrib.auth.models import User
from django import forms
#from django.db import models
#from .models import MarksPost
from django.forms import ModelForm, TextInput


class RegForm(forms.Form):
    username = forms.RegexField(regex="^[A-Za-z0-9-_]+$", min_length=3, label="Login", required=True)
    password1 = forms.RegexField(widget=forms.PasswordInput(),
    regex="(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z!@#$%^&*]{6,}",
    min_length=6, label='Пароль', required=True)
    password2 = forms.RegexField(widget=forms.PasswordInput(),
                                 regex="(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z!@#$%^&*]{6,}",
                                 min_length=6, label='Повторите пароль', required=True)

class LoginForm(forms.Form):
    username = forms.RegexField(regex="^[A-Za-z0-9-_]+$", min_length=3, label="Login", required=True)
    password = forms.RegexField(widget=forms.PasswordInput(),
                                regex="(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z!@#$%^&*]{6,}",
                                min_length=6, label='Password', required=True)