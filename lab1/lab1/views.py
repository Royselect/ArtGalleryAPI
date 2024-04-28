from django.shortcuts import render
from django.contrib.auth import logout
from django.contrib.auth import login, authenticate
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
#from .forms import RegForm, LoginForm
from django.views.decorators.csrf import csrf_protect
#from .forms import PostsForm
#from .models import MarksPost
#from bookmark.forms import BookAddMarksForm

