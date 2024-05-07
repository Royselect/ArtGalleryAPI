from models import LogiFromMethods
from permissions import custom_get_user
import django.dispatch

request_finished = django.dispatch.Signal(providing_args=["request", "response"])

def log_methods_use(request, method_name):
    user = custom_get_user(request)
    LogiFromMethods.objects.create(method_name = method_name, user=user)

def log_methods_use(sender, **kwargs):
    request = kwargs.get("request")
    method_name = request.resolver_match.view_name
    user = custom_get_user(request)
    LogiFromMethods.objects.create(user=user, method_name=method_name)

request_finished.connect(log_methods_use)