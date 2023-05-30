from django.contrib.auth.models import User
from django.db import models
from django.utils.crypto import get_random_string


def token_generator():
    return get_random_string(Service.sso_token.field.max_length)


def service_sso_token_generator():
    return get_random_string(Service.sso_token.field.max_length)


def auth_request_auth_token_generator():
    return get_random_string(SSOAuthRequest.auth_token.field.max_length)


def authenticated_auth_token_generator():
    return get_random_string(SSOAuthenticated.auth_token.field.max_length)


class Service(models.Model):
    name = models.CharField(max_length=128, verbose_name="Name")
    base_url = models.URLField(verbose_name="Base url")
    enabled = models.BooleanField(default=False, verbose_name="Enabled")
    sso_token = models.CharField(
        max_length=36, verbose_name="SSOToken", unique=True, default=token_generator
    )


class SSOAuthRequest(models.Model):
    service = models.ForeignKey(
        Service, on_delete=models.CASCADE, verbose_name="Service"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="User")
    auth_token = models.CharField(
        max_length=36, verbose_name="AuthToken", unique=True, default=token_generator
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created at")


class SSOAuthenticated(models.Model):
    service = models.ForeignKey(
        Service, on_delete=models.CASCADE, verbose_name="Service"
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="User")
    auth_token = models.CharField(
        max_length=36, verbose_name="AuthToken", unique=True, default=token_generator
    )  # Uses to generate personal link
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created at")
