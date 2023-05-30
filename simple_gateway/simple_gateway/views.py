import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from simple_gateway.models import (
    Service,
    SSOAuthenticated,
    SSOAuthRequest,
    authenticated_auth_token_generator,
)

logger = logging.getLogger(__name__)


@dataclass
class JWTData:
    username: Optional[str] = None
    pk: Optional[int] = None
    is_staff: Optional[bool] = None
    exp: Optional[datetime] = None


def build_url(
    host: str = "",
    scheme: str = "",
    netloc: str = "",
    path: str = "",
    query: str = "",
    fragment: str = "",
) -> str:
    if host:
        parts = urlsplit(host)
        scheme = parts.scheme
        netloc = parts.netloc
    url = urlunsplit((scheme, netloc, path, query, fragment))
    logger.debug(f"Built url: {url}")
    return url


@login_required
def index(request: HttpRequest) -> HttpResponse:
    sso_authenticated = SSOAuthenticated.objects.filter(user=request.user).first()
    return HttpResponse(
        f'You authorized in gateway as <b>{request.user.username}</b> <a href="http://127.0.0.1:8001/?auth_token={sso_authenticated.auth_token}"> link</a>'
    )


@csrf_exempt
@require_http_methods(["POST"])
def sso_auth(request: HttpRequest) -> HttpResponse:
    """
    Create JWT token with authenticated user data
    """
    logger.debug("Validate auth token")
    json_body = json.loads(request.body)
    if "auth_token" not in json_body:
        return HttpResponse("Bad request", statu=400)

    auth_token = json_body["auth_token"]

    sso_auth_request = SSOAuthRequest.objects.filter(auth_token=auth_token).first()
    if not sso_auth_request:
        logger.error("Received incorrect auth token")
        return HttpResponse("Incorrect auth  token", statu=400)

    logger.debug("Creat user SSO authenticated record")
    sso_authenticated = SSOAuthenticated(
        service=sso_auth_request.service,
        user=sso_auth_request.user,
    )
    sso_authenticated.save()

    logger.debug("Remove SSO authenticate request")
    sso_auth_request.delete()

    logger.debug("Create JWT token")
    encoded = jwt.encode(
        JWTData(
            username=sso_authenticated.user.username,
            pk=sso_authenticated.user.pk,
            is_staff=sso_authenticated.user.is_staff,
            exp=datetime.now() + timedelta(minutes=settings.JWT_TTL_MINUTES),
        ).__dict__,
        settings.PRIVATE_KEY,
        algorithm="RS256",
    )
    return JsonResponse({"access_token": encoded})


@csrf_exempt
@require_http_methods(["POST"])
def sso_validate_auth(request: HttpRequest) -> HttpResponse:
    logger.debug("Validate auth token")
    json_body = json.loads(request.body)
    if "auth_token" not in json_body:
        return HttpResponse("Bad request", statu=400)

    auth_token = json_body["auth_token"]

    sso_authenticated = SSOAuthenticated.objects.filter(auth_token=auth_token).first()
    if not sso_authenticated:
        return HttpResponse("Unauthorized", status=401)

    sso_authenticated.auth_token = authenticated_auth_token_generator()
    sso_authenticated.save()
    try:
        encoded = jwt.encode(
            JWTData(
                username=sso_authenticated.user.username,
                pk=sso_authenticated.user.pk,
                is_staff=sso_authenticated.user.is_staff,
                exp=datetime.now() + timedelta(minutes=settings.JWT_TTL_MINUTES),
            ).__dict__,
            settings.PRIVATE_KEY,
            algorithm="RS256",
        )
        return JsonResponse({"access_token": encoded})
    except jwt.ExpiredSignatureError as e:
        logger.debug(e)
        return HttpResponse("Expired", status=401)


@csrf_exempt
@require_http_methods(["POST"])
def sso_validate_access(request: HttpRequest) -> HttpResponse:
    json_body = json.loads(request.body)
    if "access_token" not in json_body:
        return HttpResponse("Bad request", statu=400)

    access_token = json_body["access_token"]

    decoded = jwt.decode(access_token, settings.PUBLIC_KEY, algorithms=["RS256"])
    return JsonResponse(decoded)


def do_sso_login(request: HttpRequest, user: User) -> HttpResponse:
    """
    Validate SSO token and take related service.
    Create SSO Auth Request
    """
    service = Service.objects.filter(
        enabled=True, sso_token=request.session["sso_token"]
    ).first()
    if not service:
        return JsonResponse({"error": "Service token doesn't exist"})

    sso_auth_request = SSOAuthRequest(service=service, user=user)
    sso_auth_request.save()
    return redirect(
        f"{service.base_url}/sso/accept/?auth_token={sso_auth_request.auth_token}&next={request.session['next']}"
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def sso_login(request: HttpRequest) -> HttpResponse:
    """
    Show login form on GET request and do login on post request
    """
    request.session["sso_token"] = (
        request.GET["sso_token"] if "sso_token" in request.GET else ""
    )
    request.session["next"] = request.GET["next"] if "next" in request.GET else ""

    if request.method == "POST":
        form = AuthenticationForm(request.POST)
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(username=username, password=password)

        if user:
            if user.is_active:
                auth_login(request, user)
                if request.session["sso_token"]:
                    return do_sso_login(request=request, user=user)
                return redirect("/")

        else:
            logger.debug("Incorrect credentials")
            return redirect(
                f'/accounts/login?sso_token={request.session["sso_token"]}&next={request.session["next"]}'
            )

    if not request.user.is_anonymous:
        return do_sso_login(request=request, user=request.user)

    form = AuthenticationForm()

    return render(request, "registration/login.html", {"form": form})
