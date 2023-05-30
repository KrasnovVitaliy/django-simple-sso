import logging
import re
from copy import copy
from typing import Dict
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

import requests
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.http import require_http_methods

logger = logging.getLogger(__name__)


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
    logger.debug("Built url: %s", url)
    return url


@login_required(login_url="/sso/login")
def index(request):
    return HttpResponse(f'{("You authorized as")} <b>{request.user}</b>.')


@require_http_methods(["GET"])
def sso_accept(request: HttpRequest) -> HttpResponse:
    """
    Accept sso auth data
    """

    if "auth_token" not in request.GET:
        logger.debug("No auth token in requet")
        return redirect(reverse("sso_login"))

    auth_token = request.GET["auth_token"]

    # Try to extract next path redirect to after login
    next_path = (
        request.GET["next"] if "next" in request.GET else settings.DEFULT_REDIRECT_URL
    )

    logger.debug("Send auth request to gateway")
    rsp = requests.post(
        build_url(host=settings.SSO_SERVER, path="/sso/auth"),
        json={"auth_token": auth_token},
    )
    if rsp.status_code != 200:
        logger.debug("sso auth failed. redirect to: %s", reverse("sso_login"))
        return redirect(reverse("sso_login"))

    logger.debug("Save acess token to session")
    access_token = rsp.json()["access_token"]
    request.session["access_token"] = access_token

    user_data = decode_access_token(access_token=access_token)
    if not user_data:
        return redirect(reverse("sso_login"))

    user = build_user(user_data=user_data)
    logger.debug("Created user: %s", user)
    login(request, user)

    # Auth success redirect to main page
    return redirect(next_path)


def extract_from_query_string(pattern: str, query_str: str) -> str:
    match = re.search(pattern, query_str)
    found_str = match.group() if match else ""
    if not found_str:
        return ""
    values = found_str.split("=")
    return values[-1]


@require_http_methods(["GET"])
def sso_login(request: WSGIRequest) -> HttpResponse:
    """
    Login over SSO
    """
    query_str = request.environ["QUERY_STRING"]
    logger.debug(query_str)
    auth_token = extract_from_query_string(
        pattern=r"auth_token=[^&]+", query_str=unquote(query_str)
    )
    if auth_token:
        logger.debug("Found auth_token: %s", auth_token)

        rsp = requests.post(
            build_url(host=settings.SSO_SERVER, path="sso/validate/auth"),
            json={"auth_token": auth_token},
        )
        logger.debug(rsp)
        if rsp.status_code != 200 or "access_token" not in rsp.json():
            return redirect(
                build_url(
                    host=settings.SSO_SERVER,
                    path="/accounts/login",
                    query=f"sso_token={settings.SSO_TOKEN}&next=/",
                )
            )

        user_data = decode_access_token(access_token=rsp.json()["access_token"])
        if not user_data:
            return redirect(reverse("sso_login"))

        user = build_user(user_data=user_data)
        logger.debug("Created user: %s", user)
        login(request, user)

        # Auth success redirect to main page
        next_path = extract_from_query_string(
            pattern=r"next=[^?]+", query_str=unquote(query_str)
        )
        logger.debug("next path: %s", next_path)
        return redirect(next_path)

    if "sso_auth_token" in request.GET:
        logger.debug("Found SSO auth token")

    return redirect(
        build_url(
            host=settings.SSO_SERVER,
            path="/accounts/login",
            query=f"sso_token={settings.SSO_TOKEN}&next=/",
        )
    )


def decode_access_token(access_token: str) -> Dict | None:
    logger.debug("Found access token. Decode access_token")
    rsp = requests.post(
        build_url(host=settings.SSO_SERVER, path="sso/validate/access"),
        json={"access_token": access_token},
    )
    if rsp.status_code == 200:
        return rsp.json()

    logger.debug("Could not decode access tokent")
    return None


def build_user(user_data: Dict) -> User:
    try:
        user = User.objects.get(username=user_data["username"])
        # Update user data, excluding username changes
        # Work on copied _tmp dict to keep an untouched user_data
        user_data_tmp = copy(user_data)
        del user_data_tmp["username"]
        for _attr, _val in user_data_tmp.items():
            setattr(user, _attr, _val)
    except User.DoesNotExist:
        user = User(**user_data)
    user.set_unusable_password()
    user.save()
    return user
