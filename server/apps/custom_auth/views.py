from __future__ import annotations

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods

from apps.audit.log import EventType, TargetType, get_client_ip, log_event
from apps.custom_auth.lockout import clear_failures, is_locked_out, record_failure

_LOCKOUT_ERROR = "Too many failed attempts. Please try again later."


@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    error: str | None = None

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        ip = get_client_ip(request)

        if is_locked_out(username, ip):
            error = _LOCKOUT_ERROR
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                clear_failures(username)
                log_event(
                    EventType.USER_LOGIN,
                    request=request,
                    actor_user=user,
                    target_type=TargetType.USER,
                    target_id=str(user.pk),
                    target_repr=str(user),
                    properties={"via": "password"},
                )
                next_url = request.POST.get("next") or request.GET.get("next") or ""
                if not url_has_allowed_host_and_scheme(
                    url=next_url,
                    allowed_hosts={request.get_host()},
                    require_https=request.is_secure(),
                ):
                    next_url = settings.LOGIN_REDIRECT_URL
                return redirect(next_url)

            record_failure(username, ip)
            log_event(
                EventType.USER_LOGIN_FAILED,
                request=request,
                properties={"username": username},
            )
            error = "Invalid username or password."

    return render(
        request,
        "custom_auth/login.html",
        {
            "error": error,
            "next": request.GET.get("next", ""),
        },
    )


@require_http_methods(["POST"])
def logout_view(request: HttpRequest) -> HttpResponse:
    log_event(
        EventType.USER_LOGOUT,
        request=request,
        target_type=TargetType.USER,
        target_id=str(request.user.pk),
        target_repr=str(request.user),
    )
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)
