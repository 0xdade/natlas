from __future__ import annotations

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from apps.audit.log import EventType, TargetType, log_event
from apps.custom_auth.models.user import User


class OIDCBackend(OIDCAuthenticationBackend):
    """OIDC authentication backend wired to the custom User model.

    Users are matched by email address. New accounts are created with no
    local password — they authenticate exclusively via the configured IdP.
    Existing local accounts with the same email are linked automatically on
    first OIDC login.
    """

    def create_user(self, claims: dict[str, object]) -> User:
        email = self.get_username(claims)
        user = User.objects.create_user(email)
        log_event(
            EventType.USER_CREATED,
            request=self.request,
            target_type=TargetType.USER,
            target_id=str(user.pk),
            target_repr=str(user),
            properties={"via": "oidc"},
        )
        return user

    def update_user(self, user: User, claims: dict[str, object]) -> User:
        return user

    def authenticate(self, request: object, **kwargs: object) -> User | None:
        user = super().authenticate(request, **kwargs)  # type: ignore[arg-type]
        if user is not None:
            log_event(
                EventType.USER_LOGIN,
                request=self.request,
                actor_user=user,
                target_type=TargetType.USER,
                target_id=str(user.pk),
                target_repr=str(user),
                properties={"via": "oidc"},
            )
        return user
