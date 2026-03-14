from __future__ import annotations

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

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
        return User.objects.create_user(email)

    def update_user(self, user: User, claims: dict[str, object]) -> User:
        return user
