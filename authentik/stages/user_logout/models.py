"""logout stage models"""

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.views import View
from rest_framework.serializers import BaseSerializer

from authentik.flows.models import Stage


class SAMLLogoutMethod(models.TextChoices):
    """SAML logout method choices"""
    REDIRECT = "redirect", _("Redirect Chain")
    IFRAME = "iframe", _("Iframe (Parallel)")
    NONE = "none", _("Disabled")


class UserLogoutStage(Stage):
    """Resets the users current session."""

    # SAML-specific fields
    saml_logout_method = models.CharField(
        max_length=20,
        choices=SAMLLogoutMethod.choices,
        default=SAMLLogoutMethod.REDIRECT,
        help_text=_("Method to use for SAML provider logout")
    )
    
    saml_logout_timeout = models.IntegerField(
        default=5000,
        help_text=_("Timeout in milliseconds for SAML logout operations")
    )
    
    saml_use_session_tracking = models.BooleanField(
        default=False,
        help_text=_("Only logout from SAML providers the user has active sessions with")
    )

    @property
    def serializer(self) -> type[BaseSerializer]:
        from authentik.stages.user_logout.api import UserLogoutStageSerializer

        return UserLogoutStageSerializer

    @property
    def view(self) -> type[View]:
        from authentik.stages.user_logout.stage import UserLogoutStageView

        return UserLogoutStageView

    @property
    def component(self) -> str:
        return "ak-stage-user-logout-form"

    class Meta:
        verbose_name = _("User Logout Stage")
        verbose_name_plural = _("User Logout Stages")
