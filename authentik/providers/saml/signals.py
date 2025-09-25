"""SAML Provider signals"""

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from structlog.stdlib import get_logger

from authentik.core.models import AuthenticatedSession, User
from authentik.flows.models import in_memory_stage
from authentik.flows.signals import flow_pre_user_logout
from authentik.providers.saml.models import SAMLSession
from authentik.providers.saml.tasks import send_saml_logout_request
from authentik.providers.saml.views.flows import PLAN_CONTEXT_SAML_LOGOUT_SESSIONS
from authentik.stages.user_logout.models import UserLogoutStage

LOGGER = get_logger()


@receiver(flow_pre_user_logout)
def handle_flow_pre_user_logout(sender, request, user, executor, **kwargs):
    """Handle SAML logout when user logs out via flow"""

    # Only proceed if this is actually a UserLogoutStage
    if not isinstance(executor.current_stage, UserLogoutStage):
        return

    try:
        auth_session = AuthenticatedSession.from_request(request, user)
    except ValueError:
        LOGGER.debug("No authenticated session found for SAML logout")
        return

    if not auth_session:
        return

    # Get frontchannel SAML sessions that need logout
    frontchannel_sessions = SAMLSession.objects.filter(
        session=auth_session,
        user=user,
        expires__gt=timezone.now(),
        expiring=True,
        provider__sls_url__isnull=False,
    ).exclude(
        provider__logout_method="backchannel"
    ).select_related("provider")

    if not frontchannel_sessions.exists():
        LOGGER.debug("No SAML sessions requiring frontchannel logout")
        return

    # Prepare session data for logout stages
    session_data = [
        {
            "provider_pk": str(session.provider.pk),
            "session_index": session.session_index,
            "name_id": session.name_id,
            "name_id_format": session.name_id_format,
        }
        for session in frontchannel_sessions
    ]

    # Store in flow plan context
    executor.plan.context[PLAN_CONTEXT_SAML_LOGOUT_SESSIONS] = session_data

    # Inject appropriate SAML logout stage based on configuration
    # Check if any session uses redirect method
    uses_redirect = any(
        SAMLSession.objects.filter(
            session=auth_session,
            provider__pk=session["provider_pk"],
            provider__logout_method="frontchannel_redirect"
        ).exists()
        for session in session_data
    )

    if uses_redirect:
        from authentik.providers.saml.idp_logout import SAMLLogoutStageView

        saml_stage = in_memory_stage(SAMLLogoutStageView)
    else:
        from authentik.providers.saml.idp_logout import SAMLIframeLogoutStageView

        saml_stage = in_memory_stage(SAMLIframeLogoutStageView)

    executor.plan.insert_stage(saml_stage)

    LOGGER.debug(
        "Injected SAML logout stage via signal",
        user=user,
        session_count=len(session_data),
        stage_type=saml_stage.__class__.__name__,
    )


@receiver(pre_delete, sender=AuthenticatedSession)
def user_session_deleted_saml_logout(sender, instance: AuthenticatedSession, **_):
    """Send SAML logout requests for providers that support backchannel logout
    via POST request when user session is deleted"""

    saml_sessions = SAMLSession.objects.filter(
        session=instance,
        provider__sls_url__isnull=False,
        provider__logout_method="backchannel",
        provider__sls_binding="post",
    ).select_related("provider", "user")

    for saml_session in saml_sessions:
        LOGGER.info(
            "Triggering backchannel SAML logout for deleted user session",
            user=saml_session.user,
            provider=saml_session.provider.name,
            session_index=saml_session.session_index,
        )

        send_saml_logout_request.send(
            provider_pk=saml_session.provider.pk,
            sls_url=saml_session.provider.sls_url,
            name_id=saml_session.name_id,
            name_id_format=saml_session.name_id_format,
            session_index=saml_session.session_index,
        )


@receiver(post_save, sender=User)
def user_deactivated_saml_logout(sender, instance: User, **kwargs):
    """Send SAML logout requests when user is deactivated"""
    if instance.is_active:
        return

    saml_sessions = SAMLSession.objects.filter(
        user=instance,
        provider__sls_url__isnull=False,
        provider__logout_method="backchannel",
        provider__sls_binding="post",
    ).select_related("provider")

    for saml_session in saml_sessions:
        LOGGER.info(
            "Triggering backchannel SAML logout for deactivated user",
            user=instance,
            provider=saml_session.provider.name,
            session_index=saml_session.session_index,
        )

        send_saml_logout_request.send(
            provider_pk=saml_session.provider.pk,
            sls_url=saml_session.provider.sls_url,
            name_id=saml_session.name_id,
            name_id_format=saml_session.name_id_format,
            session_index=saml_session.session_index,
        )
