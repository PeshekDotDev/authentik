"""SAML Provider tasks"""

import requests
from django.contrib.auth import get_user_model
from django.http import HttpResponseBadRequest
from dramatiq.actor import actor
from structlog.stdlib import get_logger

from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.processors.logout_request import LogoutRequestProcessor

LOGGER = get_logger()
User = get_user_model()


@actor(description="Send SAML LogoutRequest to a Service Provider")
def send_saml_logout_request(
    provider_pk: int,
    sls_url: str,
    name_id: str,
    name_id_format: str,
    session_index: str,
) -> bool:
    """Send SAML LogoutRequest to a Service Provider using session data"""
    provider = SAMLProvider.objects.filter(pk=provider_pk).first()
    if not provider:
        LOGGER.error(
            "Provider not found for SAML logout request",
            provider_pk=provider_pk,
            session_index=session_index,
        )
        return False

    try:
        LOGGER.debug(
            "Sending SAML logout request",
            provider=provider.name,
            session_index=session_index,
        )

        # Create the logout request processor with the provided data
        # Note: We don't need the user object for the logout request itself
        processor = LogoutRequestProcessor(
            provider=provider,
            user=None,  # User might be deleted already
            destination=sls_url,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
        )

        success = send_post_logout_request(provider, processor)

        return success

    except Exception as exc:
        LOGGER.error(
            "Failed to send SAML logout request",
            exc=exc,
            provider_pk=provider_pk,
            session_index=session_index,
        )
        return False


def send_post_logout_request(provider: SAMLProvider, processor: LogoutRequestProcessor) -> bool:
    """Send LogoutRequest using POST binding"""
    try:
        encoded_request = processor.encode_post()

        # Create form data
        form_data = {
            "SAMLRequest": encoded_request,
        }

        # Add RelayState if present
        if processor.relay_state:
            form_data["RelayState"] = processor.relay_state

        # Send POST request
        response = requests.post(
            provider.sls_url,
            data=form_data,
            timeout=10,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        LOGGER.debug(
            "Sent POST logout request",
            provider=provider,
            status_code=response.status_code,
        )

        return response.status_code < HttpResponseBadRequest.status_code

    except Exception as exc:
        LOGGER.error("Failed to send POST logout request", exc=exc, provider=provider)
        return False
