"""SAML logout stages - dynamically injected"""

from celery import group
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from structlog.stdlib import get_logger

from rest_framework.fields import CharField, DictField, IntegerField, ListField
from authentik.flows.challenge import Challenge, ChallengeResponse
from authentik.flows.exceptions import StageInvalidException
from authentik.flows.stage import ChallengeStageView, StageView
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.tasks import send_saml_logout_request

LOGGER = get_logger()


class SAMLLogoutMethod:
    """SAML logout method choices"""
    REDIRECT = "redirect"
    IFRAME = "iframe"
    NONE = "none"


class SAMLLogoutStageView(StageView):
    """SAML Logout stage - handles both front-channel and back-channel SAML logout"""

    def dispatch(self, request: HttpRequest) -> HttpResponse:
        """Start SAML logout for both front-channel and back-channel providers"""

        # Check if SAML logout was already completed
        if request.session.get("_saml_logout_complete", False):
            LOGGER.debug("SAML logout already completed, continuing flow")
            # Don't clean up the marker here - let UserLogoutStage handle it
            return self.executor.stage_ok()

        # Check if user is authenticated
        if not request.user.is_authenticated:
            LOGGER.debug("User not authenticated, skipping SAML logout")
            return self.executor.stage_ok()

        # Get the actual user object (handle SimpleLazyObject)
        user = request.user
        if hasattr(user, "_wrapped"):
            actual_user = user._wrapped
            if actual_user is None:
                _ = user.pk
                actual_user = user
        else:
            actual_user = user

        # Send logout requests to back-channel (POST binding) providers
        post_providers = SAMLProvider.objects.filter(
            application__isnull=False, sls_url__isnull=False, sls_binding=SAMLBindings.POST
        ).exclude(sls_url="")

        if post_providers.exists():
            LOGGER.info(
                "Sending SAML back-channel logout requests",
                user=actual_user,
                provider_count=post_providers.count(),
            )

            # Send logout requests asynchronously
            logout_tasks = group(
                send_saml_logout_request.s(provider.pk, actual_user.pk)
                for provider in post_providers
            )
            logout_tasks.apply_async()

        # Check for SAML providers with redirect binding
        redirect_providers = SAMLProvider.objects.filter(
            application__isnull=False, sls_url__isnull=False, sls_binding=SAMLBindings.REDIRECT
        ).exclude(sls_url="")

        if redirect_providers.exists():
            LOGGER.info(
                "SAML front-channel providers found, redirecting to logout chain",
                user=request.user,
                provider_count=redirect_providers.count(),
            )

            # Store a marker to continue the flow after SAML logout
            # We'll use this to skip the SAML logout stage when we return
            request.session["_saml_logout_complete"] = True
            # Store the flow executor URL to return to after SAML logout
            from django.urls import reverse
            flow_url = reverse(
                "authentik_core:if-flow",
                kwargs={"flow_slug": self.executor.flow.slug}
            )
            request.session["_saml_logout_return_to"] = flow_url
            request.session.save()

            # Redirect to SAML front-channel logout
            return redirect("authentik_providers_saml:saml-logout-front-channel")

        # No redirect providers, continue with flow
        LOGGER.debug("No SAML redirect providers, continuing flow")
        return self.executor.stage_ok()



class SAMLIFrameChallenge(Challenge):
    """Challenge for SAML iframe logout"""

    component = CharField(default="ak-stage-saml-iframe-logout")
    logout_urls = ListField(child=DictField())
    timeout = IntegerField()


class SAMLIFrameChallengeResponse(ChallengeResponse):
    """Response to SAML iframe challenge"""

    component = CharField(default="ak-stage-saml-iframe-logout")


class SAMLIframeLogoutStageView(ChallengeStageView):
    """SAML iframe logout stage - handles SAML logout using iframes"""

    response_class = SAMLIFrameChallengeResponse

    def get_challenge(self, **kwargs) -> Challenge:
        # Get the actual user object
        user = self.request.user
        if hasattr(user, "_wrapped"):
            actual_user = user._wrapped
            if actual_user is None:
                _ = user.pk
                actual_user = user
        else:
            actual_user = user

        # Get all SAML providers
        providers = SAMLProvider.objects.filter(
            application__isnull=False,
            sls_url__isnull=False,
            sls_binding__in=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        ).exclude(sls_url="")

        if not providers.exists():
            LOGGER.debug("No SAML providers require iframe logout")
            self.request.session["_saml_logout_complete"] = True
            self.request.session.save()
            # This is a bit of a hack, but we need to short-circuit the flow here
            # since we're not actually showing a challenge.
            raise StageInvalidException("No providers for iframe logout.")


        logout_urls = []

        # Import here to avoid circular imports
        from authentik.providers.saml.processors.logout_request import LogoutRequestProcessor
        from authentik.sources.saml.processors.constants import SAML_NAME_ID_FORMAT_EMAIL
        from urllib.parse import urlencode

        for provider in providers:
            try:
                # Determine NameID
                name_id = actual_user.email
                name_id_format = SAML_NAME_ID_FORMAT_EMAIL

                if provider.name_id_mapping:
                    try:
                        value = provider.name_id_mapping.evaluate(
                            user=actual_user,
                            request=self.request,
                            provider=provider,
                        )
                        if value is not None:
                            name_id = str(value)
                    except Exception as exc:
                        LOGGER.warning(
                            "Failed to evaluate name_id_mapping", exc=exc, provider=provider
                        )

                # Create logout request processor
                processor = LogoutRequestProcessor(
                    provider=provider,
                    user=actual_user,
                    destination=provider.sls_url,
                    name_id=name_id,
                    name_id_format=name_id_format,
                    relay_state=None,
                )

                # Handle different bindings
                if provider.sls_binding == SAMLBindings.POST:
                    saml_request_encoded = processor.encode_post()
                    logout_urls.append({
                        "url": provider.sls_url,
                        "saml_request": saml_request_encoded,
                        "provider_name": provider.name,
                        "binding": "POST",
                    })
                elif provider.sls_binding == SAMLBindings.REDIRECT:
                    saml_request_encoded = processor.encode_redirect()
                    params = {"SAMLRequest": saml_request_encoded}
                    if "?" in provider.sls_url:
                        full_url = f"{provider.sls_url}&{urlencode(params)}"
                    else:
                        full_url = f"{provider.sls_url}?{urlencode(params)}"
                    logout_urls.append({
                        "url": full_url,
                        "provider_name": provider.name,
                        "binding": "REDIRECT",
                    })

                LOGGER.info(
                    "Added provider for iframe logout",
                    provider=provider.name,
                    binding=provider.sls_binding,
                )

            except Exception as exc:
                LOGGER.warning(
                    "Failed to generate logout URL for provider",
                    provider=provider.name,
                    exc=exc,
                )
                continue

        # Get timeout
        timeout = getattr(self.executor.current_stage, "iframe_timeout", 5000)

        return SAMLIFrameChallenge(data={
            "logout_urls": logout_urls,
            "timeout": timeout,
        })

    def challenge_valid(self, response: ChallengeResponse) -> HttpResponse:
        """Challenge successfully submitted"""
        self.request.session["_saml_logout_complete"] = True
        self.request.session.save()
        return self.executor.stage_ok()

    def challenge_invalid(self, response: ChallengeResponse) -> HttpResponse:
        """Challenge failed, cancel flow"""
        return self.executor.stage_invalid()



class SAMLCombinedLogoutStageView(StageView):
    """Combined SAML logout stage that can switch between redirect and iframe methods

    Inherits from SAMLIframeLogoutStageView to reuse its iframe logout logic.
    """

    def get_logout_method(self) -> str:
        """Get the logout method from the user logout stage configuration"""
        # This will be set when the stage is dynamically injected
        return getattr(self.executor.current_stage, "logout_method", SAMLLogoutMethod.REDIRECT)

    def dispatch(self, request: HttpRequest) -> HttpResponse:
        """Choose between redirect and iframe logout based on configuration"""
        logout_method = self.get_logout_method()

        if logout_method == SAMLLogoutMethod.IFRAME:
            iframe_stage = SAMLIframeLogoutStageView(self.executor)
            iframe_stage.request = request
            iframe_stage.kwargs = self.kwargs
            # Pass the current stage so iframe_timeout can be accessed
            iframe_stage.executor.current_stage = self.executor.current_stage
            return iframe_stage.dispatch(request)

        # For redirect method, use the original redirect chain logic
        redirect_stage = SAMLLogoutStageView(self.executor)
        redirect_stage.request = request
        redirect_stage.kwargs = self.kwargs
        return redirect_stage.dispatch(request)
