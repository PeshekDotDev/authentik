"""SAML logout stages - dynamically injected"""

from celery import group
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from structlog.stdlib import get_logger
from urllib.parse import urlencode

from authentik.flows.stage import StageView
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.logout_request import LogoutRequestProcessor
from authentik.providers.saml.tasks import send_saml_logout_request
from authentik.sources.saml.processors.constants import SAML_NAME_ID_FORMAT_EMAIL

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


class SAMLIframeLogoutStageView(StageView):
    """SAML iframe logout stage - handles SAML logout using iframes"""

    def dispatch(self, request: HttpRequest) -> HttpResponse:
        """Handle dispatch for iframe logout"""
        # Check if user is authenticated
        if not request.user.is_authenticated:
            LOGGER.debug("User not authenticated, skipping SAML iframe logout")
            # Mark SAML logout as complete and continue
            request.session["_saml_logout_complete"] = True
            request.session.save()
            return self.executor.stage_ok()

        # Return HTML page with iframes
        return self.render_iframe_logout(request)

    def render_iframe_logout(self, request: HttpRequest) -> HttpResponse:
        """Generate HTML page with logout iframes"""

        # Get the actual user object (handle SimpleLazyObject)
        user = request.user
        if hasattr(user, "_wrapped"):
            actual_user = user._wrapped
            if actual_user is None:
                _ = user.pk
                actual_user = user
        else:
            actual_user = user

        # Get all SAML providers that need iframe logout
        # Support both POST and REDIRECT bindings
        providers = SAMLProvider.objects.filter(
            application__isnull=False,
            sls_url__isnull=False,
            sls_binding__in=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        ).exclude(sls_url="")

        LOGGER.info(
            "Found SAML providers for iframe logout",
            provider_count=providers.count(),
            providers=[(p.name, p.sls_binding) for p in providers],
        )

        logout_urls = []

        for provider in providers:
            try:
                # Determine NameID
                name_id = actual_user.email
                name_id_format = SAML_NAME_ID_FORMAT_EMAIL

                if provider.name_id_mapping:
                    try:
                        value = provider.name_id_mapping.evaluate(
                            user=actual_user,
                            request=request,
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
                    # Generate SAML request for POST binding
                    saml_request_encoded = processor.encode_post()
                    # For POST binding, we need the URL and SAML request data
                    logout_urls.append(
                        {
                            "url": provider.sls_url,
                            "saml_request": saml_request_encoded,
                            "provider_name": provider.name,
                            "binding": "POST",
                        }
                    )
                elif provider.sls_binding == SAMLBindings.REDIRECT:
                    # Generate SAML request for REDIRECT binding
                    saml_request_encoded = processor.encode_redirect()
                    # For REDIRECT binding, build the full URL with query parameters
                    params = {
                        "SAMLRequest": saml_request_encoded,
                    }
                    # Check if sls_url already has query parameters
                    if "?" in provider.sls_url:
                        # URL already has query params, append with &
                        full_url = f"{provider.sls_url}&{urlencode(params)}"
                    else:
                        # No query params yet, add with ?
                        full_url = f"{provider.sls_url}?{urlencode(params)}"
                    logout_urls.append(
                        {
                            "url": full_url,
                            "provider_name": provider.name,
                            "binding": "REDIRECT",
                        }
                    )

                LOGGER.info(
                    "Added provider for iframe logout",
                    provider=provider.name,
                    binding=provider.sls_binding,
                    sls_url=provider.sls_url,
                    name_id=name_id,
                )

            except Exception as exc:
                LOGGER.warning(
                    "Failed to generate logout URL for provider",
                    provider=provider.name,
                    exc=exc,
                )
                continue

        if not logout_urls:
            LOGGER.info("No providers require iframe logout")
            # No URLs to logout from, just continue the flow
            request.session["_saml_logout_complete"] = True
            request.session.save()
            return self.executor.stage_ok()

        # Get timeout from stage configuration
        # When injected dynamically, we'll pass timeout as a parameter
        timeout = getattr(self.executor.current_stage, "iframe_timeout", 5000)

        # Mark SAML logout as complete - the iframes will run but we'll continue immediately
        request.session["_saml_logout_complete"] = True
        request.session.save()

        LOGGER.info(
            "Returning iframe logout page",
            provider_count=len(logout_urls),
            timeout=timeout,
        )

        # Generate HTML with iframes for each logout URL
        html_parts = []
        html_parts.append('<!DOCTYPE html>')
        html_parts.append('<html>')
        html_parts.append('<head>')
        html_parts.append('<title>SAML Logout</title>')
        html_parts.append('<meta charset="utf-8">')
        html_parts.append('</head>')
        html_parts.append('<body>')
        html_parts.append('<div style="text-align: center; padding: 2rem;">')
        html_parts.append('<h2>Logging out of SAML providers...</h2>')
        html_parts.append(f'<p>This will complete in {timeout/1000} seconds</p>')

        # Add hidden iframes for each logout URL
        for i, logout_data in enumerate(logout_urls):
            if logout_data["binding"] == "REDIRECT":
                # For redirect binding, just use iframe src
                html_parts.append(
                    f'<iframe src="{logout_data["url"]}" style="display: none;" '
                    f'id="saml-logout-{i}"></iframe>'
                )
            else:
                # For POST binding, create form and submit it
                form_id = f"saml-form-{i}"
                iframe_id = f"saml-iframe-{i}"
                html_parts.append(
                    f'<iframe name="{iframe_id}" style="display: none;"></iframe>'
                )
                html_parts.append(
                    f'<form id="{form_id}" method="POST" '
                    f'action="{logout_data["url"]}" target="{iframe_id}">'
                )
                html_parts.append(
                    f'<input type="hidden" name="SAMLRequest" '
                    f'value="{logout_data["saml_request"]}">'
                )
                html_parts.append('</form>')
                html_parts.append(
                    f'<script>document.getElementById("{form_id}").submit();</script>'
                )

        # Add script to continue after timeout
        from django.urls import reverse
        flow_url = reverse(
            "authentik_core:if-flow",
            kwargs={"flow_slug": self.executor.flow.slug}
        )
        
        html_parts.append(f'''
        <script>
        setTimeout(function() {{
            // Continue the flow after the timeout
            window.location.href = "{flow_url}";
        }}, {timeout});
        </script>
        </div>
        </body>
        </html>''')

        # Return the HTML response directly
        return HttpResponse("".join(html_parts), content_type="text/html")


class SAMLCombinedLogoutStageView(SAMLIframeLogoutStageView):
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

        # For redirect method, use the original redirect chain logic
        if logout_method == SAMLLogoutMethod.REDIRECT:
            redirect_stage = SAMLLogoutStageView(self.executor)
            redirect_stage.request = request
            redirect_stage.kwargs = self.kwargs
            return redirect_stage.dispatch(request)

        # For iframe method, use parent's dispatch
        return super().dispatch(request)
