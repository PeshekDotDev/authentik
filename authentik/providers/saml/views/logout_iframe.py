"""SAML iframe logout view"""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views import View
from django.urls import reverse
from structlog.stdlib import get_logger
from urllib.parse import urlencode

from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.logout_request import LogoutRequestProcessor
from authentik.sources.saml.processors.constants import SAML_NAME_ID_FORMAT_EMAIL

LOGGER = get_logger()


class IframeLogoutView(View):
    """Handle SAML iframe logout"""

    def get(self, request: HttpRequest) -> HttpResponse:
        """Generate HTML page with logout iframes"""
        
        # Check if user is authenticated
        if not request.user.is_authenticated:
            LOGGER.debug("User not authenticated in iframe logout view")
            # Return to flow if we have a return URL
            return_to = request.session.pop("_saml_logout_return_to", None)
            if return_to:
                return redirect(return_to)
            return redirect(reverse("authentik_core:root-redirect"))

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
        providers = SAMLProvider.objects.filter(
            application__isnull=False,
            sls_url__isnull=False,
            sls_binding__in=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        ).exclude(sls_url="")

        LOGGER.info(
            "Generating iframe logout page",
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
                    params = {"SAMLRequest": saml_request_encoded}
                    if "?" in provider.sls_url:
                        full_url = f"{provider.sls_url}&{urlencode(params)}"
                    else:
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

        # Get timeout from session (set by stage)
        timeout = request.session.get("_saml_iframe_timeout", 5000)
        
        # Get return URL
        return_url = request.session.get("_saml_logout_return_to", 
                                         reverse("authentik_core:root-redirect"))

        # Generate HTML
        html_parts = []
        html_parts.append('<!DOCTYPE html>')
        html_parts.append('<html>')
        html_parts.append('<head>')
        html_parts.append('<title>SAML Logout</title>')
        html_parts.append('<meta charset="utf-8">')
        html_parts.append('<style>')
        html_parts.append('body { font-family: sans-serif; text-align: center; padding: 2rem; }')
        html_parts.append('.spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; ')
        html_parts.append('border-radius: 50%; width: 40px; height: 40px; ')
        html_parts.append('animation: spin 2s linear infinite; margin: 20px auto; }')
        html_parts.append('@keyframes spin { 0% { transform: rotate(0deg); } ')
        html_parts.append('100% { transform: rotate(360deg); } }')
        html_parts.append('</style>')
        html_parts.append('</head>')
        html_parts.append('<body>')
        html_parts.append('<h2>Logging out of SAML providers...</h2>')
        html_parts.append('<div class="spinner"></div>')
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

        # Add script to redirect after timeout
        html_parts.append(f'''
        <script>
        setTimeout(function() {{
            window.location.href = "{return_url}";
        }}, {timeout});
        </script>
        </body>
        </html>''')

        # Return the HTML response
        return HttpResponse("".join(html_parts), content_type="text/html")