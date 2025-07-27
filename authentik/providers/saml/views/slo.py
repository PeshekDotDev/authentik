"""SLO Views"""

from urllib.parse import urlencode

from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.csrf import csrf_exempt
from structlog.stdlib import get_logger

from authentik.core.models import Application
from authentik.events.models import Event, EventAction
from authentik.flows.exceptions import FlowNonApplicableException
from authentik.flows.models import Flow, in_memory_stage
from authentik.flows.planner import PLAN_CONTEXT_APPLICATION, FlowPlanner
from authentik.flows.stage import SessionEndStage
from authentik.lib.views import bad_request_message
from authentik.policies.views import PolicyAccessView
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.logout_request import LogoutRequestProcessor
from authentik.providers.saml.processors.logout_request_parser import LogoutRequestParser
from authentik.providers.saml.views.flows import (
    REQUEST_KEY_RELAY_STATE,
    REQUEST_KEY_SAML_REQUEST,
    REQUEST_KEY_SAML_RESPONSE,
    SESSION_KEY_LOGOUT_REQUEST,
)

LOGGER = get_logger()


class SAMLSLOView(PolicyAccessView):
    """ "SAML SLO Base View, which plans a flow and injects our final stage.
    Calls get/post handler."""

    flow: Flow

    def resolve_provider_application(self):
        self.application = get_object_or_404(Application, slug=self.kwargs["application_slug"])
        self.provider: SAMLProvider = get_object_or_404(
            SAMLProvider, pk=self.application.provider_id
        )
        self.flow = self.provider.invalidation_flow or self.request.brand.flow_invalidation
        if not self.flow:
            raise Http404

    def check_saml_request(self) -> HttpRequest | None:
        """Handler to verify the SAML Request. Must be implemented by a subclass"""
        raise NotImplementedError

    def get(self, request: HttpRequest, application_slug: str) -> HttpResponse:
        """Verify the SAML Request, and if valid initiate the FlowPlanner for the application"""
        # Call the method handler, which checks the SAML
        # Request and returns a HTTP Response on error
        method_response = self.check_saml_request()
        if method_response:
            return method_response

        # Check if we have a logout request in the session (SP-initiated logout)
        if SESSION_KEY_LOGOUT_REQUEST in request.session:
            # SP-initiated logout - start the logout flow but skip SAML logout
            LOGGER.info("Processing SP-initiated logout request")

            # Clear the logout request from session
            del request.session[SESSION_KEY_LOGOUT_REQUEST]

            # Set flag to skip SAML logout stage if it's in the flow
            # This prevents logging out of other SAML providers
            request.session["_saml_logout_complete"] = True

            # Start the logout flow
            planner = FlowPlanner(self.flow)
            planner.allow_empty_flows = True
            try:
                plan = planner.plan(
                    request,
                    {
                        PLAN_CONTEXT_APPLICATION: self.application,
                    },
                )
            except FlowNonApplicableException:
                raise Http404 from None

            # Execute the logout flow
            plan.append_stage(in_memory_stage(SessionEndStage))
            return plan.to_redirect(request, self.flow)

        # If no SAML request and user is authenticated, this is IDP-initiated logout
        if request.user.is_authenticated:
            return self.handle_idp_initiated_logout()

        # If user is not authenticated and no SAML data, redirect to root
        return redirect("authentik_core:root-redirect")

    def handle_idp_initiated_logout(self) -> HttpResponse:
        """Handle IDP-initiated logout"""
        if not self.provider.sls_url:
            LOGGER.error(
                "No SLS URL configured for IDP-initiated logout",
                provider=self.provider,
                application=self.application,
            )
            return bad_request_message(self.request, "Provider does not support logout")

        LOGGER.info(
            "Starting IDP-initiated logout",
            user=self.request.user,
            provider=self.provider,
            application=self.application,
        )

        # Create a LogoutRequest to send to the SP
        logout_processor = LogoutRequestProcessor(
            provider=self.provider,
            user=self.request.user,
            destination=self.provider.sls_url,
            relay_state=None,  # No relay state for IDP-initiated
        )

        # Determine binding type and send appropriately
        if self.provider.sls_binding == SAMLBindings.REDIRECT:
            # Redirect binding - send via URL parameters
            saml_request = logout_processor.encode_redirect()
            params = {
                "SAMLRequest": saml_request,
            }

            # Check if the destination URL already has query parameters
            if "?" in self.provider.sls_url:
                redirect_url = f"{self.provider.sls_url}&{urlencode(params)}"
            else:
                redirect_url = f"{self.provider.sls_url}?{urlencode(params)}"

            return redirect(redirect_url)
        else:
            # POST binding - send via auto-submit form
            saml_request = logout_processor.encode_post()

            html = f"""
            <html>
                <body onload="document.forms[0].submit()">
                    <form method="post" action="{self.provider.sls_url}">
                        <input type="hidden" name="SAMLRequest" value="{saml_request}" />
                        <noscript>
                            <input type="submit" value="Continue" />
                        </noscript>
                    </form>
                </body>
            </html>
            """

            return HttpResponse(html, content_type="text/html")

    def post(self, request: HttpRequest, application_slug: str) -> HttpResponse:
        """GET and POST use the same handler, but we can't
        override .dispatch easily because PolicyAccessView's dispatch"""
        return self.get(request, application_slug)

    def handle_logout_response(self, params) -> HttpResponse:
        """Handle incoming LogoutResponse from SP"""
        # Log the response for auditing
        Event.new(
            EventAction.LOGOUT,
            message="Received SAML logout response",
            provider=self.provider,
        ).save()

        LOGGER.info("Received SAML logout response", provider=self.provider)

        # Check if we have a RelayState that indicates this is part of front-channel logout
        # params is a QueryDict, not a regular dict
        relay_state = params.get(REQUEST_KEY_RELAY_STATE, "")
        LOGGER.info(
            "Processing logout response with RelayState",
            relay_state=relay_state,
            has_relay_state=bool(relay_state),
            relay_state_length=len(relay_state) if relay_state else 0,
            contains_continue=("logout/saml/continue/" in relay_state) if relay_state else False,
        )

        if relay_state:
            # Always honor RelayState if present
            LOGGER.info("Redirecting to RelayState URL", relay_state=relay_state)
            return redirect(relay_state)

        # Otherwise, redirect to a logout success page or home
        LOGGER.info("No RelayState found, redirecting to root")
        return redirect("authentik_core:root-redirect")


class SAMLSLOBindingRedirectView(SAMLSLOView):
    """SAML Handler for SLO/Redirect bindings, which are sent via GET"""

    def check_saml_request(self) -> HttpRequest | None:
        # Check if this is a LogoutResponse
        if REQUEST_KEY_SAML_RESPONSE in self.request.GET:
            # Handle LogoutResponse
            return self.handle_logout_response(self.request.GET)

        if REQUEST_KEY_SAML_REQUEST not in self.request.GET:
            # No SAML data - this could be IDP-initiated logout
            LOGGER.debug("No SAML request/response in URL")
            return None

        try:
            logout_request = LogoutRequestParser(self.provider).parse_detached(
                self.request.GET[REQUEST_KEY_SAML_REQUEST],
                relay_state=self.request.GET.get(REQUEST_KEY_RELAY_STATE, None),
            )
            self.request.session[SESSION_KEY_LOGOUT_REQUEST] = logout_request
        except CannotHandleAssertion as exc:
            Event.new(
                EventAction.CONFIGURATION_ERROR,
                provider=self.provider,
                message=str(exc),
            ).save()
            LOGGER.info(str(exc))
            return bad_request_message(self.request, str(exc))
        return None


@method_decorator(xframe_options_sameorigin, name="dispatch")
@method_decorator(csrf_exempt, name="dispatch")
class SAMLSLOBindingPOSTView(SAMLSLOView):
    """SAML Handler for SLO/POST bindings"""

    def check_saml_request(self) -> HttpRequest | None:
        payload = self.request.POST

        # Check if this is a LogoutResponse
        if REQUEST_KEY_SAML_RESPONSE in payload:
            # Handle LogoutResponse
            return self.handle_logout_response(payload)

        if REQUEST_KEY_SAML_REQUEST not in payload:
            # No SAML data - this could be IDP-initiated logout
            LOGGER.debug("No SAML request/response in POST data")
            return None

        try:
            logout_request = LogoutRequestParser(self.provider).parse(
                payload[REQUEST_KEY_SAML_REQUEST],
                relay_state=payload.get(REQUEST_KEY_RELAY_STATE, None),
            )
            self.request.session[SESSION_KEY_LOGOUT_REQUEST] = logout_request
        except CannotHandleAssertion as exc:
            LOGGER.info(str(exc))
            return bad_request_message(self.request, str(exc))
        return None

    def handle_logout_response(self, payload) -> HttpResponse:
        """Handle incoming LogoutResponse from SP"""
        # Log the response for auditing
        Event.new(
            EventAction.LOGOUT,
            message="Received SAML logout response",
            provider=self.provider,
        ).save()

        LOGGER.info("Received SAML logout response", provider=self.provider)

        # Check if we have a RelayState that indicates this is part of front-channel logout
        # payload is a QueryDict
        relay_state = payload.get(REQUEST_KEY_RELAY_STATE, "")
        LOGGER.info(
            "Processing logout response with RelayState",
            relay_state=relay_state,
            has_relay_state=bool(relay_state),
            relay_state_length=len(relay_state) if relay_state else 0,
            contains_continue=("logout/saml/continue/" in relay_state) if relay_state else False,
        )

        # Otherwise, redirect to a logout success page or home
        LOGGER.info("No RelayState found, redirecting to root")
        return redirect("authentik_core:root-redirect")
