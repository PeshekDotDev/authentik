"""Logout stage logic"""

from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse

from authentik.flows.models import in_memory_stage
from authentik.flows.stage import StageView
from authentik.providers.saml.models import SAMLProvider


class UserLogoutStageView(StageView):
    """Finalise Authentication flow by logging the user in"""

    def should_inject_saml_logout(self) -> bool:
        """Check if user has any SAML sessions or providers"""
        # Check if we already injected SAML stage in this flow execution
        if self.request.session.get("_saml_stage_injected", False):
            return False
            
        # Check if SAML logout was already completed
        if self.request.session.get("_saml_logout_complete", False):
            return False
            
        # Check for any SAML providers with logout configured
        return SAMLProvider.objects.filter(
            application__isnull=False,
            sls_url__isnull=False,
        ).exclude(sls_url="").exists()

    def inject_saml_logout_stage(self) -> HttpResponse:
        """Dynamically inject SAML logout stage into the flow"""
        from authentik.providers.saml.stages.logout import SAMLCombinedLogoutStageView
        from authentik.stages.user_logout.models import UserLogoutStage, SAMLLogoutMethod
        
        # Get configuration from current stage
        stage: UserLogoutStage = self.executor.current_stage
        
        # Skip SAML logout if method is NONE
        if stage.saml_logout_method == SAMLLogoutMethod.NONE:
            return self.dispatch_logout()
        
        # Determine logout method from tenant setting
        tenant = self.request.tenant
        logout_method = stage.saml_logout_method
        
        # Override with tenant preference if logout method is not explicitly set to NONE
        if logout_method != SAMLLogoutMethod.NONE:
            if tenant.enable_iframe_saml_logout:
                logout_method = SAMLLogoutMethod.IFRAME
            else:
                logout_method = SAMLLogoutMethod.REDIRECT
        
        # For redirect method, handle it directly without injecting stages
        if logout_method == SAMLLogoutMethod.REDIRECT:
            # Mark that logout should happen after SAML
            self.request.session["_logout_after_saml"] = True
            self.request.session.save()
            
            # Redirect directly to SAML logout
            from django.shortcuts import redirect
            return redirect("authentik_providers_saml:saml-logout-front-channel")
        
        # For iframe method, inject stage as before
        saml_stage = in_memory_stage(
            SAMLCombinedLogoutStageView,
            logout_method=logout_method,
            iframe_timeout=stage.saml_logout_timeout,
            use_session_tracking=stage.saml_use_session_tracking,
        )
        
        # Mark that we've injected the SAML stage
        self.request.session["_saml_stage_injected"] = True
        self.request.session.save()
        
        # Insert it as the next stage
        self.executor.plan.insert_stage(saml_stage)
        
        # Continue to the injected stage
        return self.executor.stage_ok()
    
    def dispatch_logout(self) -> HttpResponse:
        """Perform the actual logout"""
        self.logger.debug(
            "Logged out",
            user=self.request.user,
            flow_slug=self.executor.flow.slug,
        )
        logout(self.request)
        return self.executor.stage_ok()

    def dispatch(self, request: HttpRequest) -> HttpResponse:
        """Remove the user from the current session"""
        # Check if SAML logout was completed - if so, clean up and proceed to logout
        if request.session.get("_saml_logout_complete", False):
            self.logger.debug(
                "SAML logout completed, proceeding to authentik logout",
                user=request.user,
                flow_slug=self.executor.flow.slug,
            )
            # Clean up the markers
            if "_saml_logout_complete" in request.session:
                del request.session["_saml_logout_complete"]
            if "_saml_stage_injected" in request.session:
                del request.session["_saml_stage_injected"]
            request.session.save()
            # Proceed to logout
            return self.dispatch_logout()
        
        # Check if we need to inject SAML logout BEFORE logging out
        if request.user.is_authenticated and self.should_inject_saml_logout():
            # Don't logout yet - inject SAML stage first
            self.logger.debug(
                "Injecting SAML logout stage",
                user=request.user,
                flow_slug=self.executor.flow.slug,
            )
            return self.inject_saml_logout_stage()
        
        # Clean up any stale session flags before logout
        if "_saml_logout_complete" in request.session:
            del request.session["_saml_logout_complete"]
        if "_saml_stage_injected" in request.session:
            del request.session["_saml_stage_injected"]
        request.session.save()
        
        # Now actually log out the user
        return self.dispatch_logout()
