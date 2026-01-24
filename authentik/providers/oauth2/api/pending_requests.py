"""Pending OAuth2 Request API views for multi-tab session resumption"""

from urllib.parse import urlencode

from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.fields import CharField, ListField, UUIDField
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from structlog.stdlib import get_logger

from authentik.providers.oauth2.models import PendingOAuth2Request

LOGGER = get_logger()


class PendingOAuth2RequestSerializer(serializers.ModelSerializer):
    """Serializer for PendingOAuth2Request"""

    provider_name = serializers.CharField(source="provider.name", read_only=True)
    application_name = serializers.SerializerMethodField()

    class Meta:
        model = PendingOAuth2Request
        fields = [
            "request_id",
            "device_id",
            "provider_name",
            "application_name",
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
            "tab_id",
            "is_leader",
            "created_at",
            "expires",
        ]
        read_only_fields = fields

    def get_application_name(self, obj):
        try:
            return obj.provider.application.name if obj.provider.application else None
        except Exception:
            return None


class PendingOAuth2RequestViewSet(ViewSet):
    """ViewSet for managing pending OAuth2 requests for multi-tab session resumption"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="List pending OAuth2 requests",
        description="List all pending OAuth2 requests for the current device",
        responses={
            200: inline_serializer(
                name="PendingOAuth2RequestListResponse",
                fields={
                    "pending_requests": ListField(
                        child=inline_serializer(
                            name="PendingRequestInfo",
                            fields={
                                "request_id": UUIDField(),
                                "client_id": CharField(),
                                "provider_name": CharField(),
                                "application_name": CharField(allow_null=True),
                                "redirect_uri": CharField(),
                                "authorization_url": CharField(),
                            },
                        )
                    )
                },
            )
        },
    )
    def list(self, request: Request) -> Response:
        """List pending OAuth2 requests for the current device"""
        device_id = request.COOKIES.get("authentik_device")
        if not device_id:
            return Response({"pending_requests": []})

        pending = PendingOAuth2Request.objects.filter(
            device_id=device_id,
            expires__gt=timezone.now(),
        ).select_related("provider", "provider__application")

        requests = []
        for req in pending:
            try:
                app_name = req.provider.application.name if req.provider.application else None
                app_slug = req.provider.application.slug if req.provider.application else None
            except Exception:
                app_name = None
                app_slug = None

            # Build the authorization URL for resuming this flow
            authorization_url = self._build_authorization_url(request, req, app_slug)

            requests.append({
                "request_id": str(req.request_id),
                "client_id": req.client_id,
                "provider_name": req.provider.name,
                "application_name": app_name,
                "redirect_uri": req.redirect_uri,
                "authorization_url": authorization_url,
            })

        return Response({"pending_requests": requests})

    @extend_schema(
        summary="Resume a pending OAuth2 request",
        description="Get the authorization URL to resume a specific pending OAuth2 request",
        responses={
            200: inline_serializer(
                name="PendingOAuth2RequestResumeResponse",
                fields={
                    "authorization_url": CharField(),
                    "request_id": UUIDField(),
                },
            ),
            404: inline_serializer(
                name="PendingOAuth2RequestNotFoundResponse",
                fields={"detail": CharField()},
            ),
        },
    )
    @action(detail=True, methods=["get"])
    def resume(self, request: Request, pk=None) -> Response:
        """Get the authorization URL to resume a pending OAuth2 request"""
        device_id = request.COOKIES.get("authentik_device")

        try:
            pending_request = PendingOAuth2Request.objects.get(
                request_id=pk,
                expires__gt=timezone.now(),
            )
        except PendingOAuth2Request.DoesNotExist:
            return Response(
                {"detail": "Pending request not found or expired"},
                status=404,
            )

        # Verify device ID matches (security check)
        if pending_request.device_id != device_id:
            LOGGER.warning(
                "Device ID mismatch for pending request",
                request_id=str(pk),
                expected_device=pending_request.device_id,
                actual_device=device_id,
            )
            return Response(
                {"detail": "Pending request not found or expired"},
                status=404,
            )

        try:
            app_slug = (
                pending_request.provider.application.slug
                if pending_request.provider.application
                else None
            )
        except Exception:
            app_slug = None

        authorization_url = self._build_authorization_url(request, pending_request, app_slug)

        # Delete the pending request after successful resume
        pending_request.delete()

        LOGGER.info(
            "Resumed pending OAuth2 request",
            request_id=str(pk),
            device_id=device_id,
        )

        return Response({
            "authorization_url": authorization_url,
            "request_id": str(pk),
        })

    @extend_schema(
        summary="Clear pending OAuth2 requests",
        description="Clear all pending OAuth2 requests for the current device",
        responses={
            200: inline_serializer(
                name="PendingOAuth2RequestClearResponse",
                fields={"deleted_count": serializers.IntegerField()},
            )
        },
    )
    @action(detail=False, methods=["delete"])
    def clear(self, request: Request) -> Response:
        """Clear all pending OAuth2 requests for the current device"""
        device_id = request.COOKIES.get("authentik_device")
        if not device_id:
            return Response({"deleted_count": 0})

        deleted_count, _ = PendingOAuth2Request.objects.filter(
            device_id=device_id,
        ).delete()

        LOGGER.info(
            "Cleared pending OAuth2 requests",
            device_id=device_id,
            deleted_count=deleted_count,
        )

        return Response({"deleted_count": deleted_count})

    def _build_authorization_url(
        self,
        request: HttpRequest,
        pending_request: PendingOAuth2Request,
        app_slug: str | None,
    ) -> str:
        """Build the OAuth2 authorization URL for resuming a pending request"""
        # Build query parameters
        params = {
            "client_id": pending_request.client_id,
            "redirect_uri": pending_request.redirect_uri,
            "response_type": pending_request.response_type,
            "scope": " ".join(pending_request.scope),
        }

        if pending_request.state:
            params["state"] = pending_request.state
        if pending_request.nonce:
            params["nonce"] = pending_request.nonce
        if pending_request.response_mode:
            params["response_mode"] = pending_request.response_mode
        if pending_request.code_challenge:
            params["code_challenge"] = pending_request.code_challenge
        if pending_request.code_challenge_method:
            params["code_challenge_method"] = pending_request.code_challenge_method

        # Build the authorization URL
        if app_slug:
            base_url = request.build_absolute_uri(
                reverse(
                    "authentik_providers_oauth2:authorize",
                )
            )
        else:
            base_url = request.build_absolute_uri(
                reverse("authentik_providers_oauth2:authorize")
            )

        return f"{base_url}?{urlencode(params)}"
