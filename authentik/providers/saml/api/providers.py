"""SAMLProvider API Views"""

from copy import copy
from xml.etree.ElementTree import ParseError  # nosec

from defusedxml.ElementTree import fromstring
from django.http import HttpRequest
from django.http.response import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from guardian.shortcuts import get_objects_for_user
from requests import RequestException
from rest_framework.decorators import action
from rest_framework.fields import CharField, FileField, SerializerMethodField
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import PrimaryKeyRelatedField, ValidationError
from rest_framework.viewsets import ModelViewSet
from structlog.stdlib import get_logger

from authentik.api.validation import validate
from authentik.common.saml.constants import SAML_BINDING_POST, SAML_BINDING_REDIRECT
from authentik.core.api.providers import ProviderSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import PassiveSerializer, PropertyMappingPreviewSerializer
from authentik.core.models import Provider
from authentik.crypto.models import KeyType
from authentik.flows.models import Flow, FlowDesignation
from authentik.lib.utils.http import get_http_session
from authentik.providers.saml.models import SAMLLogoutMethods, SAMLProvider
from authentik.providers.saml.processors.assertion import AssertionProcessor
from authentik.providers.saml.processors.authn_request_parser import AuthNRequest
from authentik.providers.saml.processors.metadata import MetadataProcessor
from authentik.providers.saml.processors.metadata_parser import ServiceProviderMetadataParser
from authentik.rbac.decorators import permission_required

LOGGER = get_logger()


class RawXMLDataRenderer(BaseRenderer):
    """Renderer to allow application/xml as value for 'Accept' in the metadata endpoint."""

    media_type = "application/xml"
    format = "xml"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data


class SAMLProviderSerializer(ProviderSerializer):
    """SAMLProvider Serializer"""

    url_download_metadata = SerializerMethodField()

    url_sso_post = SerializerMethodField()
    url_sso_redirect = SerializerMethodField()
    url_sso_init = SerializerMethodField()
    url_slo_post = SerializerMethodField()
    url_slo_redirect = SerializerMethodField()

    def get_url_download_metadata(self, instance: SAMLProvider) -> str:
        """Get metadata download URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:metadata-download",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return request.build_absolute_uri(
                reverse(
                    "authentik_api:samlprovider-metadata",
                    kwargs={
                        "pk": instance.pk,
                    },
                )
                + "?download"
            )

    def get_url_sso_post(self, instance: SAMLProvider) -> str:
        """Get SSO Post URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-post",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_sso_redirect(self, instance: SAMLProvider) -> str:
        """Get SSO Redirect URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-redirect",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_sso_init(self, instance: SAMLProvider) -> str:
        """Get SSO IDP-Initiated URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-init",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_slo_post(self, instance: SAMLProvider) -> str:
        """Get SLO POST URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:slo-post",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_slo_redirect(self, instance: SAMLProvider) -> str:
        """Get SLO redirect URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:slo-redirect",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def validate(self, attrs: dict):
        signing_kp = attrs.get("signing_kp")
        if signing_kp:
            if not attrs.get("sign_assertion") and not attrs.get("sign_response"):
                raise ValidationError(
                    _(
                        "With a signing keypair selected, at least one of 'Sign assertion' "
                        "and 'Sign Response' must be selected."
                    )
                )

            key_type = signing_kp.key_type

            if key_type and key_type not in [KeyType.RSA, KeyType.EC, KeyType.DSA]:
                raise ValidationError(
                    {
                        "signing_kp": _(
                            "Only RSA, EC, and DSA key types are supported for SAML signing."
                        )
                    }
                )

        # Validate logout_method - backchannel is only available with POST SLS binding
        if (
            attrs.get("logout_method") == SAMLLogoutMethods.BACKCHANNEL
            and attrs.get("sls_binding") == SAML_BINDING_REDIRECT
        ):
            # Auto-correct to frontchannel_iframe
            attrs["logout_method"] = SAMLLogoutMethods.FRONTCHANNEL_IFRAME

        return super().validate(attrs)

    class Meta:
        model = SAMLProvider
        fields = ProviderSerializer.Meta.fields + [
            "acs_url",
            "sls_url",
            "audience",
            "issuer",
            "metadata_url",
            "assertion_valid_not_before",
            "assertion_valid_not_on_or_after",
            "session_valid_not_on_or_after",
            "property_mappings",
            "name_id_mapping",
            "authn_context_class_ref_mapping",
            "digest_algorithm",
            "signature_algorithm",
            "signing_kp",
            "verification_kp",
            "encryption_kp",
            "sign_assertion",
            "sign_response",
            "sign_logout_request",
            "sp_binding",
            "sls_binding",
            "logout_method",
            "default_relay_state",
            "default_name_id_policy",
            "url_download_metadata",
            "url_sso_post",
            "url_sso_redirect",
            "url_sso_init",
            "url_slo_post",
            "url_slo_redirect",
        ]
        extra_kwargs = ProviderSerializer.Meta.extra_kwargs


class SAMLMetadataSerializer(PassiveSerializer):
    """SAML Provider Metadata serializer"""

    metadata = CharField(read_only=True)
    download_url = CharField(read_only=True, required=False)


class SAMLProviderImportSerializer(PassiveSerializer):
    """Import saml provider from XML Metadata"""

    name = CharField(required=True)
    authorization_flow = PrimaryKeyRelatedField(
        queryset=Flow.objects.filter(designation=FlowDesignation.AUTHORIZATION),
    )
    invalidation_flow = PrimaryKeyRelatedField(
        queryset=Flow.objects.filter(designation=FlowDesignation.INVALIDATION),
    )
    file = FileField(required=False)
    url = CharField(required=False)

    def validate(self, attrs):
        if not attrs.get("file") and not attrs.get("url"):
            raise ValidationError(_("Either file or url must be provided"))
        if attrs.get("file") and attrs.get("url"):
            raise ValidationError(_("Provide either file or url, not both"))
        return attrs


class SAMLProviderViewSet(UsedByMixin, ModelViewSet):
    """SAMLProvider Viewset"""

    queryset = SAMLProvider.objects.all()
    serializer_class = SAMLProviderSerializer
    filterset_fields = "__all__"
    ordering = ["name"]
    search_fields = ["name"]

    metadata_generator_class = MetadataProcessor

    @extend_schema(
        responses={
            200: SAMLMetadataSerializer(many=False),
            404: OpenApiResponse(description="Provider has no application assigned"),
        },
        parameters=[
            OpenApiParameter(
                name="download",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="force_binding",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                enum=[
                    SAML_BINDING_REDIRECT,
                    SAML_BINDING_POST,
                ],
                description="Optionally force the metadata to only include one binding.",
            ),
            # Explicitly excluded, because otherwise spectacular automatically
            # add it when using multiple renderer_classes
            OpenApiParameter(
                name="format",
                exclude=True,
                required=False,
            ),
        ],
    )
    @action(
        methods=["GET"],
        detail=True,
        permission_classes=[AllowAny],
        renderer_classes=[JSONRenderer, RawXMLDataRenderer],
    )
    def metadata(self, request: Request, pk: int) -> Response:
        """Return metadata as XML string"""
        # We don't use self.get_object() on purpose as this view is un-authenticated
        try:
            provider = get_object_or_404(SAMLProvider, pk=pk)
        except ValueError:
            raise Http404 from None
        try:
            proc = self.metadata_generator_class(provider, request)
            proc.force_binding = request.query_params.get("force_binding", None)
            metadata = proc.build_entity_descriptor()
            if "download" in request.query_params:
                response = HttpResponse(metadata, content_type="application/xml")
                response["Content-Disposition"] = (
                    f'attachment; filename="{provider.name}_authentik_meta.xml"'
                )
                return response
            return Response({"metadata": metadata}, content_type="application/json")
        except Provider.application.RelatedObjectDoesNotExist:
            return Response({"metadata": ""}, content_type="application/json")

    @permission_required(
        None,
        [
            "authentik_providers_saml.add_samlprovider",
            "authentik_crypto.add_certificatekeypair",
        ],
    )
    @extend_schema(
        request={
            "multipart/form-data": SAMLProviderImportSerializer,
        },
        responses={
            201: SAMLProviderSerializer,
            400: OpenApiResponse(description="Bad request"),
        },
    )
    @action(detail=False, methods=["POST"], parser_classes=(MultiPartParser,))
    @validate(SAMLProviderImportSerializer)
    def import_metadata(self, request: Request, body: SAMLProviderImportSerializer) -> Response:
        """Create provider from SAML Metadata"""
        metadata_url = body.validated_data.get("url")

        # Get raw XML from file or URL
        if metadata_url:
            try:
                response = get_http_session().get(metadata_url)
                response.raise_for_status()
                raw_xml = response.content
            except RequestException as exc:
                raise ValidationError(
                    _("Failed to fetch metadata from URL: {error}".format_map({"error": str(exc)}))
                ) from None
        else:
            file = body.validated_data["file"]
            raw_xml = file.read()

        # Validate syntax first
        try:
            fromstring(raw_xml)
        except ParseError:
            raise ValidationError(_("Invalid XML Syntax")) from None

        try:
            metadata = ServiceProviderMetadataParser().parse(raw_xml.decode())
            provider = metadata.to_provider(
                body.validated_data["name"],
                body.validated_data["authorization_flow"],
                body.validated_data["invalidation_flow"],
            )
            # Store metadata URL for future refresh
            if metadata_url:
                provider.metadata_url = metadata_url
                provider.save()
            # Return the created provider for use in workflows like the application wizard
            return Response(SAMLProviderSerializer(provider).data, status=201)
        except ValueError as exc:  # pragma: no cover
            LOGGER.warning(str(exc))
            raise ValidationError(
                _("Failed to import Metadata: {messages}".format_map({"messages": str(exc)})),
            ) from None

    @permission_required(
        None,
        ["authentik_providers_saml.change_samlprovider"],
    )
    @extend_schema(
        responses={
            200: SAMLProviderSerializer,
            400: OpenApiResponse(description="Bad request"),
        },
    )
    @action(detail=True, methods=["POST"])
    def refresh_metadata(self, request: Request, pk: int) -> Response:
        """Refresh provider metadata from stored URL"""
        provider: SAMLProvider = self.get_object()
        if not provider.metadata_url:
            raise ValidationError(_("No metadata URL configured for this provider"))

        try:
            response = get_http_session().get(provider.metadata_url)
            response.raise_for_status()
            raw_xml = response.content
        except RequestException as exc:
            raise ValidationError(
                _("Failed to fetch metadata: {error}".format_map({"error": str(exc)}))
            ) from None

        try:
            fromstring(raw_xml)
        except ParseError:
            raise ValidationError(_("Invalid XML Syntax")) from None

        try:
            metadata = ServiceProviderMetadataParser().parse(raw_xml.decode())
            # Update provider fields from refreshed metadata
            provider.issuer = metadata.entity_id
            provider.sp_binding = metadata.acs_binding
            provider.acs_url = metadata.acs_location
            provider.default_name_id_policy = metadata.name_id_policy
            if metadata.sls_location:
                provider.sls_url = metadata.sls_location
            if metadata.sls_binding:
                provider.sls_binding = metadata.sls_binding
            # Handle keypair updates if metadata contains them
            # Only update if the certificate has changed to avoid creating duplicates
            if metadata.signing_keypair and metadata.auth_n_request_signed:
                new_cert_data = metadata.signing_keypair.certificate_data
                existing_kp = provider.verification_kp
                if existing_kp and existing_kp.certificate_data == new_cert_data:
                    # Certificate unchanged, keep existing keypair
                    pass
                elif existing_kp:
                    # Certificate changed, update existing keypair
                    existing_kp.certificate_data = new_cert_data
                    existing_kp.save()
                else:
                    # No existing keypair, create new one
                    metadata.signing_keypair.name = (
                        f"Provider {provider.name} - SAML Signing Certificate"
                    )
                    metadata.signing_keypair.save()
                    provider.verification_kp = metadata.signing_keypair
            if metadata.encryption_keypair:
                new_cert_data = metadata.encryption_keypair.certificate_data
                existing_kp = provider.encryption_kp
                if existing_kp and existing_kp.certificate_data == new_cert_data:
                    # Certificate unchanged, keep existing keypair
                    pass
                elif existing_kp:
                    # Certificate changed, update existing keypair
                    existing_kp.certificate_data = new_cert_data
                    existing_kp.save()
                else:
                    # No existing keypair, create new one
                    metadata.encryption_keypair.name = (
                        f"Provider {provider.name} - SAML Encryption Certificate"
                    )
                    metadata.encryption_keypair.save()
                    provider.encryption_kp = metadata.encryption_keypair
            provider.save()
            return Response(SAMLProviderSerializer(provider).data)
        except ValueError as exc:
            raise ValidationError(
                _("Failed to parse metadata: {messages}".format_map({"messages": str(exc)}))
            ) from None

    @permission_required(
        "authentik_providers_saml.view_samlprovider",
    )
    @extend_schema(
        responses={
            200: PropertyMappingPreviewSerializer(),
            400: OpenApiResponse(description="Bad request"),
        },
        parameters=[
            OpenApiParameter(
                name="for_user",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.INT,
            )
        ],
    )
    @action(detail=True, methods=["GET"])
    def preview_user(self, request: Request, pk: int) -> Response:
        """Preview user data for provider"""
        provider: SAMLProvider = self.get_object()
        for_user = request.user
        if "for_user" in request.query_params:
            try:
                for_user = (
                    get_objects_for_user(request.user, "authentik_core.preview_user")
                    .filter(pk=request.query_params.get("for_user"))
                    .first()
                )
                if not for_user:
                    raise ValidationError({"for_user": "User not found"})
            except ValueError:
                raise ValidationError({"for_user": "input must be numerical"}) from None

        new_request = copy(request._request)
        new_request.user = for_user

        processor = AssertionProcessor(provider, new_request, AuthNRequest())
        attributes = processor.get_attributes()
        name_id = processor.get_name_id()
        data = []
        for attribute in attributes:
            item = {"Value": []}
            item.update(attribute.attrib)
            for value in attribute:
                item["Value"].append(value.text)
            data.append(item)
        serializer = PropertyMappingPreviewSerializer(
            instance={"preview": {"attributes": data, "nameID": name_id.text}}
        )
        return Response(serializer.data)
