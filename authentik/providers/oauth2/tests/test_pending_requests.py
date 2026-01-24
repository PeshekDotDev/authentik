"""Test pending OAuth2 requests for multi-tab session resumption"""

from datetime import timedelta

from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_flow
from authentik.lib.generators import generate_id
from authentik.providers.oauth2.models import (
    OAuth2Provider,
    PendingOAuth2Request,
    RedirectURI,
    RedirectURIMatchingMode,
)


class TestPendingOAuth2Request(TestCase):
    """Test PendingOAuth2Request model"""

    def setUp(self):
        self.flow = create_test_flow()
        self.provider = OAuth2Provider.objects.create(
            name=generate_id(),
            client_id="test-client",
            authorization_flow=self.flow,
            redirect_uris=[
                RedirectURI(RedirectURIMatchingMode.STRICT, "http://localhost/callback")
            ],
        )
        self.app = Application.objects.create(
            name="Test App",
            slug="test-app",
            provider=self.provider,
        )
        self.device_id = generate_id()

    def test_create_pending_request(self):
        """Test creating a pending request"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            scope={"openid", "profile"},
            state="test-state",
            nonce="test-nonce",
            expires=timezone.now() + timedelta(hours=24),
        )
        self.assertIsNotNone(pending.request_id)
        self.assertEqual(pending.device_id, self.device_id)
        self.assertEqual(pending.provider, self.provider)
        self.assertEqual(pending.scope, {"openid", "profile"})

    def test_scope_property(self):
        """Test scope property converts correctly"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            expires=timezone.now() + timedelta(hours=24),
        )
        # Set scope as list
        pending.scope = ["openid", "profile", "email"]
        pending.save()

        # Reload and check
        pending.refresh_from_db()
        self.assertEqual(pending.scope, {"openid", "profile", "email"})

    def test_to_authorization_params_dict(self):
        """Test converting to authorization params dict"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            response_mode="query",
            scope={"openid", "profile"},
            state="test-state",
            nonce="test-nonce",
            code_challenge="challenge123",
            code_challenge_method="S256",
            expires=timezone.now() + timedelta(hours=24),
        )

        params = pending.to_authorization_params_dict()
        self.assertEqual(params["client_id"], self.provider.client_id)
        self.assertEqual(params["redirect_uri"], "http://localhost/callback")
        self.assertEqual(params["response_type"], "code")
        self.assertEqual(params["response_mode"], "query")
        self.assertEqual(params["state"], "test-state")
        self.assertEqual(params["nonce"], "test-nonce")
        self.assertEqual(params["code_challenge"], "challenge123")
        self.assertEqual(params["code_challenge_method"], "S256")

    def test_expiration(self):
        """Test that expired requests are filtered out"""
        # Create expired request
        expired = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            expires=timezone.now() - timedelta(hours=1),
        )

        # Create valid request
        valid = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            expires=timezone.now() + timedelta(hours=24),
        )

        # Filter by expiration
        active = PendingOAuth2Request.objects.filter(
            device_id=self.device_id,
            expires__gt=timezone.now(),
        )
        self.assertEqual(active.count(), 1)
        self.assertEqual(active.first().request_id, valid.request_id)


class TestPendingRequestsAPI(TestCase):
    """Test pending requests API"""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = create_test_admin_user()
        self.flow = create_test_flow()
        self.provider = OAuth2Provider.objects.create(
            name=generate_id(),
            client_id="test-client",
            authorization_flow=self.flow,
            redirect_uris=[
                RedirectURI(RedirectURIMatchingMode.STRICT, "http://localhost/callback")
            ],
        )
        self.app = Application.objects.create(
            name="Test App",
            slug="test-app",
            provider=self.provider,
        )
        self.device_id = generate_id()

    def test_list_pending_requests(self):
        """Test listing pending requests"""
        # Create pending request
        PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            state="test-state",
            expires=timezone.now() + timedelta(hours=24),
        )

        self.client.force_login(self.user)
        self.client.cookies["authentik_device"] = self.device_id

        response = self.client.get(
            reverse("authentik_api:pendingoauth2request-list"),
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["pending_requests"]), 1)
        self.assertEqual(data["pending_requests"][0]["client_id"], "test-client")

    def test_list_pending_requests_no_device(self):
        """Test listing pending requests without device cookie"""
        self.client.force_login(self.user)

        response = self.client.get(
            reverse("authentik_api:pendingoauth2request-list"),
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["pending_requests"]), 0)

    def test_resume_pending_request(self):
        """Test resuming a pending request"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            state="test-state",
            scope={"openid"},
            expires=timezone.now() + timedelta(hours=24),
        )

        self.client.force_login(self.user)
        self.client.cookies["authentik_device"] = self.device_id

        response = self.client.get(
            reverse(
                "authentik_api:pendingoauth2request-resume",
                kwargs={"pk": str(pending.request_id)},
            ),
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("authorization_url", data)
        self.assertIn("client_id=test-client", data["authorization_url"])
        self.assertIn("state=test-state", data["authorization_url"])

        # Verify pending request was deleted after resume
        self.assertFalse(
            PendingOAuth2Request.objects.filter(request_id=pending.request_id).exists()
        )

    def test_resume_pending_request_wrong_device(self):
        """Test resuming a pending request with wrong device ID"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            expires=timezone.now() + timedelta(hours=24),
        )

        self.client.force_login(self.user)
        self.client.cookies["authentik_device"] = "wrong-device-id"

        response = self.client.get(
            reverse(
                "authentik_api:pendingoauth2request-resume",
                kwargs={"pk": str(pending.request_id)},
            ),
        )
        self.assertEqual(response.status_code, 404)

    def test_resume_expired_request(self):
        """Test resuming an expired pending request"""
        pending = PendingOAuth2Request.objects.create(
            device_id=self.device_id,
            provider=self.provider,
            client_id=self.provider.client_id,
            redirect_uri="http://localhost/callback",
            response_type="code",
            expires=timezone.now() - timedelta(hours=1),  # Expired
        )

        self.client.force_login(self.user)
        self.client.cookies["authentik_device"] = self.device_id

        response = self.client.get(
            reverse(
                "authentik_api:pendingoauth2request-resume",
                kwargs={"pk": str(pending.request_id)},
            ),
        )
        self.assertEqual(response.status_code, 404)

    def test_clear_pending_requests(self):
        """Test clearing all pending requests for device"""
        # Create multiple pending requests
        for _ in range(3):
            PendingOAuth2Request.objects.create(
                device_id=self.device_id,
                provider=self.provider,
                client_id=self.provider.client_id,
                redirect_uri="http://localhost/callback",
                response_type="code",
                expires=timezone.now() + timedelta(hours=24),
            )

        self.client.force_login(self.user)
        self.client.cookies["authentik_device"] = self.device_id

        response = self.client.delete(
            reverse("authentik_api:pendingoauth2request-clear"),
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["deleted_count"], 3)

        # Verify all requests were deleted
        self.assertEqual(
            PendingOAuth2Request.objects.filter(device_id=self.device_id).count(), 0
        )


class TestAuthorizeWithPendingRequests(TestCase):
    """Test OAuth2 authorize view stores pending requests"""

    def setUp(self):
        self.factory = RequestFactory()
        self.flow = create_test_flow()
        self.provider = OAuth2Provider.objects.create(
            name=generate_id(),
            client_id="test-client",
            authorization_flow=self.flow,
            redirect_uris=[
                RedirectURI(RedirectURIMatchingMode.STRICT, "http://localhost/callback")
            ],
        )
        self.app = Application.objects.create(
            name="Test App",
            slug="test-app",
            provider=self.provider,
        )
        self.device_id = generate_id()

    def test_prompt_none_stores_pending_request(self):
        """Test that prompt=none stores a pending request when user not authenticated"""
        self.client.cookies["authentik_device"] = self.device_id

        # Make request with prompt=none without being authenticated
        response = self.client.get(
            reverse("authentik_providers_oauth2:authorize"),
            data={
                "response_type": "code",
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "test-state",
                "scope": "openid",
                "prompt": "none",
            },
        )

        # Should return login_required error
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=login_required", response.url)

        # Should have stored a pending request
        pending = PendingOAuth2Request.objects.filter(
            device_id=self.device_id,
            provider=self.provider,
        ).first()
        self.assertIsNotNone(pending)
        self.assertEqual(pending.client_id, "test-client")
        self.assertEqual(pending.state, "test-state")
        self.assertEqual(pending.redirect_uri, "http://localhost/callback")

    def test_prompt_none_no_device_cookie(self):
        """Test that prompt=none without device cookie doesn't store pending request"""
        # Make request without device cookie
        response = self.client.get(
            reverse("authentik_providers_oauth2:authorize"),
            data={
                "response_type": "code",
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "test-state",
                "scope": "openid",
                "prompt": "none",
            },
        )

        # Should return login_required error
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=login_required", response.url)

        # Should NOT have stored a pending request
        self.assertEqual(PendingOAuth2Request.objects.count(), 0)

    def test_leader_election(self):
        """Test that first tab becomes the leader"""
        self.client.cookies["authentik_device"] = self.device_id

        # First request - should become leader
        self.client.get(
            reverse("authentik_providers_oauth2:authorize"),
            data={
                "response_type": "code",
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "prompt": "none",
                "tab_id": "tab-1",
            },
        )

        # Create another provider for second request
        provider2 = OAuth2Provider.objects.create(
            name=generate_id(),
            client_id="test-client-2",
            authorization_flow=self.flow,
            redirect_uris=[
                RedirectURI(RedirectURIMatchingMode.STRICT, "http://localhost/callback2")
            ],
        )
        Application.objects.create(
            name="Test App 2",
            slug="test-app-2",
            provider=provider2,
        )

        # Second request - should NOT become leader
        self.client.get(
            reverse("authentik_providers_oauth2:authorize"),
            data={
                "response_type": "code",
                "client_id": "test-client-2",
                "redirect_uri": "http://localhost/callback2",
                "prompt": "none",
                "tab_id": "tab-2",
            },
        )

        # Check leader status
        pending_requests = PendingOAuth2Request.objects.filter(
            device_id=self.device_id,
        ).order_by("created_at")

        self.assertEqual(pending_requests.count(), 2)
        self.assertTrue(pending_requests[0].is_leader)  # First is leader
        self.assertFalse(pending_requests[1].is_leader)  # Second is not leader
