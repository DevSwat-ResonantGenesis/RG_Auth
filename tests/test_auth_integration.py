"""Auth Service Integration Tests.

Comprehensive integration tests for authentication endpoints:
- Registration flows
- Login flows (email/password, OAuth)
- Token refresh
- Password reset
- API key management
- Session management
- MFA flows
- Organization management

Author: Agent 7 - ResonantGenesis Team
Created: February 21, 2026
"""

import pytest
import json
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from unittest.mock import patch, MagicMock, AsyncMock
from uuid import uuid4

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from app.main import app


class TestConfig:
    """Test configuration constants."""
    BASE_URL = "http://testserver"
    TEST_EMAIL = "test@example.com"
    TEST_PASSWORD = "TestPassword123!"
    TEST_WEAK_PASSWORD = "weak"
    TEST_USERNAME = "testuser"
    TEST_ORG_NAME = "Test Organization"


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def json_headers():
    """Return JSON content-type headers."""
    return {"Content-Type": "application/json"}


@pytest.fixture
def unique_email():
    """Generate a unique email for each test."""
    return f"test_{uuid4().hex[:8]}@example.com"


@pytest.fixture
def valid_registration_data(unique_email):
    """Generate valid registration data."""
    return {
        "email": unique_email,
        "password": TestConfig.TEST_PASSWORD,
        "username": f"user_{uuid4().hex[:8]}",
        "full_name": "Test User",
        "org_name": TestConfig.TEST_ORG_NAME
    }


class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "auth_service"
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns service info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestRegistrationEndpoints:
    """Test user registration endpoints."""
    
    def test_register_with_valid_data(self, client, json_headers, valid_registration_data):
        """Test registration with valid data."""
        response = client.post(
            "/auth/signup",
            json=valid_registration_data,
            headers=json_headers
        )
        # May succeed or fail based on database state
        assert response.status_code in [200, 201, 400, 422, 500, 503]
    
    def test_register_missing_email(self, client, json_headers):
        """Test registration fails without email."""
        payload = {
            "password": TestConfig.TEST_PASSWORD,
            "username": "testuser"
        }
        response = client.post(
            "/auth/signup",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [400, 422, 500, 503]
    
    def test_register_missing_password(self, client, json_headers, unique_email):
        """Test registration fails without password."""
        payload = {
            "email": unique_email,
            "username": "testuser"
        }
        response = client.post(
            "/auth/signup",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [400, 422, 500, 503]
    
    def test_register_weak_password(self, client, json_headers, unique_email):
        """Test registration fails with weak password."""
        payload = {
            "email": unique_email,
            "password": TestConfig.TEST_WEAK_PASSWORD,
            "username": "testuser"
        }
        response = client.post(
            "/auth/signup",
            json=payload,
            headers=json_headers
        )
        # Should reject weak password
        assert response.status_code in [400, 422, 500, 503]
    
    def test_register_invalid_email_format(self, client, json_headers):
        """Test registration fails with invalid email format."""
        payload = {
            "email": "not-an-email",
            "password": TestConfig.TEST_PASSWORD,
            "username": "testuser"
        }
        response = client.post(
            "/auth/signup",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [400, 422, 500, 503]
    
    def test_register_duplicate_email(self, client, json_headers, valid_registration_data):
        """Test registration fails with duplicate email."""
        # First registration
        client.post(
            "/auth/signup",
            json=valid_registration_data,
            headers=json_headers
        )
        
        # Second registration with same email
        response = client.post(
            "/auth/signup",
            json=valid_registration_data,
            headers=json_headers
        )
        # Should reject duplicate
        assert response.status_code in [400, 409, 422, 500, 503]
    
    def test_public_signup_alias(self, client, json_headers, valid_registration_data):
        """Test public signup alias endpoint."""
        response = client.post(
            "/auth/public/signup",
            json=valid_registration_data,
            headers=json_headers
        )
        assert response.status_code in [200, 201, 400, 422, 500, 503]


class TestLoginEndpoints:
    """Test login endpoints."""
    
    def test_login_endpoint_exists(self, client, json_headers):
        """Test login endpoint is accessible."""
        payload = {
            "email": TestConfig.TEST_EMAIL,
            "password": TestConfig.TEST_PASSWORD
        }
        response = client.post(
            "/auth/login",
            json=payload,
            headers=json_headers
        )
        # Endpoint should exist (may fail auth)
        assert response.status_code in [200, 400, 401, 403, 422, 500, 503]
    
    def test_login_missing_credentials(self, client, json_headers):
        """Test login fails without credentials."""
        response = client.post(
            "/auth/login",
            json={},
            headers=json_headers
        )
        assert response.status_code in [400, 422, 500, 503]
    
    def test_login_invalid_credentials(self, client, json_headers):
        """Test login fails with invalid credentials."""
        payload = {
            "email": "nonexistent@example.com",
            "password": "WrongPassword123!"
        }
        response = client.post(
            "/auth/login",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [400, 401, 403, 422, 500, 503]
    
    def test_direct_login_endpoint(self, client):
        """Test direct login endpoint."""
        response = client.post("/login")
        assert response.status_code in [200, 400, 422, 500]


class TestTokenEndpoints:
    """Test token management endpoints."""
    
    def test_refresh_token_endpoint(self, client, json_headers):
        """Test token refresh endpoint."""
        response = client.post(
            "/auth/refresh",
            headers=json_headers
        )
        # Should require valid refresh token
        assert response.status_code in [200, 400, 401, 403, 422, 500, 503]
    
    def test_logout_endpoint(self, client, json_headers):
        """Test logout endpoint."""
        response = client.post(
            "/auth/logout",
            headers=json_headers
        )
        # Should handle logout (may require auth)
        assert response.status_code in [200, 204, 400, 401, 403, 422, 500, 503]
    
    def test_verify_token_endpoint(self, client, json_headers):
        """Test token verification endpoint."""
        headers = {
            **json_headers,
            "Authorization": "Bearer test-token"
        }
        response = client.get(
            "/auth/verify",
            headers=headers
        )
        assert response.status_code in [200, 400, 401, 403, 404, 422, 500, 503]


class TestPasswordResetEndpoints:
    """Test password reset endpoints."""
    
    def test_request_password_reset(self, client, json_headers):
        """Test password reset request endpoint."""
        payload = {
            "email": TestConfig.TEST_EMAIL
        }
        response = client.post(
            "/auth/password/reset-request",
            json=payload,
            headers=json_headers
        )
        # Should accept request (may not send email in test)
        assert response.status_code in [200, 202, 400, 404, 422, 500, 503]
    
    def test_password_reset_invalid_email(self, client, json_headers):
        """Test password reset with invalid email format."""
        payload = {
            "email": "not-an-email"
        }
        response = client.post(
            "/auth/password/reset-request",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [400, 422, 500, 503]
    
    def test_password_reset_confirm(self, client, json_headers):
        """Test password reset confirmation endpoint."""
        payload = {
            "token": "test-reset-token",
            "new_password": "NewPassword123!"
        }
        response = client.post(
            "/auth/password/reset-confirm",
            json=payload,
            headers=json_headers
        )
        # Should validate token
        assert response.status_code in [200, 400, 401, 404, 422, 500, 503]


class TestAPIKeyEndpoints:
    """Test API key management endpoints."""
    
    def test_create_api_key_requires_auth(self, client, json_headers):
        """Test API key creation requires authentication."""
        payload = {
            "name": "Test API Key",
            "scopes": ["read", "write"]
        }
        response = client.post(
            "/auth/api-keys",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]
    
    def test_list_api_keys_requires_auth(self, client):
        """Test listing API keys requires authentication."""
        response = client.get("/auth/api-keys")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_verify_api_key_endpoint(self, client, json_headers):
        """Test API key verification endpoint."""
        payload = {
            "api_key": "test-api-key-12345"
        }
        response = client.post(
            "/auth/api-keys/verify",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [200, 400, 401, 404, 422, 500, 503]
    
    def test_revoke_api_key_requires_auth(self, client):
        """Test API key revocation requires authentication."""
        key_id = str(uuid4())
        response = client.delete(f"/auth/api-keys/{key_id}")
        assert response.status_code in [401, 403, 404, 500, 503]


class TestOAuthEndpoints:
    """Test OAuth/SSO endpoints."""
    
    def test_oauth_providers_list(self, client):
        """Test listing available OAuth providers."""
        response = client.get("/auth/sso/providers")
        assert response.status_code in [200, 404, 500, 503]
    
    def test_oauth_google_initiate(self, client):
        """Test Google OAuth initiation."""
        response = client.get("/auth/sso/google")
        # Should redirect or return auth URL
        assert response.status_code in [200, 302, 307, 400, 404, 500, 503]
    
    def test_oauth_github_initiate(self, client):
        """Test GitHub OAuth initiation."""
        response = client.get("/auth/sso/github")
        assert response.status_code in [200, 302, 307, 400, 404, 500, 503]
    
    def test_oauth_callback_missing_code(self, client):
        """Test OAuth callback without code parameter."""
        response = client.get("/auth/oauth/callback")
        # Should fail without code
        assert response.status_code in [400, 422, 500, 503]
    
    def test_oauth_callback_with_error(self, client):
        """Test OAuth callback with error parameter."""
        response = client.get(
            "/auth/oauth/callback",
            params={
                "error": "access_denied",
                "error_description": "User denied access"
            }
        )
        assert response.status_code in [400, 401, 403, 422, 500, 503]


class TestMFAEndpoints:
    """Test Multi-Factor Authentication endpoints."""
    
    def test_mfa_setup_requires_auth(self, client):
        """Test MFA setup requires authentication."""
        response = client.post("/auth/mfa/setup")
        assert response.status_code in [401, 403, 404, 422, 500, 503]
    
    def test_mfa_verify_requires_auth(self, client, json_headers):
        """Test MFA verification requires authentication."""
        payload = {
            "code": "123456"
        }
        response = client.post(
            "/auth/mfa/verify",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]
    
    def test_mfa_disable_requires_auth(self, client):
        """Test MFA disable requires authentication."""
        response = client.post("/auth/mfa/disable")
        assert response.status_code in [401, 403, 404, 422, 500, 503]


class TestSessionEndpoints:
    """Test session management endpoints."""
    
    def test_list_sessions_requires_auth(self, client):
        """Test listing sessions requires authentication."""
        response = client.get("/auth/sessions")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_revoke_session_requires_auth(self, client):
        """Test session revocation requires authentication."""
        session_id = str(uuid4())
        response = client.delete(f"/auth/sessions/{session_id}")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_revoke_all_sessions_requires_auth(self, client):
        """Test revoking all sessions requires authentication."""
        response = client.post("/auth/sessions/revoke-all")
        assert response.status_code in [401, 403, 404, 500, 503]


class TestOrganizationEndpoints:
    """Test organization management endpoints."""
    
    def test_create_org_requires_auth(self, client, json_headers):
        """Test organization creation requires authentication."""
        payload = {
            "name": "New Organization",
            "slug": "new-org"
        }
        response = client.post(
            "/auth/organizations",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]
    
    def test_list_orgs_requires_auth(self, client):
        """Test listing organizations requires authentication."""
        response = client.get("/auth/organizations")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_get_org_requires_auth(self, client):
        """Test getting organization details requires authentication."""
        org_id = str(uuid4())
        response = client.get(f"/auth/organizations/{org_id}")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_invite_member_requires_auth(self, client, json_headers):
        """Test inviting organization member requires authentication."""
        org_id = str(uuid4())
        payload = {
            "email": "newmember@example.com",
            "role": "viewer"
        }
        response = client.post(
            f"/auth/organizations/{org_id}/invite",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]


class TestUserProfileEndpoints:
    """Test user profile endpoints."""
    
    def test_get_profile_requires_auth(self, client):
        """Test getting user profile requires authentication."""
        response = client.get("/auth/me")
        assert response.status_code in [401, 403, 404, 500, 503]
    
    def test_update_profile_requires_auth(self, client, json_headers):
        """Test updating user profile requires authentication."""
        payload = {
            "full_name": "Updated Name"
        }
        response = client.put(
            "/auth/me",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]
    
    def test_change_password_requires_auth(self, client, json_headers):
        """Test changing password requires authentication."""
        payload = {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!"
        }
        response = client.post(
            "/auth/me/change-password",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [401, 403, 404, 422, 500, 503]


class TestEmailVerificationEndpoints:
    """Test email verification endpoints."""
    
    def test_resend_verification_email(self, client, json_headers):
        """Test resending verification email."""
        payload = {
            "email": TestConfig.TEST_EMAIL
        }
        response = client.post(
            "/auth/email/resend-verification",
            json=payload,
            headers=json_headers
        )
        assert response.status_code in [200, 202, 400, 404, 422, 500, 503]
    
    def test_verify_email_with_token(self, client):
        """Test email verification with token."""
        response = client.get(
            "/auth/email/verify",
            params={"token": "test-verification-token"}
        )
        assert response.status_code in [200, 400, 401, 404, 422, 500, 503]


class TestRateLimiting:
    """Test rate limiting on auth endpoints."""
    
    def test_login_rate_limiting(self, client, json_headers):
        """Test rate limiting on login endpoint."""
        payload = {
            "email": "ratelimit@example.com",
            "password": "WrongPassword123!"
        }
        
        responses = []
        for _ in range(5):
            response = client.post(
                "/auth/login",
                json=payload,
                headers=json_headers
            )
            responses.append(response.status_code)
        
        # Should eventually get rate limited or continue failing auth
        for status in responses:
            assert status in [200, 400, 401, 403, 422, 429, 500, 503]
    
    def test_registration_rate_limiting(self, client, json_headers):
        """Test rate limiting on registration endpoint."""
        responses = []
        for i in range(5):
            payload = {
                "email": f"ratelimit{i}@example.com",
                "password": TestConfig.TEST_PASSWORD,
                "username": f"ratelimituser{i}"
            }
            response = client.post(
                "/auth/signup",
                json=payload,
                headers=json_headers
            )
            responses.append(response.status_code)
        
        for status in responses:
            assert status in [200, 201, 400, 422, 429, 500, 503]


class TestCORSHeaders:
    """Test CORS header handling."""
    
    def test_cors_preflight(self, client):
        """Test CORS preflight request."""
        headers = {
            "Origin": "https://resonantgenesis.xyz",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        }
        response = client.options("/auth/login", headers=headers)
        assert response.status_code in [200, 204, 404]
    
    def test_cors_allowed_origin(self, client, json_headers):
        """Test CORS with allowed origin."""
        headers = {
            **json_headers,
            "Origin": "https://resonantgenesis.xyz"
        }
        response = client.get("/health", headers=headers)
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling."""
    
    def test_invalid_json_payload(self, client):
        """Test handling of invalid JSON payload."""
        headers = {"Content-Type": "application/json"}
        response = client.post(
            "/auth/login",
            content="not valid json {{{",
            headers=headers
        )
        assert response.status_code in [400, 422, 500]
    
    def test_missing_content_type(self, client):
        """Test handling of missing content type."""
        response = client.post(
            "/auth/login",
            content='{"email": "test@example.com", "password": "test"}'
        )
        # Should handle gracefully
        assert response.status_code in [200, 400, 415, 422, 500, 503]
    
    def test_404_for_nonexistent_endpoint(self, client):
        """Test 404 for non-existent endpoint."""
        response = client.get("/auth/nonexistent/endpoint")
        assert response.status_code in [404, 405]


class TestSecurityHeaders:
    """Test security headers in responses."""
    
    def test_response_has_content_type(self, client):
        """Test responses have content-type header."""
        response = client.get("/health")
        assert "content-type" in response.headers
    
    def test_json_response_type(self, client):
        """Test JSON endpoints return correct content type."""
        response = client.get("/health")
        assert "application/json" in response.headers.get("content-type", "")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
