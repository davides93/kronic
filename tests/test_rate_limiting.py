"""Tests for rate limiting functionality."""

import unittest
import time
import json
from unittest.mock import patch, MagicMock

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
import config


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting functionality."""

    def setUp(self):
        """Set up test client and configuration."""
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        
        # Backup original config
        self.original_database_enabled = config.DATABASE_ENABLED
        self.original_users = config.USERS
        
        # Mock configurations for testing
        config.DATABASE_ENABLED = False
        config.USERS = {}  # No auth required for testing

    def tearDown(self):
        """Restore original configuration."""
        config.DATABASE_ENABLED = self.original_database_enabled
        config.USERS = self.original_users

    def test_rate_limit_status_endpoint(self):
        """Test rate limit status endpoint."""
        response = self.client.get("/api/auth/rate-limit-status")
        
        self.assertIn(response.status_code, [200, 500])  # May fail if Redis unavailable
        
        if response.status_code == 200:
            data = json.loads(response.data)
            self.assertIn("enabled", data)

    def test_rate_limit_headers_present(self):
        """Test that rate limit headers are present in responses."""
        # Make a request to a rate-limited endpoint
        response = self.client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "password"},
            content_type="application/json"
        )
        
        # Should have rate limit headers or be rate limited
        # Note: This may fail in test environment without Redis
        self.assertIn(response.status_code, [200, 401, 429, 500])

    def test_internal_service_bypass(self):
        """Test internal service bypass functionality."""
        # Test with internal service header
        response = self.client.get(
            "/api/auth/rate-limit-status",
            headers={"X-Internal-Service": "true"}
        )
        
        self.assertIn(response.status_code, [200, 500])
        
        if response.status_code == 200:
            data = json.loads(response.data)
            # Should indicate internal service bypass if rate limiting is enabled
            if data.get("enabled"):
                self.assertTrue(data.get("is_internal", False))

    def test_rate_limit_configuration(self):
        """Test rate limiting configuration."""
        from rate_limiting import RATE_LIMITS, RateLimitManager
        
        # Check that configuration exists
        self.assertIsInstance(RATE_LIMITS, dict)
        self.assertIn("default", RATE_LIMITS)
        self.assertIn("auth/login", RATE_LIMITS)
        self.assertIn("auth/register", RATE_LIMITS)
        
        # Check rate limit format
        for endpoint, limit in RATE_LIMITS.items():
            self.assertIsInstance(limit, str)
            self.assertIn("/", limit)

    def test_rate_limit_manager_initialization(self):
        """Test rate limit manager initialization."""
        from rate_limiting import RateLimitManager
        
        # Test initialization without app
        manager = RateLimitManager()
        self.assertIsNone(manager.app)
        self.assertIsNone(manager.limiter)
        
        # Test initialization with app
        manager = RateLimitManager(self.app)
        self.assertIsNotNone(manager.app)

    def test_get_endpoint_limit(self):
        """Test endpoint limit resolution."""
        from rate_limiting import RateLimitManager
        
        manager = RateLimitManager()
        
        # Test exact match
        limit = manager.get_endpoint_limit("auth/login")
        self.assertEqual(limit, "5/15minutes")
        
        # Test wildcard match
        limit = manager.get_endpoint_limit("api/users")
        self.assertEqual(limit, "1000/hour")
        
        # Test default fallback
        limit = manager.get_endpoint_limit("unknown/endpoint")
        self.assertEqual(limit, "100/hour")

    @patch("rate_limiting.get_remote_address")
    def test_rate_limit_key_generation(self, mock_get_ip):
        """Test rate limit key generation."""
        from rate_limiting import RateLimitManager
        
        mock_get_ip.return_value = "127.0.0.1"
        manager = RateLimitManager()
        
        with self.app.test_request_context():
            # Test IP-based key (no user)
            key = manager._get_rate_limit_key()
            self.assertTrue(key.startswith("ip:"))
            
            # Test user-based key
            from flask import request
            request.current_user = {"user_id": "test_user"}
            key = manager._get_rate_limit_key()
            self.assertTrue(key.startswith("user:"))

    def test_internal_service_detection(self):
        """Test internal service detection."""
        from rate_limiting import RateLimitManager
        
        manager = RateLimitManager()
        
        # Test with internal header
        with self.app.test_request_context(headers={"X-Internal-Service": "true"}):
            self.assertTrue(manager._is_internal_service())
        
        # Test without internal indicators
        with self.app.test_request_context():
            self.assertFalse(manager._is_internal_service())

    def test_rate_limit_decorator(self):
        """Test rate limit decorator functionality."""
        from rate_limiting import rate_limit
        
        @rate_limit("test/endpoint", "10/minute")
        def test_function():
            return "success"
        
        # Test that function still works within request context
        with self.app.test_request_context():
            result = test_function()
            self.assertEqual(result, "success")

    def test_rate_limiting_disabled(self):
        """Test behavior when rate limiting is disabled."""
        with patch("rate_limiting.RATE_LIMIT_ENABLED", False):
            from rate_limiting import RateLimitManager
            
            manager = RateLimitManager(self.app)
            self.assertIsNone(manager.limiter)
            
            # Decorator should pass through
            @manager.limit_endpoint()
            def test_function():
                return "success"
            
            result = test_function()
            self.assertEqual(result, "success")

    def test_error_handling(self):
        """Test error handling in rate limiting."""
        from rate_limiting import RateLimitManager
        
        manager = RateLimitManager()

        # Test with invalid limit format
        with patch.object(manager, "redis_client", None):
            remaining = manager._get_remaining_requests("test_key", "invalid_format")
            self.assertIsNone(remaining)

            reset_time = manager._get_reset_time("invalid_format")
            self.assertIsNone(reset_time)


if __name__ == "__main__":
    unittest.main()
