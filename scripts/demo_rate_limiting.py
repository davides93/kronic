#!/usr/bin/env python3
"""
Demonstration script for Kronic rate limiting functionality.

This script shows how rate limiting works by making multiple requests
to the authentication endpoints and observing the rate limit behavior.
"""

import requests
import time
import json
import sys


def test_rate_limiting(base_url="http://localhost:8000"):
    """Test rate limiting on authentication endpoints."""
    print("🚀 Testing Kronic Rate Limiting")
    print("=" * 50)

    # Test rate limit status endpoint
    print("\n1. Checking rate limit status...")
    try:
        response = requests.get(f"{base_url}/api/auth/rate-limit-status")
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Rate limiting enabled: {data.get('enabled', False)}")
            print(f"Current endpoint: {data.get('endpoint', 'unknown')}")
            print(f"Rate limit key: {data.get('key', 'unknown')}")
        else:
            print(f"Response: {response.text}")
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to Kronic server.")
        print("Please ensure Kronic is running at", base_url)
        return False

    # Test login rate limiting
    print("\n2. Testing login rate limiting (5 requests per 15 minutes)...")
    login_data = {"email": "test@example.com", "password": "wrongpassword"}

    for i in range(7):  # Try 7 times to exceed the limit of 5
        print(f"   Request {i + 1}:", end=" ")
        response = requests.post(
            f"{base_url}/api/auth/login",
            json=login_data,
            headers={"Content-Type": "application/json"},
        )

        print(f"Status: {response.status_code}", end="")

        # Check for rate limit headers
        if "X-RateLimit-Limit" in response.headers:
            print(f" | Limit: {response.headers['X-RateLimit-Limit']}", end="")
        if "X-RateLimit-Remaining" in response.headers:
            print(f" | Remaining: {response.headers['X-RateLimit-Remaining']}", end="")
        if "Retry-After" in response.headers:
            print(f" | Retry-After: {response.headers['Retry-After']}s", end="")

        print()

        if response.status_code == 429:
            print("   ⚠️  Rate limit exceeded!")
            try:
                error_data = response.json()
                print(f"   Message: {error_data.get('message', 'Unknown error')}")
            except:
                pass
            break
        elif response.status_code == 401:
            print("   ✓ Authentication failed (expected)")
        else:
            print(f"   Unexpected response: {response.text[:100]}")

        # Small delay between requests
        time.sleep(0.5)

    # Test registration rate limiting
    print("\n3. Testing registration rate limiting (3 requests per hour)...")

    for i in range(4):  # Try 4 times to exceed the limit of 3
        print(f"   Request {i + 1}:", end=" ")

        reg_data = {
            "email": f"test{i}@example.com",
            "password": "WeakPassword123",  # Intentionally weak to trigger validation
        }

        response = requests.post(
            f"{base_url}/api/auth/register",
            json=reg_data,
            headers={"Content-Type": "application/json"},
        )

        print(f"Status: {response.status_code}", end="")

        # Check for rate limit headers
        if "X-RateLimit-Limit" in response.headers:
            print(f" | Limit: {response.headers['X-RateLimit-Limit']}", end="")
        if "X-RateLimit-Remaining" in response.headers:
            print(f" | Remaining: {response.headers['X-RateLimit-Remaining']}", end="")

        print()

        if response.status_code == 429:
            print("   ⚠️  Rate limit exceeded!")
            try:
                error_data = response.json()
                print(f"   Message: {error_data.get('message', 'Unknown error')}")
            except:
                pass
            break
        elif response.status_code == 400:
            print("   ✓ Validation failed (expected)")
        else:
            print(f"   Response: {response.text[:100]}")

        # Small delay between requests
        time.sleep(0.5)

    # Test internal service bypass
    print("\n4. Testing internal service bypass...")
    response = requests.get(
        f"{base_url}/api/auth/rate-limit-status", headers={"X-Internal-Service": "true"}
    )

    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        is_internal = data.get("is_internal", False)
        print(f"Internal service detected: {is_internal}")
        if is_internal:
            print("   ✓ Internal service bypass working")
        else:
            print("   ⚠️  Internal service bypass not detected")

    print("\n" + "=" * 50)
    print("✨ Rate limiting demonstration complete!")
    print("\nKey observations:")
    print("- Rate limits are enforced per endpoint")
    print("- Different endpoints have different limits")
    print("- Rate limit headers provide client feedback")
    print("- Internal services can bypass rate limiting")
    print("- Rate limits help prevent abuse and ensure fair usage")

    return True


if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    test_rate_limiting(base_url)
