# Rate Limiting and Throttling

Kronic implements comprehensive API rate limiting and throttling to protect against abuse and ensure fair usage.

## Overview

The rate limiting system uses Redis-based storage for distributed rate limiting and supports:
- Per-endpoint rate limits
- User-based rate limiting (authenticated users)
- IP-based rate limiting (fallback)
- Internal service bypass mechanism
- Rate limit headers in responses
- Monitoring and status endpoints

## Configuration

Rate limits are configured through environment variables and the `RATE_LIMITS` dictionary:

```python
RATE_LIMITS = {
    "default": "100/hour",           # Default limit for unspecified endpoints
    "auth/login": "5/15minutes",     # Login attempts
    "auth/register": "3/hour",       # User registration
    "auth/refresh": "10/hour",       # Token refresh
    "auth/change-password": "3/hour", # Password changes
    "api/*": "1000/hour",            # API endpoints (wildcard)
    "password-reset": "3/hour"       # Password reset requests
}
```

### Environment Variables

- `RATE_LIMIT_ENABLED`: Enable/disable rate limiting (default: `true`)
- `REDIS_URL`: Redis connection string for storage (default: `redis://localhost:6379/0`)
- `INTERNAL_SERVICE_IPS`: Comma-separated list of internal service IPs to bypass rate limiting
- `INTERNAL_SERVICE_TOKENS`: Comma-separated list of internal service tokens

## Rate Limiting Strategies

### 1. User-Based Rate Limiting

For authenticated users, rate limits are applied per user ID:
- Key format: `user:{user_id}`
- More generous limits for registered users
- Prevents account sharing abuse

### 2. IP-Based Rate Limiting

For unauthenticated requests, rate limits are applied per IP address:
- Key format: `ip:{ip_address}`
- Stricter limits for anonymous users
- Protects against distributed attacks

### 3. Endpoint-Specific Limits

Different endpoints have different rate limits based on:
- Security sensitivity (login, registration)
- Resource intensity (API operations)
- Expected usage patterns

## Response Headers

Rate-limited responses include standard headers:

```http
X-RateLimit-Limit: 100          # Maximum requests in window
X-RateLimit-Remaining: 75       # Remaining requests in current window
X-RateLimit-Reset: 1640995200   # Unix timestamp when window resets
Retry-After: 60                 # Seconds to wait (on 429 responses)
```

## Error Responses

When rate limits are exceeded, a `429 Too Many Requests` response is returned:

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

## Internal Service Bypass

Internal services can bypass rate limiting using:

### 1. IP Whitelist
Add internal service IPs to `INTERNAL_SERVICE_IPS`:
```bash
INTERNAL_SERVICE_IPS="10.0.0.1,192.168.1.100"
```

### 2. Service Tokens
Use special tokens in the Authorization header:
```bash
INTERNAL_SERVICE_TOKENS="internal-token-1,internal-token-2"
```

### 3. Special Header
Include the internal service header:
```http
X-Internal-Service: true
```

## Monitoring

### Rate Limit Status Endpoint

Check current rate limiting status:
```http
GET /api/auth/rate-limit-status
```

Response:
```json
{
  "enabled": true,
  "endpoint": "auth/login",
  "limit": "5/15minutes",
  "key": "user:12345",
  "is_internal": false,
  "remaining": 3,
  "reset_time": 1640995200
}
```

### Logging

Rate limiting events are logged with appropriate levels:
- INFO: Rate limiter initialization
- DEBUG: Internal service bypass
- WARNING: Rate limit exceeded
- ERROR: Rate limiter failures

## Implementation Details

### Architecture

The rate limiting system consists of:

1. **RateLimitManager**: Core rate limiting logic
2. **@rate_limit decorator**: Easy endpoint decoration
3. **Flask-Limiter integration**: Underlying rate limiting engine
4. **Redis storage**: Distributed rate limit storage

### Usage in Code

Decorate endpoints with rate limits:

```python
from rate_limiting import rate_limit

@rate_limit("auth/login")
@app.route("/api/auth/login", methods=["POST"])
def login():
    # Login logic here
    pass

# Custom limit
@rate_limit(limit="50/hour")
@app.route("/api/custom", methods=["GET"])
def custom_endpoint():
    pass
```

### Error Handling

The system gracefully handles:
- Redis connection failures (falls back to in-memory)
- Invalid rate limit configurations
- Missing request context
- Internal service detection errors

## Best Practices

1. **Set appropriate limits**: Balance security and usability
2. **Monitor usage**: Use the status endpoint to track patterns
3. **Configure Redis**: Use Redis for production deployments
4. **Internal services**: Properly configure bypass mechanisms
5. **Documentation**: Keep rate limit policies documented for API consumers

## Security Considerations

- Rate limits are defense in depth, not primary security
- Monitor for distributed attacks across multiple IPs
- Regularly review and adjust limits based on usage patterns
- Consider geographic rate limiting for highly sensitive endpoints
- Implement additional authentication protections alongside rate limiting

## Performance Impact

Rate limiting has minimal performance impact:
- Redis operations are very fast (sub-millisecond)
- Efficient key generation and lookup
- Graceful degradation when Redis is unavailable
- Minimal memory footprint per request