"""
Rate limiting for auth_service endpoints.

Supports both in-memory storage (development) and Redis-backed storage (production).
Automatically uses Redis if REDIS_URL is configured.
"""

import os
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Optional, Tuple
from functools import wraps

from fastapi import HTTPException, Request, status


class RateLimiterBackend(ABC):
    """Abstract base class for rate limiter backends."""
    
    @abstractmethod
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        """Check if request is allowed."""
        pass
    
    @abstractmethod
    def get_retry_after(self, key: str, window_seconds: int) -> int:
        """Get seconds until rate limit resets."""
        pass


class InMemoryRateLimiter(RateLimiterBackend):
    """
    In-memory rate limiter using sliding window algorithm.
    
    Suitable for single-instance deployments or development.
    """
    
    def __init__(self):
        self._requests: dict = defaultdict(list)
    
    def _clean_old_requests(self, key: str, window_seconds: int):
        """Remove requests outside the current window."""
        now = time.time()
        cutoff = now - window_seconds
        self._requests[key] = [
            (ts, count) for ts, count in self._requests[key]
            if ts > cutoff
        ]
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        self._clean_old_requests(key, window_seconds)
        
        total_requests = sum(count for _, count in self._requests[key])
        
        if total_requests >= limit:
            return False, 0
        
        now = time.time()
        self._requests[key].append((now, 1))
        
        return True, limit - total_requests - 1
    
    def get_retry_after(self, key: str, window_seconds: int) -> int:
        if not self._requests[key]:
            return 0
        
        oldest_ts = min(ts for ts, _ in self._requests[key])
        now = time.time()
        retry_after = int(oldest_ts + window_seconds - now)
        return max(0, retry_after)


class RedisRateLimiter(RateLimiterBackend):
    """
    Redis-backed rate limiter using sliding window algorithm.
    
    Suitable for multi-instance production deployments.
    Uses Redis sorted sets for efficient sliding window implementation.
    """
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis = None
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection."""
        try:
            import redis
            self._redis = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            # Test connection
            self._redis.ping()
        except ImportError:
            raise RuntimeError(
                "Redis rate limiting requires 'redis' package. "
                "Install with: pip install redis"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to connect to Redis: {e}")
    
    def _get_redis_key(self, key: str) -> str:
        """Get Redis key with prefix."""
        return f"ratelimit:{key}"
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if request is allowed using Redis sorted set.
        
        Uses a sliding window implemented with sorted sets:
        - Score = timestamp
        - Member = unique request ID (timestamp + random)
        """
        import uuid
        
        redis_key = self._get_redis_key(key)
        now = time.time()
        window_start = now - window_seconds
        
        # Use pipeline for atomic operations
        pipe = self._redis.pipeline()
        
        # Remove old entries outside the window
        pipe.zremrangebyscore(redis_key, 0, window_start)
        
        # Count current requests in window
        pipe.zcard(redis_key)
        
        results = pipe.execute()
        current_count = results[1]
        
        if current_count >= limit:
            return False, 0
        
        # Add new request
        request_id = f"{now}:{uuid.uuid4().hex[:8]}"
        pipe = self._redis.pipeline()
        pipe.zadd(redis_key, {request_id: now})
        pipe.expire(redis_key, window_seconds + 1)  # TTL slightly longer than window
        pipe.execute()
        
        return True, limit - current_count - 1
    
    def get_retry_after(self, key: str, window_seconds: int) -> int:
        """Get seconds until oldest request expires."""
        redis_key = self._get_redis_key(key)
        
        # Get oldest entry
        oldest = self._redis.zrange(redis_key, 0, 0, withscores=True)
        
        if not oldest:
            return 0
        
        oldest_ts = oldest[0][1]
        now = time.time()
        retry_after = int(oldest_ts + window_seconds - now)
        return max(0, retry_after)
    
    def get_stats(self, key: str, window_seconds: int) -> dict:
        """Get rate limit stats for a key."""
        redis_key = self._get_redis_key(key)
        now = time.time()
        window_start = now - window_seconds
        
        # Clean and count
        self._redis.zremrangebyscore(redis_key, 0, window_start)
        count = self._redis.zcard(redis_key)
        
        return {
            "key": key,
            "current_count": count,
            "window_seconds": window_seconds,
        }


def _create_rate_limiter() -> RateLimiterBackend:
    """
    Create appropriate rate limiter based on configuration.
    
    Uses Redis if REDIS_URL is set, otherwise falls back to in-memory.
    """
    redis_url = os.getenv("REDIS_URL")
    
    if redis_url:
        try:
            limiter = RedisRateLimiter(redis_url)
            print(f"[RateLimit] Using Redis backend: {redis_url.split('@')[-1] if '@' in redis_url else redis_url}")
            return limiter
        except Exception as e:
            print(f"[RateLimit] Redis init failed ({e}), falling back to in-memory")
    
    print("[RateLimit] Using in-memory backend (single instance only)")
    return InMemoryRateLimiter()


# Global rate limiter instance - auto-selects backend
_limiter: RateLimiterBackend = None


def get_limiter() -> RateLimiterBackend:
    """Get or create the global rate limiter."""
    global _limiter
    if _limiter is None:
        _limiter = _create_rate_limiter()
    return _limiter


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check for forwarded headers (behind proxy/load balancer)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Take the first IP in the chain (original client)
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    
    # Fall back to direct connection IP
    if request.client:
        return request.client.host
    
    return "unknown"


def rate_limit(
    limit: int,
    window_seconds: int,
    key_func: Optional[Callable[[Request], str]] = None,
):
    """
    Rate limiting decorator for FastAPI endpoints.
    
    Args:
        limit: Maximum requests allowed in window
        window_seconds: Time window in seconds
        key_func: Optional function to extract rate limit key from request.
                  Defaults to client IP address.
    
    Usage:
        @router.post("/auth/login")
        @rate_limit(limit=5, window_seconds=60)  # 5 requests per minute
        async def login(...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Request object in args or kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")
            
            if request is None:
                # Can't rate limit without request, proceed anyway
                return await func(*args, **kwargs)
            
            # Get rate limit key
            if key_func:
                key = key_func(request)
            else:
                key = get_client_ip(request)
            
            # Add endpoint to key to have per-endpoint limits
            endpoint_key = f"{func.__name__}:{key}"
            
            # Check rate limit
            limiter = get_limiter()
            allowed, remaining = limiter.is_allowed(endpoint_key, limit, window_seconds)
            
            if not allowed:
                retry_after = limiter.get_retry_after(endpoint_key, window_seconds)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Pre-configured rate limiters for common auth operations
def login_rate_limit():
    """Rate limit for login: 5 attempts per minute per IP."""
    return rate_limit(limit=5, window_seconds=60)


def register_rate_limit():
    """Rate limit for registration: 3 attempts per minute per IP."""
    return rate_limit(limit=3, window_seconds=60)


def password_reset_rate_limit():
    """Rate limit for password reset: 3 attempts per hour per IP."""
    return rate_limit(limit=3, window_seconds=3600)


def api_key_rate_limit():
    """Rate limit for API key operations: 10 per minute per IP."""
    return rate_limit(limit=10, window_seconds=60)


def refresh_token_rate_limit():
    """Rate limit for token refresh: 30 per minute per IP."""
    return rate_limit(limit=30, window_seconds=60)
