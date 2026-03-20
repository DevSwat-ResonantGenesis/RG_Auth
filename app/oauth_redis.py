"""
OAuth state storage using Redis for production reliability.
Falls back to in-memory storage if Redis is unavailable.
"""

import json
import os
from typing import Any, Dict, Optional

import redis


# Redis connection
_redis_client = None
_redis_available = None
_memory_store = {}  # Fallback in-memory storage


def get_redis_client():
    """Get or create Redis client."""
    global _redis_client, _redis_available
    
    if _redis_available is False:
        return None
    
    if _redis_client is None:
        try:
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379")
            _redis_client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
            # Test connection
            _redis_client.ping()
            _redis_available = True
        except Exception as e:
            print(f"⚠️ Redis unavailable, using in-memory OAuth state storage: {e}")
            _redis_available = False
            _redis_client = None
    
    return _redis_client


def store_oauth_state(state: str, data: Dict[str, Any]) -> None:
    """Store OAuth state in Redis with expiration."""
    redis_client = get_redis_client()
    if redis_client:
        redis_client.setex(
            f"oauth_state:{state}",
            600,  # 10 minutes expiration
            json.dumps(data)
        )
    else:
        _memory_store[f"oauth_state:{state}"] = json.dumps(data)


def get_oauth_state(state: str) -> Optional[Dict[str, Any]]:
    """Get OAuth state from Redis."""
    redis_client = get_redis_client()
    if redis_client:
        data = redis_client.get(f"oauth_state:{state}")
        if data:
            return json.loads(data)
    else:
        # Fallback to in-memory storage
        data = _memory_store.get(f"oauth_state:{state}")
        if data:
            return json.loads(data)
    return None

def delete_oauth_state(state: str) -> None:
    """Delete OAuth state from Redis."""
    redis_client = get_redis_client()
    if redis_client:
        redis_client.delete(f"oauth_state:{state}")
    else:
        # Fallback to in-memory storage
        _memory_store.pop(f"oauth_state:{state}", None)
