"""
GeoIP service module for location lookup from IP addresses.

Supports:
- MaxMind GeoLite2 (primary - requires account)
- ip-api.com (free fallback, rate limited)
- Local/private IP detection

Usage:
    from .geoip import get_location_from_ip
    
    location = await get_location_from_ip("8.8.8.8")
    # Returns: "Mountain View, US" or None
"""
import asyncio
from typing import Optional
from functools import lru_cache

from .config import settings


# Cache for IP lookups (avoid repeated API calls)
_location_cache: dict = {}
CACHE_MAX_SIZE = 10000


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/local."""
    if not ip:
        return True
    
    private_prefixes = (
        "127.",      # Loopback
        "10.",       # Private Class A
        "172.16.", "172.17.", "172.18.", "172.19.",  # Private Class B
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", # Private Class C
        "169.254.", # Link-local
        "::1",      # IPv6 loopback
        "fe80:",    # IPv6 link-local
        "fc00:",    # IPv6 unique local
        "fd00:",    # IPv6 unique local
    )
    
    return ip.startswith(private_prefixes)


async def get_location_from_ip(ip: str) -> Optional[str]:
    """
    Get location string from IP address.
    
    Returns:
        Location string like "City, Country" or None if unknown
    """
    if not ip or _is_private_ip(ip):
        return "Local Network"
    
    # Check cache first
    if ip in _location_cache:
        return _location_cache[ip]
    
    location = None
    
    # Try MaxMind if configured
    if settings.MAXMIND_LICENSE_KEY:
        location = await _lookup_maxmind(ip)
    
    # Fallback to free API
    if not location:
        location = await _lookup_ipapi(ip)
    
    # Cache the result
    if location and len(_location_cache) < CACHE_MAX_SIZE:
        _location_cache[ip] = location
    
    return location


async def _lookup_maxmind(ip: str) -> Optional[str]:
    """
    Lookup IP using MaxMind GeoLite2 web service.
    
    Requires MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY.
    """
    try:
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://geolite.info/geoip/v2.1/city/{ip}",
                auth=(settings.MAXMIND_ACCOUNT_ID, settings.MAXMIND_LICENSE_KEY),
                timeout=5.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                city = data.get("city", {}).get("names", {}).get("en", "")
                country = data.get("country", {}).get("iso_code", "")
                
                if city and country:
                    return f"{city}, {country}"
                elif country:
                    return country
                    
    except Exception as e:
        print(f"[GeoIP] MaxMind lookup failed for {ip}: {e}")
    
    return None


async def _lookup_ipapi(ip: str) -> Optional[str]:
    """
    Lookup IP using ip-api.com (free, rate limited to 45/min).
    
    No API key required but has rate limits.
    """
    try:
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,city,country,countryCode"},
                timeout=5.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    city = data.get("city", "")
                    country_code = data.get("countryCode", "")
                    
                    if city and country_code:
                        return f"{city}, {country_code}"
                    elif country_code:
                        return country_code
                        
    except Exception as e:
        print(f"[GeoIP] ip-api lookup failed for {ip}: {e}")
    
    return None


def clear_cache():
    """Clear the location cache."""
    global _location_cache
    _location_cache = {}
