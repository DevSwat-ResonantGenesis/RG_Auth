"""
Economic Integration for Auth Service.

This module provides the integration between auth_service and billing_service
for creating UserEconomicState during registration.

Contract:
- Registration MUST call billing_service to create UserEconomicState
- Registration MUST fail if billing_service fails
- No user enters the system without an economic state
"""

import httpx
from typing import Optional
from uuid import UUID

from .config import settings


# Billing service URL
BILLING_SERVICE_URL = getattr(settings, 'BILLING_URL', 'http://billing_service:8000')


class EconomicIntegrationError(Exception):
    """Raised when economic state creation fails."""
    pass


async def create_user_economic_state(
    user_id: UUID,
    org_id: UUID,
    tier: str = "developer",
    subscription_source: str = "internal",
    subscription_id: Optional[str] = None,
    is_dev_override: bool = False,
) -> dict:
    """
    Create UserEconomicState in billing_service.
    
    This MUST be called during registration.
    Registration MUST fail if this fails.
    
    Args:
        user_id: The user's UUID (from auth_service)
        org_id: The organization's UUID (from auth_service)
        tier: Subscription tier (free, plus, pro, enterprise)
        subscription_source: Where subscription originated (internal, stripe)
        subscription_id: Optional Stripe subscription ID
        is_dev_override: If True, user gets unlimited access (dev mode only)
    
    Returns:
        The created UserEconomicState as a dict
    
    Raises:
        EconomicIntegrationError: If creation fails
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{BILLING_SERVICE_URL}/economic-state/",
                json={
                    "user_id": str(user_id),
                    "org_id": str(org_id),
                    "tier": tier,
                    "subscription_source": subscription_source,
                    "subscription_id": subscription_id,
                    "is_dev_override": is_dev_override,
                }
            )
    except httpx.RequestError as e:
        raise EconomicIntegrationError(f"Billing service unavailable: {e}")

    if resp.status_code == 409:
        # Already exists - this is OK for idempotency
        return resp.json()

    if resp.status_code != 200:
        raise EconomicIntegrationError(
            f"Failed to create economic state: {resp.status_code} - {resp.text}"
        )

    return resp.json()


async def get_user_economic_state(user_id: UUID) -> Optional[dict]:
    """
    Get UserEconomicState from billing_service.
    
    Args:
        user_id: The user's UUID
    
    Returns:
        The UserEconomicState as a dict, or None if not found
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{BILLING_SERVICE_URL}/economic-state/{user_id}"
            )
    except httpx.RequestError:
        return None

    if resp.status_code != 200:
        return None

    return resp.json()


async def upgrade_user_subscription(
    user_id: UUID,
    new_tier: str,
    subscription_id: Optional[str] = None,
) -> dict:
    """
    Upgrade user's subscription tier.
    
    Args:
        user_id: The user's UUID
        new_tier: New subscription tier (plus, pro, enterprise)
        subscription_id: Optional Stripe subscription ID
    
    Returns:
        The updated UserEconomicState as a dict
    
    Raises:
        EconomicIntegrationError: If upgrade fails
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{BILLING_SERVICE_URL}/economic-state/{user_id}/upgrade",
                params={
                    "new_tier": new_tier,
                    "subscription_id": subscription_id,
                }
            )
    except httpx.RequestError as e:
        raise EconomicIntegrationError(f"Billing service unavailable: {e}")

    if resp.status_code != 200:
        raise EconomicIntegrationError(
            f"Failed to upgrade subscription: {resp.status_code} - {resp.text}"
        )

    return resp.json()
