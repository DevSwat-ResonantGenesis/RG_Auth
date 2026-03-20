"""
Identity module - Canonical identity payload for auth layers.
Ported from old backend for full compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from uuid import UUID

from .roles import has_permission, is_role_higher_or_equal


@dataclass(frozen=True, slots=True)
class Identity:
    """
    Canonical identity payload propagated through auth layers.

    Every request — whether authenticated via JWT or API key — is represented by
    this tuple to keep RBAC decisions consistent across the platform.
    """

    user_id: Optional[UUID]
    org_id: UUID
    role: str  # user | org_admin | platform_dev | finance | compliance | ml_engineer | viewer | service
    scopes: List[str] = field(default_factory=list)
    api_key_id: Optional[UUID] = None
    auth_method: str = "jwt"  # jwt | api_key | internal

    def has_scope(self, scope: str) -> bool:
        if "*" in self.scopes:
            return True
        return scope in self.scopes

    def is_admin(self) -> bool:
        """Check if user is org admin."""
        return self.role == "org_admin" or self.role == "admin"

    def is_platform_dev(self) -> bool:
        """Check if user is platform developer."""
        return self.role == "platform_dev" or self.role == "system"

    def allows_cross_org(self) -> bool:
        """Check if identity can access cross-org resources."""
        return self.is_platform_dev() or self.auth_method == "internal"

    def has_permission(self, permission: str) -> bool:
        """Check if identity has a specific permission."""
        if self.allows_cross_org():
            return True
        return has_permission(self.role, permission)

    def can_access(self, resource_type: str, action: str) -> bool:
        """Check if identity can perform action on resource."""
        if self.allows_cross_org():
            return True
        return has_permission(self.role, f"{resource_type}:{action}")

    def can_manage_org(self) -> bool:
        """Check if user can manage their organization."""
        return self.is_admin() or self.role == "org_admin"

    def to_claims(self) -> dict:
        return {
            "user_id": str(self.user_id) if self.user_id else None,
            "org_id": str(self.org_id),
            "role": self.role,
            "scopes": self.scopes,
            "api_key_id": str(self.api_key_id) if self.api_key_id else None,
            "auth_method": self.auth_method,
        }

    @staticmethod
    def from_claims(claims: dict) -> "Identity":
        def _parse(value):
            if value is None:
                return None
            return UUID(str(value))

        return Identity(
            user_id=_parse(claims.get("user_id")),
            org_id=UUID(str(claims["org_id"])),
            role=claims["role"],
            scopes=list(claims.get("scopes", [])),
            api_key_id=_parse(claims.get("api_key_id")),
            auth_method=claims.get("auth_method", "jwt"),
        )
