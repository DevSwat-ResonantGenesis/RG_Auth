"""
Role-based access control definitions.
Ported from old backend for full compatibility.

Roles:
- viewer: Public viewer (unauthenticated) - no access
- user: Authenticated org member (non-admin)
- org_admin: Organization admin (tenant admin)
- platform_dev: Platform developer (system level, global)
- finance: Accounting/billing operations
- compliance: Compliance/security officer
- ml_engineer: ML Engineer (ML subsystem only)
- platform_owner: Platform owner (superuser)
"""

# Role hierarchy (higher = more permissions)
ROLE_HIERARCHY = {
    "viewer": 0,
    "user": 1,
    "compliance": 2,
    "finance": 2,
    "ml_engineer": 3,
    "org_admin": 4,
    "platform_dev": 5,
    "owner": 5,  # Owner has same level as platform_dev
    "platform_owner": 6,
}

# Role definitions
ROLES = {
    "viewer": {
        "level": 0,
        "description": "Public viewer (unauthenticated)",
        "can_access": [],
    },
    "platform_owner": {
        "level": 6,
        "description": "Platform owner (superuser)",
        "can_access": [
            "*",  # All permissions
        ],
    },
    "user": {
        "level": 1,
        "description": "Authenticated org member",
        "can_access": [
            "dashboard:view",
            "predictions:create",
            "predictions:view_own",
            "evidence:view",
            "embeddings:create",
            "audit:view_own",
            "settings:view_profile",
            "api_keys:manage_personal",
            "billing:view_usage",
        ],
    },
    "owner": {
        "level": 5,
        "description": "Organization owner",
        "can_access": [
            "*",  # All permissions
        ],
    },
    "org_admin": {
        "level": 4,
        "description": "Organization admin",
        "can_access": [
            "dashboard:view",
            "dashboard:manage",
            "predictions:create",
            "predictions:view_all",
            "predictions:delete",
            "predictions:bulk_upload",
            "predictions:export",
            "evidence:view",
            "evidence:manage",
            "embeddings:create",
            "embeddings:manage",
            "policies:crud",
            "compliance:manage",
            "audit:view_org",
            "audit:export",
            "users:create",
            "users:invite",
            "users:remove",
            "users:assign_roles",
            "api_keys:manage_org",
            "billing:full",
            "model:view_versions",
            "model:trigger_retrain",
            "model:rollback",
            "settings:org_config",
        ],
    },
    "platform_dev": {
        "level": 5,
        "description": "Platform developer (system level)",
        "can_access": [
            "*",  # All permissions
        ],
    },
    "finance": {
        "level": 2,
        "description": "Accounting/billing operations",
        "can_access": [
            "billing:view_all",
            "billing:apply_credits",
            "billing:adjust_invoices",
            "billing:refund",
            "billing:update_plans",
            "billing:reports",
            "billing:export",
            "usage:monitor",
            "audit:view_billing",
        ],
    },
    "compliance": {
        "level": 2,
        "description": "Compliance/security officer",
        "can_access": [
            "compliance:dashboard",
            "compliance:view_policies",
            "compliance:violations",
            "compliance:reports",
            "compliance:export",
            "audit:view_all",
            "security:view_api_keys",
            "security:audit_sessions",
            "security:view_risky",
            "model:view_drift",
        ],
    },
    "ml_engineer": {
        "level": 3,
        "description": "ML Engineer",
        "can_access": [
            "ml:view_training_jobs",
            "ml:view_versions",
            "ml:push_versions",
            "ml:rollback",
            "ml:offline_eval",
            "ml:import_dataset",
            "ml:drift_detection",
            "ml:embedding_diagnostics",
            "ml:worker_logs",
            "ml:latency_metrics",
            "ml:resource_usage",
        ],
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    if role not in ROLES:
        return False
    
    role_perms = ROLES[role]["can_access"]
    
    # Platform dev has all permissions
    if "*" in role_perms:
        return True
    
    # Check exact permission
    if permission in role_perms:
        return True
    
    # Check wildcard permissions (e.g., "predictions:*" matches "predictions:create")
    permission_parts = permission.split(":")
    if len(permission_parts) == 2:
        category, action = permission_parts
        wildcard = f"{category}:*"
        if wildcard in role_perms:
            return True
    
    return False


def can_access_resource(role: str, resource_type: str, action: str) -> bool:
    """Check if role can perform action on resource."""
    permission = f"{resource_type}:{action}"
    return has_permission(role, permission)


def is_role_higher_or_equal(role1: str, role2: str) -> bool:
    """Check if role1 has equal or higher level than role2."""
    level1 = ROLE_HIERARCHY.get(role1, 0)
    level2 = ROLE_HIERARCHY.get(role2, 0)
    return level1 >= level2


def get_allowed_roles_for_action(resource_type: str, action: str) -> list:
    """Get all roles that can perform an action."""
    permission = f"{resource_type}:{action}"
    allowed = []
    for role, config in ROLES.items():
        if has_permission(role, permission):
            allowed.append(role)
    return allowed
