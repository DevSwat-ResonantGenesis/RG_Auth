#!/usr/bin/env python3
"""
Migration script to handle existing users with role="owner".

This script migrates existing users from the old "owner" role to the new
subscription-based role system (unsubscribed, plus_plan, business_plan, enterprise_plan).

Usage:
    python migrations/migrate_owner_roles.py --dry-run  # Preview changes
    python migrations/migrate_owner_roles.py --execute   # Apply changes
    python migrations/migrate_owner_roles.py --rollback  # Rollback changes
"""

import argparse
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from app.config import settings, get_database_url
from app.models import OrgMembership, User
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def get_billing_tier_for_user(user_id: str, db: AsyncSession) -> str:
    """
    Query billing service to get user's current subscription tier.
    
    Returns:
        - "developer" if user has developer tier subscription
        - "plus" if user has plus tier subscription
        - "enterprise" if user has enterprise tier subscription
        - None if no subscription found
    """
    import httpx
    
    try:
        billing_url = getattr(settings, "BILLING_URL", "http://billing_service:8000").rstrip("/")
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{billing_url}/economic-state/{user_id}/headers")
            
            if response.status_code == 200:
                data = response.json() or {}
                headers = data.get("headers", {}) if isinstance(data, dict) else {}
                tier = (headers.get("X-Subscription-Tier") or "").strip().lower()
                
                if tier in {"developer", "plus", "enterprise"}:
                    return tier
    except Exception as e:
        logger.warning(f"Failed to query billing service for user {user_id}: {e}")
    
    return None


def map_tier_to_role(tier: str) -> str:
    """Map billing tier to new role name."""
    tier_to_role = {
        "developer": "plus_plan",
        "plus": "business_plan",
        "enterprise": "enterprise_plan",
    }
    return tier_to_role.get(tier, "unsubscribed")


async def migrate_owner_roles(dry_run: bool = False, force_unsubscribed: bool = False) -> dict:
    """
    Migrate existing users with role="owner" to new subscription-based roles.
    
    Args:
        dry_run: If True, only preview changes without applying them
        force_unsubscribed: If True, force all owner users to unsubscribed (ignore billing)
    
    Returns:
        Dictionary with migration statistics
    """
    engine = create_async_engine(get_database_url())
    
    async with engine.begin() as conn:
        async with AsyncSession(conn) as db:
            # Find all users with role="owner"
            result = await db.execute(
                select(OrgMembership, User)
                .join(User, OrgMembership.user_id == User.id)
                .where(OrgMembership.role == "owner", OrgMembership.status == "active")
            )
            
            owner_memberships = result.all()
            
            stats = {
                "total_owner_users": len(owner_memberships),
                "migrated_to_plus_plan": 0,
                "migrated_to_business_plan": 0,
                "migrated_to_enterprise_plan": 0,
                "migrated_to_unsubscribed": 0,
                "errors": [],
            }
            
            logger.info(f"Found {len(owner_memberships)} users with role='owner'")
            
            for membership, user in owner_memberships:
                user_id_str = str(user.id)
                user_email = user.email
                
                if force_unsubscribed:
                    new_role = "unsubscribed"
                    reason = "forced_unsubscribed"
                else:
                    # Check billing service for existing subscription
                    billing_tier = await get_billing_tier_for_user(user_id_str, db)
                    
                    if billing_tier:
                        new_role = map_tier_to_role(billing_tier)
                        reason = f"billing_tier_{billing_tier}"
                    else:
                        new_role = "unsubscribed"
                        reason = "no_subscription"
                
                logger.info(f"User {user_email} ({user_id_str}): owner -> {new_role} ({reason})")
                
                if not dry_run:
                    try:
                        # Update role in database
                        await db.execute(
                            update(OrgMembership)
                            .where(OrgMembership.id == membership.id)
                            .values(role=new_role)
                        )
                        
                        # Track statistics
                        if new_role == "plus_plan":
                            stats["migrated_to_plus_plan"] += 1
                        elif new_role == "business_plan":
                            stats["migrated_to_business_plan"] += 1
                        elif new_role == "enterprise_plan":
                            stats["migrated_to_enterprise_plan"] += 1
                        else:
                            stats["migrated_to_unsubscribed"] += 1
                            
                    except Exception as e:
                        error_msg = f"Failed to migrate user {user_email}: {e}"
                        logger.error(error_msg)
                        stats["errors"].append(error_msg)
                else:
                    # Dry run - just track what would happen
                    if new_role == "plus_plan":
                        stats["migrated_to_plus_plan"] += 1
                    elif new_role == "business_plan":
                        stats["migrated_to_business_plan"] += 1
                    elif new_role == "enterprise_plan":
                        stats["migrated_to_enterprise_plan"] += 1
                    else:
                        stats["migrated_to_unsubscribed"] += 1
            
            if not dry_run:
                await db.commit()
                logger.info("Migration committed to database")
            else:
                logger.info("Dry run - no changes committed")
    
    await engine.dispose()
    return stats


async def rollback_migration() -> dict:
    """
    Rollback migration by setting all users with subscription-based roles back to "owner".
    
    WARNING: This should only be used if the migration causes issues.
    """
    engine = create_async_engine(get_database_url())
    
    async with engine.begin() as conn:
        async with AsyncSession(conn) as db:
            # Find all users with new subscription-based roles
            result = await db.execute(
                select(OrgMembership)
                .where(
                    OrgMembership.role.in_(["plus_plan", "business_plan", "enterprise_plan", "unsubscribed"]),
                    OrgMembership.status == "active"
                )
            )
            
            memberships = result.all()
            
            stats = {
                "total_rolled_back": len(memberships),
                "errors": [],
            }
            
            logger.info(f"Rolling back {len(memberships)} users to 'owner' role")
            
            for membership in memberships:
                try:
                    await db.execute(
                        update(OrgMembership)
                        .where(OrgMembership.id == membership.id)
                        .values(role="owner")
                    )
                except Exception as e:
                    error_msg = f"Failed to rollback membership {membership.id}: {e}"
                    logger.error(error_msg)
                    stats["errors"].append(error_msg)
            
            await db.commit()
            logger.info("Rollback committed to database")
    
    await engine.dispose()
    return stats


def main():
    parser = argparse.ArgumentParser(description="Migrate owner roles to subscription-based roles")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--execute", action="store_true", help="Apply migration changes")
    parser.add_argument("--rollback", action="store_true", help="Rollback migration")
    parser.add_argument("--force-unsubscribed", action="store_true", help="Force all to unsubscribed (ignore billing)")
    
    args = parser.parse_args()
    
    if args.rollback:
        print("⚠️  ROLLBACK MODE - This will revert all subscription-based roles back to 'owner'")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != "yes":
            print("Rollback cancelled")
            return
        
        stats = asyncio.run(rollback_migration())
        print(f"\nRollback complete:")
        print(f"  Total rolled back: {stats['total_rolled_back']}")
        if stats['errors']:
            print(f"  Errors: {len(stats['errors'])}")
            for error in stats['errors']:
                print(f"    - {error}")
    elif args.execute or args.dry_run:
        mode = "DRY RUN" if args.dry_run else "EXECUTE"
        print(f"🔄 {mode} MODE - Migrating owner roles to subscription-based roles")
        
        stats = asyncio.run(migrate_owner_roles(dry_run=args.dry_run, force_unsubscribed=args.force_unsubscribed))
        
        print(f"\nMigration statistics:")
        print(f"  Total owner users found: {stats['total_owner_users']}")
        print(f"  Migrated to plus_plan: {stats['migrated_to_plus_plan']}")
        print(f"  Migrated to business_plan: {stats['migrated_to_business_plan']}")
        print(f"  Migrated to enterprise_plan: {stats['migrated_to_enterprise_plan']}")
        print(f"  Migrated to unsubscribed: {stats['migrated_to_unsubscribed']}")
        
        if stats['errors']:
            print(f"  Errors: {len(stats['errors'])}")
            for error in stats['errors']:
                print(f"    - {error}")
        
        if args.dry_run:
            print("\n⚠️  This was a dry run. No changes were applied.")
            print("   Run with --execute to apply these changes.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
