#!/usr/bin/env python3
"""
Emergency rollback script - Reverts all subscription-based roles back to 'owner'.

BREAK GLASS ONLY - Use this if the subscription-first registration flow
causes critical issues and you need to restore access immediately.

This script does NOT require a new deploy - it directly modifies the database.

Usage:
    python migrations/emergency_rollback.py --dry-run  # Preview changes
    python migrations/emergency_rollback.py --execute   # Apply changes
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
from app.models import OrgMembership
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def emergency_rollback(dry_run: bool = False) -> dict:
    """
    Emergency rollback: Revert all subscription-based roles to 'owner'.
    
    This affects users with roles: plus_plan, business_plan, enterprise_plan, unsubscribed
    """
    engine = create_async_engine(get_database_url())
    
    async with engine.begin() as conn:
        async with AsyncSession(conn) as db:
            # Find all users with subscription-based roles
            result = await db.execute(
                select(OrgMembership)
                .where(
                    OrgMembership.role.in_(["plus_plan", "business_plan", "enterprise_plan", "unsubscribed"]),
                    OrgMembership.status == "active"
                )
            )
            
            memberships = result.all()
            
            stats = {
                "total_reverted": len(memberships),
                "from_plus_plan": 0,
                "from_business_plan": 0,
                "from_enterprise_plan": 0,
                "from_unsubscribed": 0,
                "errors": [],
            }
            
            logger.warning(f"⚠️  EMERGENCY ROLLBACK - Found {len(memberships)} users to revert to 'owner'")
            
            for membership in memberships:
                old_role = membership.role
                logger.warning(f"Reverting user {membership.user_id}: {old_role} -> owner")
                
                if not dry_run:
                    try:
                        await db.execute(
                            update(OrgMembership)
                            .where(OrgMembership.id == membership.id)
                            .values(role="owner")
                        )
                        
                        # Track statistics
                        if old_role == "plus_plan":
                            stats["from_plus_plan"] += 1
                        elif old_role == "business_plan":
                            stats["from_business_plan"] += 1
                        elif old_role == "enterprise_plan":
                            stats["from_enterprise_plan"] += 1
                        else:
                            stats["from_unsubscribed"] += 1
                            
                    except Exception as e:
                        error_msg = f"Failed to revert membership {membership.id}: {e}"
                        logger.error(error_msg)
                        stats["errors"].append(error_msg)
                else:
                    # Dry run - just track what would happen
                    if old_role == "plus_plan":
                        stats["from_plus_plan"] += 1
                    elif old_role == "business_plan":
                        stats["from_business_plan"] += 1
                    elif old_role == "enterprise_plan":
                        stats["from_enterprise_plan"] += 1
                    else:
                        stats["from_unsubscribed"] += 1
            
            if not dry_run:
                await db.commit()
                logger.warning("🚨 EMERGENCY ROLLBACK COMMITTED - All users reverted to 'owner'")
            else:
                logger.warning("Dry run - no changes committed")
    
    await engine.dispose()
    return stats


def main():
    parser = argparse.ArgumentParser(description="Emergency rollback - revert subscription-based roles to 'owner'")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--execute", action="store_true", help="Apply rollback changes")
    
    args = parser.parse_args()
    
    if args.execute or args.dry_run:
        mode = "DRY RUN" if args.dry_run else "EXECUTE"
        print(f"🚨 EMERGENCY ROLLBACK - {mode} MODE")
        print("⚠️  This will revert ALL users with subscription-based roles to 'owner'")
        
        if not args.dry_run:
            confirm = input("Type 'EMERGENCY' to confirm: ")
            if confirm != "EMERGENCY":
                print("Rollback cancelled")
                return
        
        stats = asyncio.run(emergency_rollback(dry_run=args.dry_run))
        
        print(f"\nRollback statistics:")
        print(f"  Total reverted: {stats['total_reverted']}")
        print(f"  From plus_plan: {stats['from_plus_plan']}")
        print(f"  From business_plan: {stats['from_business_plan']}")
        print(f"  From enterprise_plan: {stats['from_enterprise_plan']}")
        print(f"  From unsubscribed: {stats['from_unsubscribed']}")
        
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
