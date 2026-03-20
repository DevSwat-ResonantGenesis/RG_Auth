#!/usr/bin/env python3
"""
Database initialization script for Auth Service
Creates all necessary tables for the authentication system
"""

import asyncio
import sys
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from .db import engine, Base
from .models import User, Organization, OrgMembership, RefreshToken, ApiKey, UserApiKey, PasswordResetToken, Agent
from .audit import AuditLog  # Import AuditLog to ensure table is created

async def init_database():
    """Initialize the database with all tables"""
    print("🔧 Initializing Auth Service Database...")
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("✅ Database tables created successfully!")
        
        # List created tables
        async with engine.begin() as conn:
            result = await conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            )
            tables = [row[0] for row in result]
            
        print(f"📋 Created tables: {', '.join(tables)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

async def check_database():
    """Check if database is accessible"""
    print("🔍 Checking database connection...")
    
    try:
        async with engine.begin() as conn:
            result = await conn.execute("SELECT 1")
            print("✅ Database connection successful!")
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

async def create_test_user():
    """Create a test user for development"""
    print("👤 Creating test user...")
    
    try:
        from .db import SessionLocal
        from .security import hash_password
        
        async with SessionLocal() as session:
            # Check if test user already exists
            from sqlalchemy import select
            result = await session.execute(
                select(User).where(User.email == "test@example.com")
            )
            existing_user = result.scalar_one_or_none()
            
            if existing_user:
                print("ℹ️  Test user already exists")
                return True
            
            # Create test user
            test_user = User(
                email="test@example.com",
                username="testuser",
                full_name="Test User",
                password_hash=hash_password("test123"),
                status="active",
                is_active=True,
                is_superuser=True,
                email_verified=True,
                email_verified_at=asyncio.get_event_loop().time()
            )
            
            session.add(test_user)
            await session.commit()
            await session.refresh(test_user)
            
            print(f"✅ Test user created with ID: {test_user.id}")
            return True
            
    except Exception as e:
        print(f"❌ Failed to create test user: {e}")
        return False

async def main():
    """Main initialization function"""
    print("🚀 Auth Service Database Initialization")
    print("=" * 50)
    
    # Check database connection
    if not await check_database():
        sys.exit(1)
    
    # Initialize database
    if not await init_database():
        sys.exit(1)
    
    # Create test user
    if not await create_test_user():
        sys.exit(1)
    
    print("\n🎉 Database initialization complete!")
    print("📝 Test credentials:")
    print("   Email: test@example.com")
    print("   Password: test123")

if __name__ == "__main__":
    asyncio.run(main())
