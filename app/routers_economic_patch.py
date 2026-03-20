"""
SIGNUP FLOW REWRITE - Economic State Integration

This file contains the EXACT changes needed to integrate UserEconomicState
into the registration flow.

BEFORE: Registration creates user + org, but NO economic state
AFTER: Registration creates user + org + UserEconomicState atomically

INVARIANT: No user enters the system without a UserEconomicState

---

PATCH INSTRUCTIONS FOR auth_service/app/routers.py:

1. Add import at top of file:
   from .economic_integration import create_user_economic_state, EconomicIntegrationError

2. Replace the register() function with the version below.

3. Replace the dev_create_user() function with the version below.

---
"""

# ============================================
# NEW REGISTER FUNCTION (replaces existing)
# ============================================

"""
@router.post("/auth/register", response_model=LoginResponse)
async def register(
    request: Request,
    payload: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    '''
    Register a new user with organization and economic state.
    
    Creates (atomically):
    1. Organization (with name or default)
    2. User (with email, password, full_name)
    3. OrgMembership (user -> org, role=owner)
    4. UserEconomicState (in billing_service) <-- NEW
    5. JWT tokens with Identity claims
    6. HttpOnly cookies
    
    INVARIANT: If UserEconomicState creation fails, registration fails.
    '''
    # Check for duplicate email
    result = await db.execute(select(User).where(User.email == payload.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create organization
    org_name = payload.org_name or f"{payload.email.split('@')[0]}'s Organization"
    org = Organization(
        name=org_name,
        slug=_generate_slug(org_name),
        is_active=True,
    )
    db.add(org)
    await db.flush()  # Get org.id

    # Create user
    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name or payload.username or payload.email.split('@')[0],
        password_hash=hash_password(payload.password),
        is_active=True,
        is_superuser=False,
        default_org_id=org.id,
        status="active",
    )
    db.add(user)
    await db.flush()  # Get user.id
    
    # Generate cryptographic identity
    crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, payload.email)
    user.crypto_hash = crypto_hash
    user.user_hash = user_hash
    user.universe_id = universe_id

    # Create membership (owner role)
    membership = OrgMembership(
        user_id=user.id,
        org_id=org.id,
        role="owner",
        status="active",
    )
    db.add(membership)
    
    # ============================================
    # NEW: Create UserEconomicState in billing_service
    # ============================================
    try:
        economic_state = await create_user_economic_state(
            user_id=user.id,
            org_id=org.id,
            tier="developer",  # Default tier for new users
            subscription_source="internal",
            is_dev_override=False,
        )
    except EconomicIntegrationError as e:
        # CRITICAL: Rollback the transaction if economic state creation fails
        await db.rollback()
        raise HTTPException(
            status_code=503,
            detail=f"Registration failed: could not create economic state. {e}"
        )
    # ============================================
    
    await db.commit()

    # Create Identity
    identity = Identity(
        user_id=user.id,
        org_id=org.id,
        role="owner",
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    # Create tokens
    access_token = create_access_token(identity, user.token_version)
    refresh_plain = await _issue_refresh_token(db, identity, request)
    
    # Set cookies
    _set_auth_cookies(response, access_token, refresh_plain)

    return LoginResponse(
        access_token=access_token,
        org_id=org.id,
        role="owner",
        user={
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
        }
    )
"""


# ============================================
# NEW DEV_CREATE_USER FUNCTION (replaces existing)
# ============================================

"""
@router.post("/auth/dev-create-user", response_model=LoginResponse)
async def dev_create_user(
    request: Request,
    payload: DevCreateUserRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    '''Create a local dev user + org + economic state and return login tokens.

    This endpoint is intended *only* for local development. It creates
    a user with is_dev_override=True, which bypasses all economic limits.
    '''

    # Hard safety check: never allow this outside development
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found")

    # Normalize inputs
    email = payload.email
    full_name = payload.full_name or "Dev User"
    org_name = payload.org_name or "Dev Organization"

    # Check if user already exists
    result = await db.execute(select(User).where(User.email == email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        user = existing_user
        # Ensure password is usable for local testing
        user.password_hash = hash_password(payload.password)
        db.add(user)
        await db.commit()

        # Ensure there is at least one active membership
        membership_result = await db.execute(
            select(OrgMembership).where(
                OrgMembership.user_id == user.id,
                OrgMembership.status == "active",
            )
        )
        membership = membership_result.scalar_one_or_none()
        if not membership:
            org_result = await db.execute(select(Organization))
            org = org_result.scalar_one_or_none()
            if org:
                membership = OrgMembership(
                    user_id=user.id,
                    org_id=org.id,
                    role="owner",
                    status="active",
                )
                db.add(membership)
                await db.commit()
        
        org_id = membership.org_id if membership else user.default_org_id
        
    else:
        # Create new user + org
        org = Organization(
            name=org_name,
            slug=_generate_slug(org_name),
            is_active=True,
        )
        db.add(org)
        await db.flush()

        user = User(
            email=email,
            username=email.split('@')[0],
            full_name=full_name,
            password_hash=hash_password(payload.password),
            is_active=True,
            is_superuser=True,  # Dev users are superusers
            default_org_id=org.id,
            status="active",
        )
        db.add(user)
        await db.flush()

        # Generate cryptographic identity
        crypto_hash, user_hash, universe_id = _generate_crypto_identity(user.id, email)
        user.crypto_hash = crypto_hash
        user.user_hash = user_hash
        user.universe_id = universe_id

        membership = OrgMembership(
            user_id=user.id,
            org_id=org.id,
            role="owner",
            status="active",
        )
        db.add(membership)
        
        # ============================================
        # NEW: Create UserEconomicState with dev override
        # ============================================
        try:
            economic_state = await create_user_economic_state(
                user_id=user.id,
                org_id=org.id,
                tier="enterprise",  # Dev users get enterprise tier
                subscription_source="internal",
                is_dev_override=True,  # CRITICAL: This bypasses all limits
            )
        except EconomicIntegrationError as e:
            await db.rollback()
            raise HTTPException(
                status_code=503,
                detail=f"Dev user creation failed: could not create economic state. {e}"
            )
        # ============================================
        
        await db.commit()
        org_id = org.id

    # Create Identity
    identity = Identity(
        user_id=user.id,
        org_id=org_id,
        role="owner",
        scopes=[],
        api_key_id=None,
        auth_method="jwt",
    )

    # Create tokens
    access_token = create_access_token(identity, user.token_version)
    refresh_plain = await _issue_refresh_token(db, identity, request)
    
    # Set cookies
    _set_auth_cookies(response, access_token, refresh_plain)

    return LoginResponse(
        access_token=access_token,
        org_id=org_id,
        role="owner",
        user={
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
        }
    )
"""


# ============================================
# MIGRATION SCRIPT FOR EXISTING USERS
# ============================================

"""
For existing users who don't have a UserEconomicState, run this migration:

async def migrate_existing_users_to_economic_state():
    '''
    One-time migration to create UserEconomicState for all existing users.
    Run this ONCE after deploying the new schema.
    '''
    from auth_service.app.db import async_session
    from auth_service.app.models import User, OrgMembership
    from auth_service.app.economic_integration import create_user_economic_state
    
    async with async_session() as db:
        # Get all users
        result = await db.execute(select(User))
        users = result.scalars().all()
        
        for user in users:
            # Get user's org
            membership_result = await db.execute(
                select(OrgMembership).where(
                    OrgMembership.user_id == user.id,
                    OrgMembership.status == "active",
                )
            )
            membership = membership_result.scalar_one_or_none()
            
            if not membership:
                print(f"Skipping user {user.id} - no active membership")
                continue
            
            # Check if user is a dev/admin
            is_dev = user.is_superuser or membership.role in ("admin", "platform_dev")
            
            try:
                await create_user_economic_state(
                    user_id=user.id,
                    org_id=membership.org_id,
                    tier="enterprise" if is_dev else "developer",
                    subscription_source="internal",
                    is_dev_override=is_dev,
                )
                print(f"Created economic state for user {user.id}")
            except Exception as e:
                print(f"Failed to create economic state for user {user.id}: {e}")
"""
