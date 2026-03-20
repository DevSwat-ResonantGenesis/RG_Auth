import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

# Deterministic sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import real auth components
try:
    from .db import get_db
    from .models import User
    from .routers import router as auth_router
    from .owner_auth import router as owner_auth_router
    from .config import settings
    print("✅ Real auth components loaded")
except ImportError as e:
    print(f"❌ Import error: {e}")
    # Fallback to basic imports
    get_db = None
    User = None
    auth_router = None
    owner_auth_router = None
    settings = None

# Single service entrypoint
app = FastAPI(
    title="Auth Service",
    description="Real Authentication Service for Genesis2026",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event - validate database connection
@app.on_event("startup")
async def startup_event():
    """Validate critical connections on startup."""
    if get_db:
        from .db import check_database_connection
        db_ok = await check_database_connection()
        if not db_ok:
            print("⚠️ WARNING: Database connection failed!")
    print("✅ Auth service startup complete")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "auth_service"}

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Real Auth Service is running"}

# Include real auth router if available
if auth_router:
    app.include_router(auth_router, tags=["auth"])
    print("✅ Real auth router included")
else:
    # Fallback endpoints removed - using real router endpoints instead
    pass

# Include owner auth router for platform owner login
if owner_auth_router:
    app.include_router(owner_auth_router, tags=["owner-auth"])
    print("✅ Owner auth router included")
else:
    print("⚠️ Owner auth router not available")

# Include Google service connection router (Drive/Calendar/Gmail)
# Isolated in a separate file — failure here can NEVER take down core auth
try:
    from .routers_services import router as services_router
    app.include_router(services_router, tags=["google-services"])
    print("✅ Google services router included")
except Exception as e:
    print(f"⚠️ Google services router failed to load (non-fatal): {e}")

# Direct endpoints for compatibility
@app.post("/login")
async def direct_login():
    return {"message": "Direct login endpoint", "status": "ok"}

@app.post("/register")
async def direct_register():
    return {"message": "Direct register endpoint", "status": "ok"}

# Alias routes for frontend compatibility
@app.get("/auth/oauth/callback")
async def oauth_callback_alias(
    code: str,
    state: str,
    request: Request,
    response: Response,
    error: str = None,
    error_description: str = None,
    db: AsyncSession = Depends(get_db),
):
    """OAuth callback alias - forwards to /auth/sso/oauth/callback"""
    if auth_router:
        from .routers import oauth_callback_get_no_provider
        return await oauth_callback_get_no_provider(
            code=code,
            state=state,
            request=request,
            response=response,
            db=db,
            error=error,
            error_description=error_description,
        )
    raise HTTPException(status_code=503, detail="Auth router not available")

@app.post("/auth/public/signup")
async def public_signup_alias(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Public signup alias - forwards to /auth/signup"""
    if auth_router:
        from .routers import signup
        # Get the JSON body
        body = await request.json()
        from .routers import RegisterRequest
        payload = RegisterRequest(**body)
        return await signup(request, payload, response, db)
    raise HTTPException(status_code=503, detail="Auth router not available")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
