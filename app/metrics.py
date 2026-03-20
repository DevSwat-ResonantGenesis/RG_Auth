"""
Prometheus metrics for Auth Service.

Exposes metrics for:
- Request counts and latencies
- Authentication events (login, register, logout)
- MFA operations
- Session management
- Error rates
"""
from prometheus_client import Counter, Histogram, Gauge, Info
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import APIRouter, Response
import time

router = APIRouter()

# ============================================
# SERVICE INFO
# ============================================
AUTH_SERVICE_INFO = Info('auth_service', 'Auth service information')
AUTH_SERVICE_INFO.info({
    'version': '1.0.0',
    'service': 'auth_service',
})

# ============================================
# REQUEST METRICS
# ============================================
REQUEST_COUNT = Counter(
    'auth_requests_total',
    'Total number of requests to auth service',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'auth_request_latency_seconds',
    'Request latency in seconds',
    ['method', 'endpoint'],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# ============================================
# AUTHENTICATION METRICS
# ============================================
LOGIN_TOTAL = Counter(
    'auth_login_total',
    'Total login attempts',
    ['status', 'method']  # status: success/failed, method: password/oauth/saml
)

REGISTER_TOTAL = Counter(
    'auth_register_total',
    'Total registration attempts',
    ['status']  # status: success/failed
)

LOGOUT_TOTAL = Counter(
    'auth_logout_total',
    'Total logout operations',
    ['status']
)

PASSWORD_RESET_TOTAL = Counter(
    'auth_password_reset_total',
    'Total password reset requests',
    ['status']
)

# ============================================
# MFA METRICS
# ============================================
MFA_SETUP_TOTAL = Counter(
    'auth_mfa_setup_total',
    'Total MFA setup attempts',
    ['status']
)

MFA_VERIFY_TOTAL = Counter(
    'auth_mfa_verify_total',
    'Total MFA verification attempts',
    ['status']
)

MFA_ENABLED_USERS = Gauge(
    'auth_mfa_enabled_users',
    'Number of users with MFA enabled'
)

# ============================================
# SESSION METRICS
# ============================================
ACTIVE_SESSIONS = Gauge(
    'auth_active_sessions',
    'Number of active sessions'
)

SESSION_CREATED = Counter(
    'auth_session_created_total',
    'Total sessions created'
)

SESSION_REVOKED = Counter(
    'auth_session_revoked_total',
    'Total sessions revoked',
    ['reason']  # reason: user_logout/admin_revoke/expired/security
)

TRUSTED_DEVICES = Gauge(
    'auth_trusted_devices',
    'Number of trusted devices'
)

# ============================================
# TOKEN METRICS
# ============================================
TOKEN_ISSUED = Counter(
    'auth_token_issued_total',
    'Total tokens issued',
    ['type']  # type: access/refresh
)

TOKEN_REFRESHED = Counter(
    'auth_token_refreshed_total',
    'Total token refresh operations'
)

TOKEN_REVOKED = Counter(
    'auth_token_revoked_total',
    'Total tokens revoked'
)

# ============================================
# ERROR METRICS
# ============================================
AUTH_ERRORS = Counter(
    'auth_errors_total',
    'Total authentication errors',
    ['error_type']  # error_type: invalid_credentials/account_locked/mfa_required/etc
)

ACCOUNT_LOCKED = Counter(
    'auth_account_locked_total',
    'Total accounts locked due to failed attempts'
)

# ============================================
# USER METRICS
# ============================================
TOTAL_USERS = Gauge(
    'auth_total_users',
    'Total registered users'
)

VERIFIED_USERS = Gauge(
    'auth_verified_users',
    'Users with verified email'
)

# ============================================
# AUDIT METRICS
# ============================================
AUDIT_EVENTS = Counter(
    'auth_audit_events_total',
    'Total audit events logged',
    ['event_type']
)

# ============================================
# METRICS ENDPOINT
# ============================================
@router.get("/metrics")
async def metrics():
    """Expose Prometheus metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# ============================================
# HELPER FUNCTIONS
# ============================================
def track_request(method: str, endpoint: str, status: int, duration: float):
    """Track a request for metrics."""
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)


def track_login(success: bool, method: str = "password"):
    """Track a login attempt."""
    status = "success" if success else "failed"
    LOGIN_TOTAL.labels(status=status, method=method).inc()
    if success:
        SESSION_CREATED.inc()
        TOKEN_ISSUED.labels(type="access").inc()
        TOKEN_ISSUED.labels(type="refresh").inc()


def track_register(success: bool):
    """Track a registration attempt."""
    status = "success" if success else "failed"
    REGISTER_TOTAL.labels(status=status).inc()


def track_logout(success: bool = True):
    """Track a logout operation."""
    status = "success" if success else "failed"
    LOGOUT_TOTAL.labels(status=status).inc()
    if success:
        SESSION_REVOKED.labels(reason="user_logout").inc()


def track_mfa_setup(success: bool):
    """Track MFA setup."""
    status = "success" if success else "failed"
    MFA_SETUP_TOTAL.labels(status=status).inc()


def track_mfa_verify(success: bool):
    """Track MFA verification."""
    status = "success" if success else "failed"
    MFA_VERIFY_TOTAL.labels(status=status).inc()


def track_error(error_type: str):
    """Track an authentication error."""
    AUTH_ERRORS.labels(error_type=error_type).inc()


def track_audit_event(event_type: str):
    """Track an audit event."""
    AUDIT_EVENTS.labels(event_type=event_type).inc()


def update_user_gauges(total: int, verified: int, mfa_enabled: int):
    """Update user-related gauges."""
    TOTAL_USERS.set(total)
    VERIFIED_USERS.set(verified)
    MFA_ENABLED_USERS.set(mfa_enabled)


def update_session_gauges(active: int, trusted_devices: int):
    """Update session-related gauges."""
    ACTIVE_SESSIONS.set(active)
    TRUSTED_DEVICES.set(trusted_devices)
