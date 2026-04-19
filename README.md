# RG Auth

> **Part of the [ResonantGenesis](https://dev-swat.com) platform** — Identity, access control, MFA, organizations, API keys, and cryptographic identity.

[![Status: Production](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()
[![License: RG Source Available](https://img.shields.io/badge/License-RG%20Source%20Available-blue.svg)](LICENSE.txt)

---

## What This Service Does

The Auth service is the **"who you are"** layer of the platform. Every authenticated request flows through it.

| Service | Owns | Example |
|---|---|---|
| **RG_Auth** (this) | Identity & security | "Who are you?" — login, JWT, MFA, roles, org memberships, API keys |
| **RG_Billing** | Money & credits | "What do you pay?" — subscriptions, credits, usage metering |
| **RG_User_Service** | Profile & preferences | "How do you look & behave?" — display name, theme, dashboard |

---

## GitHub Repository

```
git@github-devswat:DevSwat-ResonantGenesis/RG_Auth.git
```

**Server path**: `/home/deploy/RG_Auth`
**Local path**: `/Users/louie/CascadeProjects/RG/RG_Auth`

---

## Responsibilities

### 1. Authentication
- **Email/password** registration and login with Argon2 password hashing
- **Google OAuth** and **GitHub OAuth** (SSO)
- **JWT** access tokens (1h expiry) + refresh tokens (30d) stored in HTTP-only cookies
- **Account lockout** after failed attempts
- **Email verification** with token-based confirmation flow
- **Password reset** with secure tokens

### 2. Multi-Factor Authentication (MFA)
- **TOTP** (Time-based One-Time Password) — Google Authenticator / Authy
- **Backup codes** (hashed, one-time use)
- **Trusted devices** — "remember this device" for 30 days
- **MFA enforcement** rules per org/role

### 3. Multi-Tenant Organizations
- **Organizations** with name, slug, plan tier, status
- **Org memberships** linking users to orgs with roles: `owner`, `admin`, `viewer`
- **Default org** per user — auto-selected on login
- **Plans per org**: `developer`, `plus`, `enterprise`

### 4. API Key Management
- **Org-level API keys** — scoped, prefixed, with expiry (`rg_xxxx...`)
- **User BYOK keys** — Bring Your Own Key for LLM providers (OpenAI, Anthropic, Google, Groq, Mistral, etc.)
- **Agent-specific API keys** — programmatic access per agent (`rga_xxxx...`)
- All keys stored as Argon2 hashes, only prefix shown after creation

### 5. Cryptographic Identity
- **BIP-39 anchor seed** — deterministic seed per user (encrypted at rest)
- **Universe ID** — derived from seed, ties user to Memory Universe
- **Crypto hash** — for blockchain/NFT ownership proofs
- **User hash** — Hash Sphere identity

### 6. Session Management
- **Active sessions** list with device info, location (GeoIP), last active
- **Revoke individual sessions** or revoke all
- **Trusted device** management — list, add, revoke

### 7. Owner/Admin Dashboard
- Platform-wide stats (total users, active users, org count)
- User management (list, search, reset password, set password)
- Platform settings read/write

### 8. Third-Party Integrations
- **Google services** connection (Drive, Calendar, Gmail) — OAuth flow with token storage
- **Slack** workspace integration — OAuth flow with workspace linking

---

## Architecture & Data Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                      ORG_Frontend (React)                        │
│                                                                  │
│  Login/Register  ──→ POST /auth/login, /auth/register            │
│  OAuth           ──→ GET  /auth/sso/oauth/{provider}/authorize   │
│  Get current user──→ GET  /auth/me                               │
│  MFA setup       ──→ POST /auth/mfa/setup                        │
│  API keys        ──→ GET  /auth/api-keys                         │
│  BYOK keys       ──→ GET  /auth/user/api-keys                    │
│  Sessions        ──→ GET  /auth/sessions                         │
│  Agent settings  ──→ GET  /auth/settings/agents/*                │
└───────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS (dev-swat.com)
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                    RG_Gateway (FastAPI proxy)                     │
│                                                                  │
│  /auth/*           ──proxy──→  auth_service:8000/auth/*           │
│  /owner/auth/*     ──direct──→ auth_service:8000/owner/auth/*     │
│  /user/api-keys/*  ──proxy──→  auth_service:8000/auth/user/*      │
│  /oauth/*          ──proxy──→  auth_service:8000/oauth/*          │
│  /v1/public/*      ──proxy──→  auth_service:8000/v1/public/*      │
│                                                                  │
│  NOTE: /auth/settings/agents/* is intercepted by Gateway          │
│        and redirected to agent_engine_service, NOT auth_service   │
└───────────────────────────┬──────────────────────────────────────┘
                            │ Docker internal network
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                   RG_Auth (this service)                          │
│                      Port 8000                                   │
│                                                                  │
│  10 routers (refactored from monolithic routers.py):             │
│    routers.py            ── /auth/* core (30 endpoints, ~2.2k)   │
│    mfa_routes.py         ── /auth/mfa/* (6 endpoints)            │
│    password_routes.py    ── /auth/{change,forgot,reset}-password  │
│    email_routes.py       ── /auth/verify-email, resend, status   │
│    sessions_routes.py    ── /auth/sessions/*, trusted-devices/*  │
│    byok_routes.py        ── /auth/user/api-keys/* (11 endpoints) │
│    api_keys_routes.py    ── /auth/api-keys/* (4 endpoints)       │
│    agent_settings_routes ── /auth/settings/agents/* extended      │
│    owner_auth.py         ── /owner/auth/* (admin/owner endpoints)│
│    routers_services.py   ── /auth/services/* (Google, Slack)     │
│                                                                  │
│  Outbound calls:                                                 │
│    ├── RG_Blockchain  (external_blockchain_service:8000)         │
│    │   → Crypto identity provisioning on signup                  │
│    └── Redis (shared_redis:6379)                                 │
│        → Rate limiting, OAuth state, session cache               │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│           PostgreSQL (DigitalOcean Managed Database)              │
│           resonant-db / defaultdb                                │
│                                                                  │
│  Tables (10):                                                    │
│    users              — core identity (258 cols w/ MFA, lockout) │
│    organizations      — multi-tenant orgs                        │
│    org_memberships    — user↔org role mapping                    │
│    refresh_tokens     — JWT refresh tokens + session metadata    │
│    api_keys           — org-level API keys                       │
│    user_api_keys      — BYOK per-provider keys (encrypted)      │
│    agents             — agent definitions                        │
│    agent_api_keys     — per-agent programmatic keys              │
│    trusted_devices    — MFA bypass devices                       │
│    password_reset_tokens — password recovery                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Dependencies & Connections

### Upstream (who calls this service)

| Caller | How | What it calls |
|---|---|---|
| **ORG_Frontend** | Via Gateway HTTPS proxy | All `/auth/*` routes — login, register, MFA, keys, sessions |
| **RG_Gateway** | HTTP proxy on Docker network | All routes — also uses `/auth/verify` to validate JWTs on every request |
| **RG_IDE** | Via Gateway | `/auth/me`, `/auth/api-keys`, OAuth flows |

### Downstream (what this service calls)

| Service | URL (Docker internal) | Why |
|---|---|---|
| **PostgreSQL** | `AUTH_DATABASE_URL` env var | All persistent data (users, orgs, keys, tokens) |
| **Redis** | `redis://shared_redis:6379` | Rate limiting, OAuth state storage, session cache |
| **RG_Blockchain** | `http://external_blockchain_service:8000` | Crypto identity provisioning on user signup |

### Services that READ from Auth (internal calls)

| Service | What it reads | Why |
|---|---|---|
| **RG_User_Service** | Dashboard calls `auth_service:8000/auth/orgs/members` | Org member list for dashboard |
| **RG_User_Service** | Dashboard calls `auth_service:8000/admin/stats` | Platform-wide stats (owner tier) |
| **RG_Billing** | Validates user identity on credit operations | JWT verification |
| **All services** | Gateway injects `x-user-id` from Auth JWT on every proxied request | Identity propagation |

### No dependency on

| Service | Why |
|---|---|
| **RG_User_Service** | Auth doesn't know about profiles/preferences — separate concern |
| **RG_Billing** | Auth doesn't check credits — billing is independent |
| **RG_Chat** | Auth has no direct chat dependency |
| **RG_Mining** | Mining authenticates via Gateway headers, not direct auth calls |

---

## Database Schema

### `users` (core identity table)
| Column | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | **The user_id used across ALL services** |
| `email` | String(320) | Unique, indexed |
| `username` | String(100) | Unique, indexed, nullable |
| `full_name` | String(255) | Display name |
| `password_hash` | String(255) | Argon2 hash |
| `status` | String(50) | `active`, `suspended`, `deleted` |
| `is_active` | Boolean | Account active flag |
| `is_superuser` | Boolean | Platform superuser |
| `unlimited_credits` | Boolean | Bypass billing (no role elevation) |
| `trial_expires_at` | Timestamp | 1-week unlimited trial expiry |
| `default_org_id` | UUID | Auto-selected org on login |
| `token_version` | Integer | Increment to invalidate all tokens |
| `last_login_at` | Timestamp | Last successful login |
| `mfa_enabled` | Boolean | MFA active |
| `mfa_secret` | String(500) | Encrypted TOTP secret |
| `mfa_backup_codes` | JSON | Hashed backup codes |
| `failed_login_attempts` | Integer | Lockout counter |
| `locked_until` | Timestamp | Account lockout expiry |
| `email_verified` | Boolean | Email confirmed |
| `anchor_seed` | String(500) | Encrypted BIP-39 seed |
| `universe_id` | String(32) | Derived Memory Universe ID |
| `crypto_hash` | String(64) | Blockchain identity hash |
| `user_hash` | String(64) | Hash Sphere identity |
| `created_at` / `updated_at` | Timestamp | Auto |

### `organizations`
| Column | Type | Notes |
|---|---|---|
| `id` | UUID (PK) | Referenced by `org_memberships`, `api_keys` |
| `name` | String(255) | Org display name |
| `slug` | String(128) | Unique URL slug |
| `plan` | String(50) | `developer`, `plus`, `enterprise` |
| `status` | String(50) | `active`, `suspended` |
| `meta` / `settings` | JSON | Extensible config |

### `org_memberships`
| Column | Type | Notes |
|---|---|---|
| `user_id` + `org_id` | UUID | Composite unique constraint |
| `role` | String(50) | `owner`, `admin`, `viewer` |

### `refresh_tokens`
| Column | Type | Notes |
|---|---|---|
| `user_id` | UUID | Token owner |
| `token_hash` | String(128) | Hashed refresh token |
| `device_name` / `device_type` / `location` | String | Session metadata |
| `expires_at` | Timestamp | 30-day default |

### `api_keys` (org-level)
| Column | Type | Notes |
|---|---|---|
| `org_id` | UUID | Which org owns this key |
| `prefix` | String(12) | Visible prefix (`rg_xxxx`) |
| `hashed_key` | String(128) | Argon2 hash of full key |
| `scopes` | JSON | Allowed operations |

### `user_api_keys` (BYOK — Bring Your Own Key)
| Column | Type | Notes |
|---|---|---|
| `user_id` | UUID | Key owner |
| `provider` | String(50) | `openai`, `anthropic`, `google`, `groq`, `mistral`, etc. |
| `encrypted_key` | Text | AES-encrypted API key |
| `is_primary` | Boolean | Default key for this provider |

### `agents`
| Column | Type | Notes |
|---|---|---|
| `user_id` | UUID | Creator |
| `agent_hash` | String(64) | Unique agent identity |
| `system_prompt` | Text | Agent personality |
| `personality_config` / `memory_config` / `anchor_config` | JSON | Agent configuration |
| `is_template` / `is_shared` / `is_public` | Boolean | Sharing flags |

### `agent_api_keys`
| Column | Type | Notes |
|---|---|---|
| `agent_id` | UUID | Which agent |
| `prefix` | String(16) | `rga_xxxx` |
| `scopes` | JSON | Allowed operations |
| `rate_limit` | Integer | Requests per minute |

### `trusted_devices` / `password_reset_tokens`
Standard security token tables with expiry and device fingerprinting.

---

## API Routes (84 endpoints)

### Core Auth
| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Register with email/password |
| POST | `/auth/signup` | Public signup (alias) |
| POST | `/auth/login` | Login (returns JWT cookies) |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout (revoke tokens, clear cookies) |
| POST | `/auth/verify` | Verify JWT token (used by Gateway on every request) |
| GET | `/auth/me` | Get current authenticated user |

### MFA
| Method | Path | Description |
|---|---|---|
| POST | `/auth/mfa/setup` | Generate TOTP secret + QR code |
| POST | `/auth/mfa/verify` | Verify TOTP code and enable MFA |
| POST | `/auth/mfa/disable` | Disable MFA |
| POST | `/auth/mfa/backup-codes` | Generate new backup codes |

### OAuth / SSO
| Method | Path | Description |
|---|---|---|
| GET | `/auth/sso/oauth/{provider}/authorize` | Start OAuth flow (Google, GitHub) |
| GET | `/auth/sso/oauth/callback` | OAuth callback |
| GET | `/auth/desktop-callback` | IDE desktop OAuth callback |

### Email Verification
| Method | Path | Description |
|---|---|---|
| POST | `/auth/verify-email` | Verify email with token |
| POST | `/auth/resend-verification` | Resend verification email |
| GET | `/auth/email-status` | Check verification status |

### Sessions & Devices
| Method | Path | Description |
|---|---|---|
| GET | `/auth/sessions` | List active sessions |
| DELETE | `/auth/sessions/{id}` | Revoke specific session |
| POST | `/auth/sessions/revoke-all` | Revoke all sessions |
| GET | `/auth/trusted-devices` | List trusted devices |
| POST | `/auth/trusted-devices` | Trust current device |
| DELETE | `/auth/trusted-devices/{id}` | Revoke trusted device |

### API Keys (Org-level)
| Method | Path | Description |
|---|---|---|
| GET | `/auth/api-keys` | List org API keys |
| POST | `/auth/api-keys` | Create org API key |
| POST | `/auth/api-keys/revoke` | Revoke org API key |
| POST | `/auth/api-keys/verify` | Verify an API key |

### User BYOK Keys
| Method | Path | Description |
|---|---|---|
| GET | `/auth/user/api-keys` | List user's provider keys |
| POST | `/auth/user/api-keys` | Add a provider key |
| POST | `/auth/user/api-keys/validate` | Validate a key with provider |
| DELETE | `/auth/user/api-keys/{id}` | Delete a key |
| PUT | `/auth/user/api-keys/{id}/set-primary` | Set default key for provider |

### Agents (settings stored in Auth, execution in Agent Engine)
| Method | Path | Description |
|---|---|---|
| GET/POST/PUT/DELETE | `/auth/settings/agents/*` | Agent CRUD, templates, sharing, export/import |
| GET/POST/DELETE | `/auth/settings/agents/{id}/api-keys` | Agent-specific API keys |
| GET/PUT | `/auth/settings/agents/{id}/memory` | Agent memory config |
| GET/PUT | `/auth/settings/agents/{id}/restrictions` | Agent restriction rules |

### Cryptographic Identity
| Method | Path | Description |
|---|---|---|
| GET | `/auth/identity` | Get user's crypto hash + universe ID |
| POST | `/auth/mnemonic` | Get/generate BIP-39 mnemonic |

### Owner/Admin (`/owner/auth/*`)
| Method | Path | Description |
|---|---|---|
| POST | `/owner/auth/login` | Owner login (separate auth) |
| GET | `/owner/auth/validate` | Validate owner token |
| GET | `/owner/auth/dashboard/stats` | Platform-wide stats |
| GET | `/owner/auth/dashboard/users` | User management list |
| GET/POST | `/owner/auth/settings` | Platform settings |
| POST | `/owner/auth/admin/reset-password/{id}` | Admin password reset |

### Third-Party Integrations
| Method | Path | Description |
|---|---|---|
| POST | `/auth/services/google/initiate` | Start Google OAuth for Drive/Calendar/Gmail |
| POST | `/auth/services/google/callback` | Google services callback |
| POST | `/auth/services/slack/initiate` | Start Slack workspace OAuth |
| POST | `/auth/services/slack/callback` | Slack callback |
| GET | `/auth/integrations` | List connected integrations |

---

## Security Features

- **Password hashing**: Argon2id (via `passlib[argon2]`)
- **JWT tokens**: HS256, signed with `JWT_SECRET_KEY`, 1h access / 30d refresh
- **Cookies**: HTTP-only, Secure, SameSite=Lax
- **Rate limiting**: Redis-backed per-IP rate limiter on login/register
- **Account lockout**: Progressive lockout after failed login attempts
- **API key storage**: Argon2 hashed (org keys), AES encrypted (BYOK keys)
- **MFA secrets**: Encrypted at rest
- **Anchor seeds**: AES encrypted BIP-39 mnemonics
- **Token versioning**: Increment `token_version` to invalidate all user's tokens instantly
- **GeoIP**: MaxMind integration for login location tracking
- **Audit logging**: `audit.py` for security-relevant event tracking

---

## Alembic Migrations

10 migration versions tracking schema evolution:

| Version | Description |
|---|---|
| 002 | Add organizations + refresh_tokens tables |
| 003 | Add MFA fields to users |
| 004 | Add agent API keys table |
| 005 | Add account lockout fields |
| 006 | Add email verification fields |
| 007 | Add audit_logs table |
| 008 | Add session + trusted device fields |
| 009 | Add unlimited_credits field |
| 010 | Add trial_expires_at field |

Run migrations:
```bash
alembic upgrade head
```

---

## File Structure

```
RG_Auth/
├── Dockerfile                    # Python 3.11-slim, uvicorn
├── LICENSE.txt
├── README.md                     # This file
├── requirements.txt              # 16 dependencies
├── alembic.ini                   # Alembic config
├── alembic/
│   ├── env.py                    # Async migration runner
│   ├── script.py.mako            # Template
│   └── versions/                 # 10 migrations (002–010)
├── migrations/
│   └── 003_multi_keys_per_provider.sql  # Manual SQL migration
├── tests/
│   ├── test_auth.py              # Unit tests
│   ├── test_auth_integration.py  # Integration tests
│   └── run_auth_tests.sh         # Test runner
└── app/
    ├── main.py                   # FastAPI app, mounts 10 routers, startup
    ├── config.py                 # Settings (Pydantic), JWT config, DB URL, secrets
    ├── db.py                     # Async SQLAlchemy engine + session
    ├── models.py                 # 10 tables (User, Org, Membership, Keys, Agents, etc.)
    │
    │   # ── Routers (84 endpoints total) ──
    ├── routers.py                # Core auth + SSO/OAuth + orgs + agent CRUD (30 endpoints)
    ├── mfa_routes.py             # MFA TOTP + backup codes (6 endpoints)
    ├── password_routes.py        # Change/forgot/reset password (3 endpoints)
    ├── email_routes.py           # Email verification (3 endpoints)
    ├── sessions_routes.py        # Sessions + trusted devices (7 endpoints)
    ├── byok_routes.py            # User BYOK API keys (11 endpoints)
    ├── api_keys_routes.py        # Org-level API keys (4 endpoints)
    ├── agent_settings_routes.py  # Agent templates, sharing, anchors, etc. (20 endpoints)
    ├── owner_auth.py             # Owner/admin routes (/owner/auth/*)
    ├── routers_services.py       # Google/Slack integration routes
    │
    │   # ── Shared modules ──
    ├── schemas.py                # All Pydantic request/response models
    ├── deps.py                   # Shared helpers (cookies, identity, utils)
    ├── security.py               # JWT creation, validation, password hashing
    ├── crypto.py                 # AES encryption for API keys and seeds
    ├── mfa.py                    # TOTP generation, verification, backup codes
    ├── mfa_enforcement.py        # MFA policy enforcement rules
    ├── oauth.py                  # Google/GitHub OAuth flow
    ├── oauth_redis.py            # Redis-backed OAuth state storage
    ├── sessions.py               # Session management (list, revoke)
    ├── roles.py                  # RBAC role definitions and checks
    ├── rate_limit.py             # Redis-backed rate limiter
    ├── audit.py                  # Security audit logging
    ├── metrics.py                # Prometheus metrics
    ├── errors.py                 # Custom error types
    ├── identity.py               # Crypto identity (hashes, universe ID)
    ├── keypair_generation.py     # Ed25519 keypair generation
    ├── seed_manager.py           # BIP-39 seed management
    ├── geoip.py                  # MaxMind GeoIP lookup
    ├── email_service.py          # SMTP/SendGrid email sending
    ├── email_verification.py     # Email verification flow
    ├── login_notifications.py    # Login notification emails
    ├── economic_integration.py   # Billing/economic state hooks
    └── init_db.py                # Database initialization
```

---

## Environment Variables

All prefixed with `AUTH_` (via Pydantic `env_prefix`):

| Variable | Default | Description |
|---|---|---|
| `AUTH_DATABASE_URL` | (constructed from DB_HOST/PORT/etc.) | PostgreSQL connection string |
| `AUTH_JWT_SECRET_KEY` | **REQUIRED in production** | JWT signing secret |
| `AUTH_API_KEY_SALT` | **REQUIRED in production** | Salt for API key hashing |
| `AUTH_INTERNAL_SERVICE_KEY` | **REQUIRED in production** | Service-to-service auth |
| `AUTH_FRONTEND_URL` | `https://dev-swat.com` | For OAuth callbacks and email links |
| `AUTH_COOKIE_DOMAIN` | *(empty = same-origin)* | Set to `.dev-swat.com` in production |
| `AUTH_COOKIE_SECURE` | `true` | HTTPS-only cookies |
| `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT access token lifetime |
| `AUTH_REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh token lifetime |
| `AUTH_SMTP_HOST` | *(empty)* | SMTP server for emails |
| `AUTH_SMTP_USER` / `AUTH_SMTP_PASSWORD` | *(empty)* | SMTP credentials |
| `AUTH_SENDGRID_API_KEY` | *(empty)* | Alternative email provider |
| `AUTH_REQUIRE_EMAIL_VERIFICATION` | `true` | Enforce email verification |
| `AUTH_MAXMIND_LICENSE_KEY` | *(empty)* | GeoIP for login location |
| `AUTH_SENTRY_DSN` | *(empty)* | Error monitoring |
| `REDIS_URL` | `redis://shared_redis:6379` | Rate limiting + OAuth state |

---

## Deployment

- **Container name**: `auth_service`
- **Port**: 8000
- **Server path**: `/home/deploy/RG_Auth`
- **Docker network**: `genesis2026_production_backend_app-network`
- **Database**: DigitalOcean Managed PostgreSQL (`resonant-db`)
- **Redis**: `shared_redis` container on same network
- **Health check**: `GET /health` every 30s
- **Restart policy**: `unless-stopped`

### Docker Compose entry (in `RG_core/docker-compose.unified.yml`)
```yaml
auth_service:
  build:
    context: /home/deploy/RG_Auth
    dockerfile: Dockerfile
  container_name: auth_service
  env_file:
    - ./.env.production
  environment:
    DATABASE_URL: ${AUTH_DATABASE_URL}
    REDIS_URL: redis://shared_redis:6379/0
  depends_on:
    - shared_redis
  networks:
    - app-network
  restart: unless-stopped
```

---

## Quick Start (local development)

```bash
cd RG_Auth
pip install -r requirements.txt

export AUTH_DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db"
export AUTH_JWT_SECRET_KEY="dev-secret-change-me"
export REDIS_URL="redis://localhost:6379/0"

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

**Organization**: [DevSwat-ResonantGenesis](https://github.com/DevSwat-ResonantGenesis) | **Platform**: [dev-swat.com](https://dev-swat.com)
