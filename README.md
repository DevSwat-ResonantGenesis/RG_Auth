# RG Auth

> **Part of the [ResonantGenesis](https://dev-swat.com) platform** — Identity & access control service.

[![Status: Production](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()
[![License: RG Source Available](https://img.shields.io/badge/License-RG%20Source%20Available-blue.svg)](LICENSE.txt)

## Features
- JWT token issuance and validation
- Login/register with email, Google OAuth, GitHub OAuth
- Role and plan management (free/pro/enterprise/owner)
- Owner-level auth for admin endpoints

## Quick Start
```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Deployment
- **Container**: `auth_service` | **Port**: 8000
- **Server path**: `/home/deploy/RG_Auth`

---
**Organization**: [DevSwat-ResonantGenesis](https://github.com/DevSwat-ResonantGenesis) | **Platform**: [dev-swat.com](https://dev-swat.com)
