"""Placeholder for 011_add_agent_verify_status

This revision id was already stamped in production's alembic_version table
(the actual schema change was applied out-of-band and never committed to
this repo, discovered 2026-07-10 while adding 012_add_user_ssh_hosts on
top of it). This file only exists so alembic's revision graph is
consistent going forward - upgrade()/downgrade() are intentionally no-ops
since whatever it actually changed already exists live and reapplying an
unknown DDL blind would be unsafe.

TODO: reconcile this with the real prod schema (likely related to
RG_Auth's lightweight Agent table used by pages/Settings/ResonantChat/
Agents/AgentEditor.tsx, which is a separate table from RG_Agent_Engine's
real AgentDefinition table where user-created agents like Pastor AI/Kids
Story actually live - the naming strongly suggests this is that split).

Revision ID: 011_add_agent_verify_status
Revises: 010_add_trial_expires_at
Create Date: 2026-07-10 (backfilled, not the original application date)

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '011_add_agent_verify_status'
down_revision = '010_add_trial_expires_at'
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
