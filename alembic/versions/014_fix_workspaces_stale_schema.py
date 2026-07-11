"""Fix workspaces table left with a stale pre-existing schema

Revision 013 skipped creating/altering the `workspaces` table because a
table by that name already existed (an orphaned, unrelated schema with
agent_id/name/root_path/settings/is_active columns, 0 rows, no code
references anywhere in the codebase). This left production without the
title/last_active_at columns the Workspace model actually requires,
500ing every /auth/user/workspaces call.

Revision ID: 014_fix_workspaces
Revises: 013_add_workspaces
Create Date: 2026-07-11

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '014_fix_workspaces'
down_revision = '013_add_workspaces'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = {c['name'] for c in inspector.get_columns('workspaces')}

    if 'title' not in columns:
        op.add_column('workspaces', sa.Column('title', sa.String(255), nullable=True))
        op.execute("UPDATE workspaces SET title = COALESCE(name, 'Untitled')")
        op.alter_column('workspaces', 'title', nullable=False)

    if 'last_active_at' not in columns:
        op.add_column(
            'workspaces',
            sa.Column('last_active_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        )

    for legacy_col in ('agent_id', 'name', 'description', 'root_path', 'settings', 'is_active', 'updated_at'):
        if legacy_col in columns:
            op.drop_column('workspaces', legacy_col)


def downgrade() -> None:
    op.add_column('workspaces', sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('workspaces', sa.Column('name', sa.String(255), nullable=True))
    op.add_column('workspaces', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('workspaces', sa.Column('root_path', sa.String(512), nullable=True))
    op.add_column('workspaces', sa.Column('settings', sa.JSON(), nullable=True))
    op.add_column('workspaces', sa.Column('is_active', sa.Boolean(), nullable=True))
    op.add_column('workspaces', sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))
    op.drop_column('workspaces', 'last_active_at')
    op.drop_column('workspaces', 'title')
