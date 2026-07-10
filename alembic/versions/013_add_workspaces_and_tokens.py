"""Add workspaces and workspace_access_tokens tables

Revision ID: 013_add_workspaces
Revises: 012_add_user_ssh_hosts
Create Date: 2026-07-10

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '013_add_workspaces'
down_revision = '012_add_user_ssh_hosts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    if 'workspaces' not in existing_tables:
        op.create_table(
            'workspaces',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('title', sa.String(255), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
            sa.Column('last_active_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        )
        op.create_index('ix_workspaces_user_id', 'workspaces', ['user_id'])

    if 'workspace_access_tokens' not in existing_tables:
        op.create_table(
            'workspace_access_tokens',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('workspace_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('prefix', sa.String(16), nullable=False),
            sa.Column('hashed_secret', sa.String(255), nullable=False),
            sa.Column('scopes', postgresql.JSON(astext_type=sa.Text()), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index('ix_workspace_access_tokens_workspace_id', 'workspace_access_tokens', ['workspace_id'])
        op.create_index('ix_workspace_access_tokens_prefix', 'workspace_access_tokens', ['prefix'], unique=True)


def downgrade() -> None:
    op.drop_index('ix_workspace_access_tokens_prefix', table_name='workspace_access_tokens')
    op.drop_index('ix_workspace_access_tokens_workspace_id', table_name='workspace_access_tokens')
    op.drop_table('workspace_access_tokens')
    op.drop_index('ix_workspaces_user_id', table_name='workspaces')
    op.drop_table('workspaces')
