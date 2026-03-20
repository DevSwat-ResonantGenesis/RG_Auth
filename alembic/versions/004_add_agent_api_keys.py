"""Add agent_api_keys table

Revision ID: 004_add_agent_api_keys
Revises: 003_add_mfa_fields
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004_add_agent_api_keys'
down_revision = '003_add_mfa_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Check if table already exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    if 'agent_api_keys' not in inspector.get_table_names():
        op.create_table(
            'agent_api_keys',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('agent_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
            sa.Column('name', sa.String(255), nullable=False),
            sa.Column('prefix', sa.String(16), nullable=False, index=True),
            sa.Column('hashed_key', sa.String(128), nullable=False),
            sa.Column('scopes', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
            sa.Column('rate_limit', sa.Integer(), nullable=False, server_default='100'),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
            sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
            sa.UniqueConstraint('agent_id', 'name', name='uq_agent_api_keys_agent_name'),
        )


def downgrade() -> None:
    op.drop_table('agent_api_keys')
