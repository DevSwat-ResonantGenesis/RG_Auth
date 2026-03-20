"""Add unlimited_credits field to users table

Revision ID: 009_add_unlimited_credits
Revises: 008_add_session_trusted_devices
Create Date: 2026-03-06

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '009_add_unlimited_credits'
down_revision = '008_add_session_trusted_devices'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'unlimited_credits' not in existing_columns:
        op.add_column('users', sa.Column(
            'unlimited_credits',
            sa.Boolean(),
            nullable=False,
            server_default='false',
        ))


def downgrade() -> None:
    op.drop_column('users', 'unlimited_credits')
