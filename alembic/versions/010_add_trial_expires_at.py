"""Add trial_expires_at field to users table for 1-week unlimited trial

Revision ID: 010_add_trial_expires_at
Revises: 009_add_unlimited_credits
Create Date: 2026-03-10

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '010_add_trial_expires_at'
down_revision = '009_add_unlimited_credits'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'trial_expires_at' not in existing_columns:
        op.add_column('users', sa.Column(
            'trial_expires_at',
            sa.DateTime(timezone=True),
            nullable=True,
        ))


def downgrade() -> None:
    op.drop_column('users', 'trial_expires_at')
