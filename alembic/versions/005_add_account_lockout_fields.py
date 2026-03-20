"""Add account lockout fields to users table

Revision ID: 005_add_account_lockout
Revises: 004_add_agent_api_keys
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '005_add_account_lockout'
down_revision = '004_add_agent_api_keys'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Get existing columns to avoid duplicate column errors
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    # Add account lockout fields if they don't exist
    if 'failed_login_attempts' not in existing_columns:
        op.add_column('users', sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
    
    if 'locked_until' not in existing_columns:
        op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))
    
    if 'last_failed_login_at' not in existing_columns:
        op.add_column('users', sa.Column('last_failed_login_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'last_failed_login_at')
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_attempts')
