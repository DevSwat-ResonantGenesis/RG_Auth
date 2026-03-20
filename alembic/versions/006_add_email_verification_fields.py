"""Add email verification fields to users table

Revision ID: 006_add_email_verification
Revises: 005_add_account_lockout
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '006_add_email_verification'
down_revision = '005_add_account_lockout'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Get existing columns to avoid duplicate column errors
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    # Add email verification fields if they don't exist
    if 'email_verified' not in existing_columns:
        op.add_column('users', sa.Column('email_verified', sa.Boolean(), nullable=False, server_default='false'))
    
    if 'email_verified_at' not in existing_columns:
        op.add_column('users', sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True))
    
    if 'email_verification_token' not in existing_columns:
        op.add_column('users', sa.Column('email_verification_token', sa.String(128), nullable=True))
    
    if 'email_verification_sent_at' not in existing_columns:
        op.add_column('users', sa.Column('email_verification_sent_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'email_verification_sent_at')
    op.drop_column('users', 'email_verification_token')
    op.drop_column('users', 'email_verified_at')
    op.drop_column('users', 'email_verified')
