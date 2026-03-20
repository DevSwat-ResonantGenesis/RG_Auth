"""Add MFA fields to users table

Revision ID: 003_add_mfa_fields
Revises: 002_add_org_and_refresh_tables
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_add_mfa_fields'
down_revision = '002_add_org_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Get existing columns to avoid duplicate column errors
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    # Add MFA fields if they don't exist
    if 'mfa_enabled' not in existing_columns:
        op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'))
    
    if 'mfa_secret' not in existing_columns:
        op.add_column('users', sa.Column('mfa_secret', sa.String(500), nullable=True))
    
    if 'mfa_backup_codes' not in existing_columns:
        op.add_column('users', sa.Column('mfa_backup_codes', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    
    if 'mfa_verified_at' not in existing_columns:
        op.add_column('users', sa.Column('mfa_verified_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Remove MFA fields
    op.drop_column('users', 'mfa_verified_at')
    op.drop_column('users', 'mfa_backup_codes')
    op.drop_column('users', 'mfa_secret')
    op.drop_column('users', 'mfa_enabled')
