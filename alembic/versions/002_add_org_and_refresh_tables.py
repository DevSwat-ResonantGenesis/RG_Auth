"""Add Organization, OrgMembership, RefreshToken tables and update User model

Revision ID: 002_add_org_tables
Revises: 001_initial
Create Date: 2024-12-11

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002_add_org_tables'
down_revision = None  # Set to your initial migration if exists
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create organizations table
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(128), nullable=False),
        sa.Column('plan', sa.String(50), nullable=False, server_default='free'),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('meta', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('settings', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', name='uq_organizations_slug')
    )
    op.create_index('ix_organizations_name', 'organizations', ['name'])
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    # Create org_memberships table
    op.create_table(
        'org_memberships',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', sa.String(50), nullable=False, server_default='viewer'),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'org_id', name='uq_memberships_user_org')
    )
    op.create_index('ix_org_memberships_user_id', 'org_memberships', ['user_id'])
    op.create_index('ix_org_memberships_org_id', 'org_memberships', ['org_id'])

    # Create refresh_tokens table
    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.String(128), nullable=False),
        sa.Column('user_agent', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(64), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('auth_method', sa.String(50), nullable=False, server_default='jwt'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_refresh_tokens_user_id', 'refresh_tokens', ['user_id'])
    op.create_index('ix_refresh_tokens_org_id', 'refresh_tokens', ['org_id'])
    op.create_index('ix_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'])

    # Add new columns to users table
    # First check if columns exist to avoid errors
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'full_name' not in existing_columns:
        op.add_column('users', sa.Column('full_name', sa.String(255), nullable=True))
    
    if 'status' not in existing_columns:
        op.add_column('users', sa.Column('status', sa.String(50), nullable=False, server_default='active'))
    
    if 'is_superuser' not in existing_columns:
        op.add_column('users', sa.Column('is_superuser', sa.Boolean(), nullable=False, server_default='false'))
    
    if 'default_org_id' not in existing_columns:
        op.add_column('users', sa.Column('default_org_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_index('ix_users_default_org_id', 'users', ['default_org_id'])
    
    if 'token_version' not in existing_columns:
        op.add_column('users', sa.Column('token_version', sa.Integer(), nullable=False, server_default='1'))
    
    if 'last_login_at' not in existing_columns:
        op.add_column('users', sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True))
    
    # Deterministic Anchor Universe fields
    if 'anchor_seed' not in existing_columns:
        op.add_column('users', sa.Column('anchor_seed', sa.String(500), nullable=True))
    
    if 'universe_id' not in existing_columns:
        op.add_column('users', sa.Column('universe_id', sa.String(32), nullable=True))
        op.create_index('ix_users_universe_id', 'users', ['universe_id'])
    
    if 'seed_encrypted' not in existing_columns:
        op.add_column('users', sa.Column('seed_encrypted', sa.Boolean(), nullable=False, server_default='false'))
    
    # Crypto hash fields
    if 'crypto_hash' not in existing_columns:
        op.add_column('users', sa.Column('crypto_hash', sa.String(64), nullable=True))
        op.create_index('ix_users_crypto_hash', 'users', ['crypto_hash'])
    
    if 'user_hash' not in existing_columns:
        op.add_column('users', sa.Column('user_hash', sa.String(64), nullable=True))
        op.create_index('ix_users_user_hash', 'users', ['user_hash'])
    
    # Rename hashed_password to password_hash if needed
    if 'hashed_password' in existing_columns and 'password_hash' not in existing_columns:
        op.alter_column('users', 'hashed_password', new_column_name='password_hash')


def downgrade() -> None:
    # Drop new tables
    op.drop_table('refresh_tokens')
    op.drop_table('org_memberships')
    op.drop_table('organizations')
    
    # Remove new columns from users (optional - be careful in production)
    # op.drop_column('users', 'user_hash')
    # op.drop_column('users', 'crypto_hash')
    # etc.
