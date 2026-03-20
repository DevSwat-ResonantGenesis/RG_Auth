"""Add session metadata and trusted_devices table

Revision ID: 008_add_session_trusted_devices
Revises: 007_add_audit_logs
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '008_add_session_trusted_devices'
down_revision = '007_add_audit_logs'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Add session metadata columns to refresh_tokens
    existing_columns = [col['name'] for col in inspector.get_columns('refresh_tokens')]
    
    if 'device_name' not in existing_columns:
        op.add_column('refresh_tokens', sa.Column('device_name', sa.String(255), nullable=True))
    
    if 'device_type' not in existing_columns:
        op.add_column('refresh_tokens', sa.Column('device_type', sa.String(50), nullable=True))
    
    if 'location' not in existing_columns:
        op.add_column('refresh_tokens', sa.Column('location', sa.String(255), nullable=True))
    
    if 'last_active_at' not in existing_columns:
        op.add_column('refresh_tokens', sa.Column('last_active_at', sa.DateTime(timezone=True), nullable=True))
    
    if 'is_current' not in existing_columns:
        op.add_column('refresh_tokens', sa.Column('is_current', sa.Boolean(), nullable=False, server_default='false'))
    
    # Create trusted_devices table
    if 'trusted_devices' not in inspector.get_table_names():
        op.create_table(
            'trusted_devices',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
            sa.Column('device_fingerprint', sa.String(128), nullable=False, index=True),
            sa.Column('device_name', sa.String(255), nullable=True),
            sa.Column('device_type', sa.String(50), nullable=True),
            sa.Column('user_agent', sa.String(500), nullable=True),
            sa.Column('ip_address', sa.String(64), nullable=True),
            sa.Column('trusted_until', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
            sa.UniqueConstraint('user_id', 'device_fingerprint', name='uq_trusted_devices_user_device'),
        )


def downgrade() -> None:
    op.drop_table('trusted_devices')
    op.drop_column('refresh_tokens', 'is_current')
    op.drop_column('refresh_tokens', 'last_active_at')
    op.drop_column('refresh_tokens', 'location')
    op.drop_column('refresh_tokens', 'device_type')
    op.drop_column('refresh_tokens', 'device_name')
