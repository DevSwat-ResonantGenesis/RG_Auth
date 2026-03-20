"""Add audit_logs table

Revision ID: 007_add_audit_logs
Revises: 006_add_email_verification
Create Date: 2024-12-24

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '007_add_audit_logs'
down_revision = '006_add_email_verification'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Check if table already exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'audit_logs' not in inspector.get_table_names():
        op.create_table(
            'audit_logs',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('event_type', sa.String(50), nullable=False, index=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
            sa.Column('org_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
            sa.Column('ip_address', sa.String(45), nullable=True),
            sa.Column('user_agent', sa.String(500), nullable=True),
            sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=True),
            sa.Column('success', sa.String(10), nullable=False, server_default='true'),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        )
        
        # Create indexes
        op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_audit_logs_created_at', table_name='audit_logs')
    op.drop_table('audit_logs')
