"""Add user_ssh_hosts table (opt-in SSH target for the sandboxed IDE terminal)

Revision ID: 012_add_user_ssh_hosts
Revises: 011_add_agent_verify_status
Create Date: 2026-07-10

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '012_add_user_ssh_hosts'
down_revision = '011_add_agent_verify_status'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if 'user_ssh_hosts' not in inspector.get_table_names():
        op.create_table(
            'user_ssh_hosts',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
            sa.Column('host', sa.String(255), nullable=False),
            sa.Column('port', sa.Integer(), nullable=False, server_default='22'),
            sa.Column('label', sa.String(255), nullable=True),
            sa.Column('public_key_fingerprint', sa.String(128), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        )
        # One registered host per user by design - see UserSshHost's docstring.
        op.create_index(
            'ix_user_ssh_hosts_user_id', 'user_ssh_hosts', ['user_id'], unique=True,
        )


def downgrade() -> None:
    op.drop_index('ix_user_ssh_hosts_user_id', table_name='user_ssh_hosts')
    op.drop_table('user_ssh_hosts')
