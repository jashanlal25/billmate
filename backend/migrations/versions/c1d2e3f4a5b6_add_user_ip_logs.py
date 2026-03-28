"""add user_ip_logs table

Revision ID: c1d2e3f4a5b6
Revises: e0e9ecd7170e
Create Date: 2026-03-28 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'c1d2e3f4a5b6'
down_revision = '6f94a5041bd3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user_ip_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=80), nullable=False),
        sa.Column('ip_address', sa.String(length=50), nullable=False),
        sa.Column('log_date', sa.Date(), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('request_count', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'ip_address', 'log_date', name='uq_user_ip_date'),
    )
    with op.batch_alter_table('user_ip_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_ip_logs_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_user_ip_logs_log_date'), ['log_date'], unique=False)


def downgrade():
    with op.batch_alter_table('user_ip_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_ip_logs_log_date'))
        batch_op.drop_index(batch_op.f('ix_user_ip_logs_user_id'))
    op.drop_table('user_ip_logs')
