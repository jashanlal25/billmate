"""add recovery_email reset_code fields to users

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-03-28 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd2e3f4a5b6c7'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recovery_email', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('reset_code_hash', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('reset_code_expiry', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('reset_code_expiry')
        batch_op.drop_column('reset_code_hash')
        batch_op.drop_column('recovery_email')
