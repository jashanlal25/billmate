"""add previous_balance to invoices

Revision ID: b4e2f3a1c890
Revises: a3c1d2e4f567
Create Date: 2026-03-25 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b4e2f3a1c890'
down_revision = 'a3c1d2e4f567'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('invoices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('previous_balance', sa.Numeric(precision=10, scale=2), nullable=True, server_default='0'))


def downgrade():
    with op.batch_alter_table('invoices', schema=None) as batch_op:
        batch_op.drop_column('previous_balance')
