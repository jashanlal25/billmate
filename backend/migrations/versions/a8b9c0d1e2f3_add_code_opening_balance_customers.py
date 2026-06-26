"""add code and opening_balance to customers

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-06-24 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a8b9c0d1e2f3'
down_revision = 'f7a8b9c0d1e2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('customers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('code', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('opening_balance', sa.Numeric(10, 2), nullable=True, server_default='0'))
        batch_op.create_index('ix_customers_code', ['code'])


def downgrade():
    with op.batch_alter_table('customers', schema=None) as batch_op:
        batch_op.drop_index('ix_customers_code')
        batch_op.drop_column('opening_balance')
        batch_op.drop_column('code')
