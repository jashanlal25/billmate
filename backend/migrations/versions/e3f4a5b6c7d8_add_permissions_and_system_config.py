"""add user permissions and system_config table

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-03-29 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'e3f4a5b6c7d8'
down_revision = 'd2e3f4a5b6c7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('system_config',
        sa.Column('key',   sa.String(length=80),  nullable=False),
        sa.Column('value', sa.String(length=200), nullable=False),
        sa.PrimaryKeyConstraint('key')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('perm_bill',      sa.Boolean(), nullable=False, server_default='true'))
        batch_op.add_column(sa.Column('perm_items',     sa.Boolean(), nullable=False, server_default='true'))
        batch_op.add_column(sa.Column('perm_customers', sa.Boolean(), nullable=False, server_default='true'))
        batch_op.add_column(sa.Column('perm_suppliers', sa.Boolean(), nullable=False, server_default='true'))
        batch_op.add_column(sa.Column('perm_purchases', sa.Boolean(), nullable=False, server_default='true'))


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('perm_purchases')
        batch_op.drop_column('perm_suppliers')
        batch_op.drop_column('perm_customers')
        batch_op.drop_column('perm_items')
        batch_op.drop_column('perm_bill')
    op.drop_table('system_config')
