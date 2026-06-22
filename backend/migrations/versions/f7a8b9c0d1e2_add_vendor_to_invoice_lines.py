"""add vendor to invoice_lines

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-06-22 00:00:01.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'f7a8b9c0d1e2'
down_revision = 'e6f7a8b9c0d1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('invoice_lines', schema=None) as batch_op:
        batch_op.add_column(sa.Column('vendor', sa.String(length=50), nullable=True))


def downgrade():
    with op.batch_alter_table('invoice_lines', schema=None) as batch_op:
        batch_op.drop_column('vendor')
