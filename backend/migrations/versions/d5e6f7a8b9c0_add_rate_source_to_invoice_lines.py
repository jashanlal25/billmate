"""add rate_source to invoice_lines

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a890
Create Date: 2026-04-30 00:01:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a890'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('invoice_lines', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rate_source', sa.String(length=50), nullable=True))


def downgrade():
    with op.batch_alter_table('invoice_lines', schema=None) as batch_op:
        batch_op.drop_column('rate_source')
