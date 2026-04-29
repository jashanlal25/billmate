"""add rate_source to items

Revision ID: c4d5e6f7a890
Revises: 8cfdd34e8f1b
Create Date: 2026-04-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'c4d5e6f7a890'
down_revision = '8cfdd34e8f1b'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rate_source', sa.String(length=50), nullable=True))


def downgrade():
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('rate_source')
