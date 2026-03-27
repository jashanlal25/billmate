"""add qty to items

Revision ID: a3c1d2e4f567
Revises: f678cb3ac489
Create Date: 2026-03-25 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a3c1d2e4f567'
down_revision = 'f678cb3ac489'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('qty', sa.Numeric(precision=10, scale=3), nullable=True, server_default='0'))


def downgrade():
    with op.batch_alter_table('items', schema=None) as batch_op:
        batch_op.drop_column('qty')
