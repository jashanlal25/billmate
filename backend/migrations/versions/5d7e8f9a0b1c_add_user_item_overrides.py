"""add user item overrides table

Revision ID: 5d7e8f9a0b1c
Revises: 247c0b06a3f2
Create Date: 2026-09-15

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d7e8f9a0b1c'
down_revision = '247c0b06a3f2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'user_item_overrides',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('item_id', sa.Integer(), nullable=False),
        sa.Column('tp', sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column('retail_price', sa.Numeric(precision=10, scale=2), nullable=True),
        sa.Column('tax_pct', sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column('bonus_text', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['item_id'], ['items.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'item_id', name='uq_user_item_override'),
    )
    with op.batch_alter_table('user_item_overrides', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_user_item_overrides_user_id'),
            ['user_id'],
            unique=False,
        )


def downgrade():
    with op.batch_alter_table('user_item_overrides', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_item_overrides_user_id'))
    op.drop_table('user_item_overrides')
