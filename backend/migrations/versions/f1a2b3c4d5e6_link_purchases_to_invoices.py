"""link purchases to source invoices

Revision ID: f1a2b3c4d5e6
Revises: e3f4a5b6c7d8
"""
from alembic import op
import sqlalchemy as sa

revision = 'f1a2b3c4d5e6'
down_revision = 'e3f4a5b6c7d8'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('purchases', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_invoice_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('source_invoice_number', sa.String(length=30), nullable=True))
        batch_op.add_column(sa.Column('source_invoice_vendor', sa.String(length=150), nullable=True))
        batch_op.create_index('ix_purchases_source_invoice_id', ['source_invoice_id'], unique=False)

def downgrade():
    with op.batch_alter_table('purchases', schema=None) as batch_op:
        batch_op.drop_index('ix_purchases_source_invoice_id')
        batch_op.drop_column('source_invoice_vendor')
        batch_op.drop_column('source_invoice_number')
        batch_op.drop_column('source_invoice_id')
