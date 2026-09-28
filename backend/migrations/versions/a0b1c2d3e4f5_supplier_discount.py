"""Keep supplier list discounts independent of customer billing discounts."""
from alembic import op
import sqlalchemy as sa
from supplier_discount import backfill_supplier_discounts
revision = 'a0b1c2d3e4f5'
down_revision = '9a0b1c2d3e4f'
branch_labels = None
depends_on = None

def upgrade():
    for table in ('items', 'invoice_lines'):
        if 'vendor_discount_pct' not in {c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)}:
            op.add_column(table, sa.Column('vendor_discount_pct', sa.Numeric(5,2), nullable=True))
    backfill_supplier_discounts(op.get_bind())

def downgrade():
    for table in ('items', 'invoice_lines'):
        op.drop_column(table, 'vendor_discount_pct')
