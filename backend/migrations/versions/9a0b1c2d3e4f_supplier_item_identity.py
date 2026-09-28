"""Preserve supplier item identity and order snapshots."""
from alembic import op
import sqlalchemy as sa
revision = '9a0b1c2d3e4f'
down_revision = '5d7e8f9a0b1c'
branch_labels = None
depends_on = None

def upgrade():
    for table in ('items', 'invoice_lines'):
        existing = {c['name'] for c in sa.inspect(op.get_bind()).get_columns(table)}
        for name, size in (('vendor_code', 100), ('vendor_name', 300), ('vendor_list_no', 100)):
            if name not in existing:
                op.add_column(table, sa.Column(name, sa.String(size), nullable=True))

def downgrade():
    for table in ('items', 'invoice_lines'):
        for name in ('vendor_code', 'vendor_name', 'vendor_list_no'):
            op.drop_column(table, name)
