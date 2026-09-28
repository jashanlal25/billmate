"""Backfill supplier rates only from imported catalog data, never sale discounts."""
from sqlalchemy import text

def backfill_supplier_discounts(connection):
    connection.execute(text("""
        UPDATE items SET vendor_discount_pct = discount_pct
        WHERE vendor_discount_pct IS NULL
          AND COALESCE(vendor_code, '') <> '' AND COALESCE(vendor_list_no, '') <> ''
    """))
    connection.execute(text("""
        UPDATE invoice_lines SET vendor_discount_pct = (
            SELECT items.vendor_discount_pct FROM items
            WHERE items.id = invoice_lines.item_id
              AND items.vendor = invoice_lines.vendor
              AND items.vendor_code = invoice_lines.vendor_code
              AND items.vendor_list_no = invoice_lines.vendor_list_no
        ) WHERE vendor_discount_pct IS NULL
    """))

def ensure_supplier_discounts(connection):
    for table in ('items', 'invoice_lines'):
        connection.execute(text(f'ALTER TABLE {table} ADD COLUMN IF NOT EXISTS vendor_discount_pct NUMERIC(5,2)'))
    backfill_supplier_discounts(connection)
