"""Read only the bill fields needed by reports, including older databases.

Some deployed databases predate the optional purchase-to-invoice link migration.
Use an explicit projection so an unmigrated optional column cannot break reports.
No schema or bill data is changed by this reader.
"""
from types import SimpleNamespace
import sqlalchemy as sa
from models import db, Invoice, InvoiceLine, Purchase, PurchaseLine


def read_profit_bills(user_id, end):
    purchase_columns = {column['name'] for column in sa.inspect(db.engine).get_columns('purchases')}
    has_links = 'source_invoice_id' in purchase_columns
    source = Purchase.source_invoice_id if has_links else sa.cast(sa.null(), sa.Integer)
    valid_sources = sa.select(Invoice.id).where(
        Invoice.user_id == user_id, Invoice.status.in_(('posted', 'finalised')),
        Invoice.invoice_date <= end)
    purchase_scope = sa.and_(Purchase.user_id == user_id, sa.or_(
        Purchase.purchase_date <= end, source.in_(valid_sources)))
    linked_sources = sa.select(source).where(
        Purchase.user_id == user_id, Purchase.purchase_date <= end,
        source.isnot(None)).select_from(Purchase)
    invoice_scope = sa.and_(Invoice.user_id == user_id,
        Invoice.status.in_(('posted', 'finalised')), sa.or_(
            Invoice.invoice_date <= end, Invoice.id.in_(linked_sources)))

    def headers(statement):
        return {row['id']: SimpleNamespace(**row, lines=[])
                for row in db.session.execute(statement).mappings()}

    invoices = headers(sa.select(
        Invoice.id, Invoice.invoice_date, Invoice.status, Invoice.customer_id,
        Invoice.customer_name_snap, Invoice.discount_amount
    ).where(invoice_scope).order_by(Invoice.invoice_date, Invoice.id))
    purchases = headers(sa.select(
        Purchase.id, Purchase.purchase_date, Purchase.total_cost,
        source.label('source_invoice_id')
    ).where(purchase_scope).order_by(Purchase.purchase_date, Purchase.id))

    invoice_ids = sa.select(Invoice.id).where(invoice_scope)
    purchase_ids = sa.select(Purchase.id).where(purchase_scope)
    for row in db.session.execute(sa.select(
        InvoiceLine.invoice_id, InvoiceLine.item_id, InvoiceLine.item_name,
        InvoiceLine.qty, InvoiceLine.line_net, InvoiceLine.tax_pct
    ).where(InvoiceLine.invoice_id.in_(invoice_ids)).order_by(InvoiceLine.id)).mappings():
        invoices[row['invoice_id']].lines.append(SimpleNamespace(**row))
    for row in db.session.execute(sa.select(
        PurchaseLine.purchase_id, PurchaseLine.item_id, PurchaseLine.item_name,
        PurchaseLine.qty, PurchaseLine.line_total
    ).where(PurchaseLine.purchase_id.in_(purchase_ids)).order_by(PurchaseLine.id)).mappings():
        purchases[row['purchase_id']].lines.append(SimpleNamespace(**row))
    return list(purchases.values()), list(invoices.values()), has_links
