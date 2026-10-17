"""Read-only profit reporting from saved bills. No catalog price guesses.

Costs use FIFO purchase lots. Invoice-linked purchases are reserved for their
source invoice (even if entered later); remaining ordinary stock uses dated FIFO.
Rebuilding all sales through the report end keeps filtered periods consistent.
Amounts include the fixed per-unit tax already included in BillMate bills.
"""
from collections import defaultdict, deque
from decimal import Decimal, ROUND_HALF_UP

ZERO = Decimal('0')

def number(value):
    return Decimal(str(value or 0))

def money(value):
    return float(value.quantize(Decimal('.01'), rounding=ROUND_HALF_UP))

def build_profit_report(purchases, invoices, start, end, group_by='customer', query=''):
    names = defaultdict(set)
    for bill in [*purchases, *invoices]:
        for line in bill.lines:
            if line.item_id:
                names[' '.join(line.item_name.casefold().split())].add(line.item_id)

    def item_key(line):
        name = ' '.join(line.item_name.casefold().split())
        ids = names[name]
        # A manual bill can match a subsequently created purchase item only
        # when its name identifies one item, never across ambiguous vendors.
        return ('id', line.item_id) if line.item_id else (
            ('id', next(iter(ids))) if len(ids) == 1 else ('name', name))

    stock = defaultdict(deque)
    linked = defaultdict(deque)
    demand = defaultdict(lambda: ZERO)
    for invoice in invoices:
        if invoice.status in ('posted', 'finalised'):
            for line in invoice.lines:
                demand[(invoice.id, item_key(line))] += max(number(line.qty), ZERO)
    events = []
    for purchase in purchases:
        for line in purchase.lines:
            qty = number(line.qty)
            if qty <= 0:
                continue
            key = item_key(line)
            unit_cost = number(line.line_total) / qty
            source_key = (purchase.source_invoice_id, key)
            reserved = min(qty, demand[source_key]) if purchase.source_invoice_id else ZERO
            if reserved:
                linked[source_key].append([reserved, unit_cost])
                demand[source_key] -= reserved
            # Surplus and purchases whose source bill was cancelled remain
            # available stock, starting on their purchase date.
            if qty > reserved and purchase.purchase_date <= end:
                events.append((purchase.purchase_date, 0, purchase.id,
                               (key, qty-reserved, unit_cost)))
    for invoice in invoices:
        if invoice.status in ('posted', 'finalised') and invoice.invoice_date <= end:
            events.append((invoice.invoice_date, 1, invoice.id, invoice))
    events.sort(key=lambda e: e[:3])
    groups = {}
    summary = dict(sales=ZERO, matched_sales=ZERO, cost=ZERO, profit=ZERO,
                   missing_qty=ZERO, qty=ZERO, purchases=sum(
                       (number(p.total_cost) for p in purchases if start <= p.purchase_date <= end), ZERO))
    for when, kind, _, bill in events:
        if kind == 0:
            key, qty, unit_cost = bill
            stock[key].append([qty, unit_cost])
            continue
        subtotal = sum((number(l.line_net) for l in bill.lines), ZERO)
        for line in bill.lines:
            qty = number(line.qty)
            if qty <= 0:
                continue
            remaining, cost = qty, ZERO
            for lots in (linked[(bill.id, item_key(line))], stock[item_key(line)]):
                while remaining > 0 and lots:
                    lot = lots[0]
                    used = min(remaining, lot[0])
                    cost += used * lot[1]
                    remaining -= used
                    lot[0] -= used
                    if lot[0] == 0:
                        lots.popleft()
            # Consume earlier sales even outside the selected reporting period.
            if not start <= when <= end:
                continue
            if group_by == 'item':
                key, label = item_key(line), line.item_name
            elif group_by == 'day':
                key = label = when.isoformat()
            elif group_by == 'month':
                key = label = when.strftime('%Y-%m')
            else:
                label = bill.customer_name_snap or 'Walk-in'
                key = ('customer', bill.customer_id) if bill.customer_id else ('walk-in', label.casefold())
            if query and query.casefold() not in label.casefold():
                continue
            net = number(line.line_net)
            discount = number(bill.discount_amount) * net / subtotal if subtotal else ZERO
            sales = net + qty * number(line.tax_pct) - discount
            matched_sales = sales * (qty - remaining) / qty
            values = dict(sales=sales, matched_sales=matched_sales, cost=cost,
                          profit=matched_sales-cost, missing_qty=remaining, qty=qty)
            if key not in groups:
                groups[key] = dict(label=label, **{k: ZERO for k in values})
            for field, value in values.items():
                groups[key][field] += value
                summary[field] += value

    def output(values):
        result = {k: (float(v.quantize(Decimal('.001'), rounding=ROUND_HALF_UP)) if k in ('qty', 'missing_qty') else money(v)) if isinstance(v, Decimal) else v for k, v in values.items()}
        result['complete'] = values['missing_qty'] == 0
        result['margin'] = money(values['profit'] / values['matched_sales'] * 100) if values['matched_sales'] else None
        return result

    rows = sorted(groups.values(), key=lambda row: row['label'].casefold())
    return dict(summary=output(summary), rows=[output(row) for row in rows],
                group_by=group_by, start=start.isoformat(), end=end.isoformat(),
                method='FIFO; invoice-linked purchases reserved for the source invoice',
                purchase_scope='All purchases in the date range; search filters the sales breakdown only')
