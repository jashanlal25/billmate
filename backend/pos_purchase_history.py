"""Account-scoped, idempotent purchase history from the existing POS ZIP sync."""
import hashlib
import json
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from types import SimpleNamespace
import sqlalchemy as sa
from flask import Blueprint, jsonify, request, session
from models import db, User, Purchase, PurchaseLine, POSPurchase, Item

bp = Blueprint('pos_purchase_history', __name__)


@bp.after_request
def private_response(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


def table_exists():
    return sa.inspect(db.engine).has_table(POSPurchase.__tablename__)


def decimal(value):
    try:
        value = Decimal(str(value))
        if not value.is_finite() or abs(value) > Decimal('99999999999'):
            raise ValueError('Invalid purchase amount or quantity')
        return value
    except (InvalidOperation, TypeError):
        raise ValueError('Invalid purchase amount or quantity')


def normalize(bill):
    if not isinstance(bill, dict):
        raise ValueError('Invalid purchase invoice')
    when = date.fromisoformat(str(bill.get('purchase_date', '')))
    invoice = str(bill.get('pos_invoice_number') or '').strip()
    supplier = str(bill.get('supplier_code') or '').strip()
    name = str(bill.get('supplier_name') or '').strip()
    if not re.fullmatch(r'[^\x00-\x1f<>]{1,40}',invoice) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',supplier) or not name or len(name)>150:
        raise ValueError('Missing or invalid POS purchase invoice / supplier')
    cancelled = bill.get('cancelled', False)
    if not isinstance(cancelled, bool):
        raise ValueError('Invalid purchase cancellation flag')
    total = decimal(bill.get('total_cost', 0)).quantize(Decimal('.01'))
    raw_lines = bill.get('lines', [])
    if not isinstance(raw_lines, list) or len(raw_lines)>1500:
        raise ValueError('Invalid purchase line list')
    lines = []
    for row in ([] if cancelled else raw_lines):
        if not isinstance(row, dict):
            raise ValueError('Invalid purchase line')
        code = str(row.get('pos_item_code') or '').strip()
        item_name = str(row.get('item_name') or '').strip()
        if not code or len(code)>40 or not item_name or len(item_name)>200:
            raise ValueError('Missing purchase item identity')
        line = dict(pos_item_code=code, item_name=item_name, unresolved=bool(row.get('unresolved')),
                    batch=str(row.get('batch') or '')[:100], expiry=str(row.get('expiry') or '')[:10], item_id=None)
        for field in ('qty', 'paid_qty', 'bonus_qty', 'pack_qty', 'tp', 'retail', 'disc_pct', 'tax', 'line_total'):
            line[field] = float(decimal(row.get(field, 0)))
        if line['qty'] == 0 or line['pack_qty']<=0 or not -100<=line['disc_pct']<=100:
            raise ValueError('Invalid purchase quantity, packing or discount')
        if abs(decimal(line['qty'])-decimal(line['paid_qty'])-decimal(line['bonus_qty']))>Decimal('.000001'):
            raise ValueError('Purchase quantity must include paid and bonus quantities')
        if line['qty']*line['line_total']<0:
            raise ValueError('Purchase/return quantity and amount have inconsistent signs')
        lines.append(line)
    identity = json.dumps([when.isoformat(),supplier,invoice], separators=(',', ':'))
    source_key = hashlib.sha256(identity.encode()).hexdigest()
    content = dict(invoice_number=invoice,purchase_date=when.isoformat(),supplier_code=supplier,
                   supplier_name=name,total_cost=str(total),cancelled=cancelled,details=lines)
    digest = hashlib.sha256(json.dumps(content,sort_keys=True,separators=(',', ':')).encode()).hexdigest()
    return dict(content,source_key=source_key,digest=digest)


@bp.route('/api/pos-backup/purchases', methods=['POST'])
def import_purchases():
    uid = session.get('user_id')
    user = db.session.get(User,uid) if uid and not session.get('is_guest') else None
    if not user:
        return jsonify(error='Registered account required'),403
    if not user.perm_purchases:
        return jsonify(error='Purchase access is locked',locked=True),403
    body = request.get_json(silent=True) or {}
    bills = body.get('bills')
    if not isinstance(bills,list) or not bills or len(bills)>100:
        return jsonify(error='Send 1–100 purchase bills at a time'),400
    try:
        normalized = [normalize(bill) for bill in bills]
        if sum(len(b['details']) for b in normalized)>1500:
            return jsonify(error='Purchase batch contains too many lines'),413
        keys = [b['source_key'] for b in normalized]
        if len(set(keys)) != len(keys):
            raise ValueError('Duplicate invoice identities within purchase batch')
    except (ValueError,TypeError,AttributeError) as exc:
        return jsonify(error=str(exc)),400
    # Add only the new history table on an explicit sync action. Legacy purchase
    # tables and their rows are left intact; read routes never migrate schemas.
    POSPurchase.__table__.create(bind=db.engine, checkfirst=True)
    try:
        existing = {p.source_key:p for p in POSPurchase.query.filter(
            POSPurchase.user_id==uid,POSPurchase.source_key.in_(keys)).all()}
        stats = dict(created=0,updated=0,unchanged=0,cancelled=0)
        for bill in normalized:
            obj=existing.get(bill['source_key'])
            if obj and obj.digest==bill['digest']:
                stats['unchanged']+=1
                continue
            if obj:
                stats['updated']+=1
            else:
                obj=POSPurchase(user_id=uid,source_key=bill['source_key'])
                db.session.add(obj);stats['created']+=1
            for field in ('invoice_number','supplier_code','supplier_name','total_cost','cancelled','details','digest'):
                setattr(obj,field,bill[field])
            obj.purchase_date=date.fromisoformat(bill['purchase_date'])
            if obj.cancelled:stats['cancelled']+=1
        db.session.commit()
        return jsonify(success=True,**stats)
    except sa.exc.IntegrityError:
        db.session.rollback()
        return jsonify(error='Another purchase sync is running. Retry this batch.'),409


def manual_history(user_id):
    """Read old purchase schemas without loading absent optional link columns."""
    columns = {c['name'] for c in sa.inspect(db.engine).get_columns('purchases')}
    fields = [Purchase.id,Purchase.purchase_number,Purchase.purchase_date,
              Purchase.supplier_id,Purchase.supplier_name,Purchase.total_cost]
    for name in ('source_invoice_id','source_invoice_number','source_invoice_vendor'):
        if name in columns:fields.append(getattr(Purchase,name))
    return sa.select(*fields).where(Purchase.user_id==user_id)


@bp.route('/api/purchase-history')
def history():
    uid=session.get('user_id')
    if not uid or session.get('is_guest'):
        return jsonify(error='Registered account required'),403
    try:
        offset=max(int(request.args.get('offset',0)),0)
        limit=min(max(int(request.args.get('limit',30)),1),100)
        start=date.fromisoformat(request.args['start']) if request.args.get('start') else None
        end=date.fromisoformat(request.args['end']) if request.args.get('end') else None
    except ValueError:
        return jsonify(error='Invalid purchase history filters'),400
    query=request.args.get('q','').strip().casefold()[:200]
    source=request.args.get('source','all')
    # Header-only reads keep large historical backups off the mobile heap.
    rows=[]
    if source in ('all','manual'):
        statement=manual_history(uid)
        if start:statement=statement.where(Purchase.purchase_date>=start)
        if end:statement=statement.where(Purchase.purchase_date<=end)
        if query:statement=statement.where(sa.or_(sa.func.lower(Purchase.supplier_name).contains(query,autoescape=True),sa.func.lower(Purchase.purchase_number).contains(query,autoescape=True)))
        for row in db.session.execute(statement).mappings():
            item=dict(row);item['purchase_date']=item['purchase_date'].isoformat();item['total_cost']=float(item['total_cost'] or 0)
            rows.append(dict(item,source='manual',read_only=False,lines=[]))
    if source in ('all','pos') and table_exists():
        statement=sa.select(POSPurchase.id,POSPurchase.invoice_number.label('purchase_number'),
            POSPurchase.purchase_date,POSPurchase.supplier_name,POSPurchase.total_cost).where(
                POSPurchase.user_id==uid,POSPurchase.cancelled==False)
        if start:statement=statement.where(POSPurchase.purchase_date>=start)
        if end:statement=statement.where(POSPurchase.purchase_date<=end)
        if query:statement=statement.where(sa.or_(sa.func.lower(POSPurchase.supplier_name).contains(query,autoescape=True),sa.func.lower(POSPurchase.invoice_number).contains(query,autoescape=True)))
        for row in db.session.execute(statement).mappings():
            item=dict(row);item['purchase_date']=item['purchase_date'].isoformat();item['total_cost']=float(item['total_cost'])
            rows.append(dict(item,source='pos',read_only=True,lines=[]))
    rows.sort(key=lambda row:(row['purchase_date'],row['id']),reverse=True)
    return jsonify(items=rows[offset:offset+limit],total=len(rows),offset=offset,limit=limit,
                   total_cost=round(sum(r['total_cost'] for r in rows),2))


@bp.route('/api/purchase-history/<source>/<int:pid>')
def detail(source,pid):
    uid=session.get('user_id')
    if not uid or session.get('is_guest'):
        return jsonify(error='Registered account required'),403
    if source=='pos' and table_exists():
        obj=POSPurchase.query.filter_by(user_id=uid,id=pid).first()
        if obj:return jsonify(obj.to_dict())
    elif source=='manual':
        row=db.session.execute(manual_history(uid).where(Purchase.id==pid)).mappings().first()
        if row:
            result=dict(row);result['purchase_date']=result['purchase_date'].isoformat();result['total_cost']=float(result['total_cost'] or 0)
            lines=db.session.execute(sa.select(PurchaseLine.__table__).where(PurchaseLine.purchase_id==pid).order_by(PurchaseLine.id)).mappings()
            result['lines']=[{k:float(v) if isinstance(v,Decimal) else v for k,v in line.items()} for line in lines]
            return jsonify(dict(result,source='manual',read_only=False))
    return jsonify(error='Purchase not found'),404


def profit_purchases(user_id,end):
    if not table_exists():return []
    # Match only exact POS codes or an unambiguous normalized item name. Never
    # create thousands of catalogue items merely to keep historical bills.
    items=Item.query.filter_by(user_id=user_id,is_global=False).all()
    by_code={item.code.removeprefix('POS-'):item.id for item in items if item.code.startswith('POS-')}
    by_name={}
    namekey=lambda name:' '.join(name.casefold().split())
    for item in items:by_name.setdefault(namekey(item.name),set()).add(item.id)
    result=[]
    for bill in POSPurchase.query.filter(POSPurchase.user_id==user_id,
            POSPurchase.cancelled==False,POSPurchase.purchase_date<=end).order_by(POSPurchase.purchase_date,POSPurchase.id):
        raw=bill.details or []
        net=sum((decimal(l['line_total']) for l in raw),Decimal(0))
        # Preserve signed bill-level rounding / discount by distributing its
        # adjustment proportionally; keep raw line NET for history display.
        factor=decimal(bill.total_cost)/net if net else Decimal(1)
        if factor < 0:
            continue
        lines=[]
        for line in raw:
            if line.get('unresolved'):continue
            ids=by_name.get(namekey(line['item_name']),set())
            item_id=by_code.get(line['pos_item_code']) or (next(iter(ids)) if len(ids)==1 else None)
            lines.append(SimpleNamespace(item_id=item_id,item_name=line['item_name'],qty=line['qty'],line_total=decimal(line['line_total'])*factor))
        result.append(SimpleNamespace(id=bill.id,purchase_date=bill.purchase_date,total_cost=bill.total_cost,
            source_invoice_id=None,pos_history=True,lines=lines))
    return result


def restore_history(user_id, rows):
    """Restore the optional backup section without adding stock or balances."""
    normalized = [normalize(dict(pos_invoice_number=row['invoice_number'],
        purchase_date=row['purchase_date'],supplier_code=row['supplier_code'],
        supplier_name=row['supplier_name'],total_cost=row['total_cost'],
        cancelled=row.get('cancelled',False),lines=row['details'])) for row in rows]
    existing = {p.source_key for p in POSPurchase.query.filter_by(user_id=user_id)}
    count=0
    for values in normalized:
        if values['source_key'] in existing:continue
        values['purchase_date']=date.fromisoformat(values['purchase_date'])
        db.session.add(POSPurchase(user_id=user_id,**values))
        existing.add(values['source_key']);count+=1
    return count
