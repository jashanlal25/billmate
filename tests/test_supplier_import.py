"""Exercise the production import route against an isolated SQLite database."""
import ast
import io
import re
import sys
from pathlib import Path

import bs4
import pytest
from flask import Flask, request, session, jsonify

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from models import db, Item, User, Invoice, InvoiceLine, Purchase, PurchaseLine, Customer, Supplier

@pytest.fixture
def env():
    app = Flask(__name__)
    app.config.update(SECRET_KEY='test', SQLALCHEMY_DATABASE_URI='sqlite://')
    db.init_app(app)
    tree = ast.parse((ROOT / 'backend/app.py').read_text())
    route = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'import_items')
    route.decorator_list = []
    namespace = dict(request=request, session=session, jsonify=jsonify, re=re,
                     os=__import__('os'), Item=Item, User=User, db=db,
                     _get_bs4=lambda: bs4, _ensure_supplier=lambda *args: None)
    exec(compile(ast.Module(body=[route], type_ignores=[]), 'import_items', 'exec'), namespace)
    app.add_url_rule('/import', view_func=namespace['import_items'], methods=['POST'])
    with app.app_context():
        db.create_all()
        db.session.add_all([User(id=1, username='one', password_hash='x'), User(id=2, username='two', password_hash='x')])
        db.session.commit()
        client = app.test_client()
        with client.session_transaction() as s: s['user_id'] = 1
        yield client
        db.session.remove()
        db.drop_all()


def upload(client, content, vendor='DOSANI'):
    return client.post('/import', data={'vendor': vendor, 'file': (io.BytesIO(content.encode()), 'list.htm')})


def offer(codes, list_no='1', price=100):
    return '<html><body>List No: ' + list_no + '<table>' + ''.join(
        f'<tr class="item-row" data-tp="{price}" data-disc="10"><td>{code}</td><td>Item {code}</td><td></td><td></td><td></td><td></td><td></td></tr>'
        for code in codes) + '</table></body></html>'


def item(code, vendor='DOSANI', user_id=1, qty=0, active=True):
    obj = Item(user_id=user_id, code='local-' + code + '-' + vendor, name='Item ' + code,
               vendor=vendor, vendor_code=code, vendor_list_no='old', tp=100,
               retail_price=120, qty=qty, is_active=active, is_global=False)
    db.session.add(obj)
    db.session.commit()
    return obj


def test_real_lists_replace_and_repeat(env):
    files = ROOT.parent / 'upload'
    old = files / 'DOSANI MEDICOSE_24-09-2026_000049_C1_SHOWCASE-1.HTM'
    new = files / 'DOSANI MEDICOSE_30-09-2026_000054_C1.HTM'
    if not old.exists(): pytest.skip('User-provided fixture files unavailable')
    assert upload(env, old.read_text()).json['added'] == 459
    result = upload(env, new.read_text()).json
    assert (result['added'], result['updated'], result['archived']) == (136, 373, 86)
    assert Item.query.filter_by(is_active=True).count() == 509
    repeated = upload(env, new.read_text()).json
    assert (repeated['added'], repeated['updated'], repeated['archived']) == (0, 509, 0)
    assert Item.query.count() == 595


def test_history_scope_and_stock_are_preserved(env):
    current = item('0071', qty=8)
    missing = item('0099')
    stocked = item('0098', qty=3)
    other = item('0071', vendor='OTHER')
    own = item('0071', vendor='STOCK', qty=19)
    another_user = item('0071', user_id=2)
    customer = Customer(user_id=1, code='C1', name='Customer', opening_balance=250, balance=250)
    supplier = Supplier(user_id=1, code='S1', name='DOSANI', opening_balance=500, balance=500)
    db.session.add_all([customer, supplier]); db.session.flush()
    invoice = Invoice(user_id=1, invoice_number='INV-1', customer_id=customer.id, customer_name_snap='Customer')
    purchase = Purchase(user_id=1, purchase_number='PUR-1', supplier_id=supplier.id, supplier_name='DOSANI')
    db.session.add_all([invoice, purchase]); db.session.flush()
    line = InvoiceLine(invoice_id=invoice.id, item_id=missing.id, item_name='Original', qty=2, tp=70,
                       discount_pct=7, line_net=130.2, vendor_list_no='old')
    pl = PurchaseLine(purchase_id=purchase.id, item_id=current.id, item_name='Original', qty=8, tp=50, line_total=400)
    db.session.add_all([line, pl]);db.session.commit()
    before = (line.to_dict(), pl.to_dict(), customer.balance, supplier.balance)
    result = upload(env, offer(['0071'], 'new', 200)).json
    assert result['archived'] == 1 and result['stock_kept'] == 1
    assert current.qty == 8 and current.tp == 200 and current.vendor_list_no == 'new'
    assert not missing.is_active and stocked.is_active and stocked.qty == 3
    assert other.tp == 100 and own.qty == 19 and another_user.tp == 100
    assert before == (line.to_dict(), pl.to_dict(), customer.balance, supplier.balance)
    # Old invoice/purchase references still resolve after archiving.
    assert db.session.get(Item, line.item_id).id == missing.id


def test_duplicates_archived_without_relinking_history(env):
    first = item('0071')
    duplicate = Item(user_id=1, code='duplicate', name=first.name, vendor='DOSANI', vendor_code='0071', vendor_list_no='old2', tp=100, retail_price=120, qty=0, is_active=True)
    db.session.add(duplicate);db.session.commit()
    result = upload(env, offer(['0071'], 'next')).json
    assert result['added'] == 0 and result['archived'] == 1
    assert first.is_active and not duplicate.is_active
    assert db.session.get(Item, duplicate.id) is not None


def test_reactivate_returning_code_and_case_insensitive_supplier(env):
    old = item('0071', active=False)
    result = upload(env, offer(['0071']), 'dosani').json
    assert result['added'] == 0 and old.is_active and old.vendor_code == '0071'


def test_empty_or_broken_list_rolls_back(env):
    original = item('0071')
    assert upload(env, '<html>No items</html>').status_code == 500
    assert original.is_active and original.tp == 100
    broken = offer(['0071'], price=250).replace('</table>', '<tr class="item-row"><td>bad</td></tr></table>')
    assert upload(env, broken).status_code == 500
    db.session.refresh(original)
    assert original.is_active and original.tp == 100
