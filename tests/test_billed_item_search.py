"""Previously billed names are searchable without treating snapshots as stock."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from flask_sqlalchemy import SQLAlchemy

os.environ['DATABASE_URL'] = 'sqlite://'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
_init = SQLAlchemy.init_app
def sqlite_init(self, app):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    _init(self, app)
with patch.object(SQLAlchemy, 'init_app', sqlite_init):
    import app as service
from models import db, User, Invoice, InvoiceLine
service._defaults_seeded = True


class BilledItemSearchTest(unittest.TestCase):
    def setUp(self):
        self.ctx = service.app.app_context(); self.ctx.push()
        db.create_all()
        db.session.add_all([User(id=1, username='one', password_hash='x'),
                            User(id=2, username='two', password_hash='x')])
        db.session.commit()
        self.client = service.app.test_client()
        with self.client.session_transaction() as s: s['user_id'] = 1

    def tearDown(self):
        db.session.remove(); db.drop_all(); self.ctx.pop()

    def bill(self, uid, number, name, status='posted', tp=300):
        inv = Invoice(user_id=uid, invoice_number=number, status=status)
        db.session.add(inv); db.session.flush()
        db.session.add(InvoiceLine(invoice_id=inv.id, item_name=name,
            item_code='F20', qty=2, tp=tp, discount_pct=11, tax_pct=4,
            vendor='OLD VENDOR', line_net=tp*2*.89))
        db.session.commit()

    def test_previous_bill_is_account_scoped_deduplicated_and_not_stock(self):
        self.bill(1, 'SSD-0001', 'FAMOSPIN 20', tp=200)
        self.bill(1, 'SSD-0002', 'FAMOSPIN 20', tp=350)
        self.bill(1, 'DRAFT-10', 'FAMOSPIN AUTOSAVE', status='draft')
        self.bill(1, 'SSD-0003', 'FAMOSPIN CANCELLED', status='cancelled')
        self.bill(2, 'OTHER-0001', 'FAMOSPIN PRIVATE')
        r = self.client.get('/api/items/history?q=famospin')
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(len(r.json), 1)
        row = r.json[0]
        self.assertEqual((row['name'], row['previous_invoice'], row['tp'],
                          row['discount_pct'], row['tax_pct']),
                         ('FAMOSPIN 20', 'SSD-0002', 350, 11, 4))
        self.assertIsNone(row['id'])
        self.assertEqual(row['qty'], 0)
        self.assertTrue(row['historical'])
        with self.client.session_transaction() as s: s.clear()
        self.assertNotEqual(self.client.get('/api/items/history?q=famospin').status_code, 200)


if __name__ == '__main__':
    unittest.main()
