"""Previous balance survives draft promotion and excludes the edited invoice."""
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
from models import db, User, Customer
service._defaults_seeded = True


class InvoicePreviousBalanceTest(unittest.TestCase):
    def setUp(self):
        self.ctx = service.app.app_context(); self.ctx.push()
        db.create_all()
        db.session.add(User(id=1, username='one', password_hash='x'))
        db.session.add(Customer(id=1, user_id=1, name='Customer', code='C1', opening_balance=100))
        db.session.commit()
        self.client = service.app.test_client()
        with self.client.session_transaction() as sess: sess['user_id'] = 1

    def tearDown(self):
        db.session.remove(); db.drop_all(); self.ctx.pop()

    def payload(self, **extra):
        return dict(customer_id=1, customer_name='Customer', lines=[
            dict(item_name='Manual item', qty=1, tp=50, discount_pct=0, tax_pct=0)
        ], **extra)

    def test_draft_customer_selection_and_edit_exclude_current_invoice(self):
        draft = self.client.post('/api/invoices', json=self.payload(is_auto_draft=True)).json
        # Another unpaid bill arrives before the draft is explicitly saved.
        prior = self.client.post('/api/invoices', json=self.payload(amount_paid=0))
        self.assertEqual(prior.status_code, 201, prior.json)
        self.assertEqual(prior.json['previous_balance'], 100)

        saved = self.client.put(f"/api/invoices/{draft['id']}", json=self.payload(amount_paid=0))
        self.assertEqual(saved.status_code, 200, saved.json)
        self.assertEqual(saved.json['previous_balance'], 150)
        fetched = self.client.get(f"/api/invoices/{draft['id']}").json
        self.assertEqual(fetched['edit_previous_balance'], 150)
        self.assertEqual(self.client.get('/api/customers').json[0]['outstanding'], 200)

        edited = self.client.put(f"/api/invoices/{draft['id']}", json=self.payload(amount_paid=10))
        self.assertEqual(edited.status_code, 200, edited.json)
        self.assertEqual(edited.json['previous_balance'], 150)


if __name__ == '__main__':
    unittest.main()
