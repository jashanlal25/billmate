"""Exercise the real Flask endpoint and account-scoped saved bills."""
import unittest
from datetime import date
from test_billed_item_search import service, db, User, Invoice, InvoiceLine
from models import Settings, Purchase, PurchaseLine

class ProfitAPITest(unittest.TestCase):
    def setUp(self):
        self.ctx=service.app.app_context(); self.ctx.push()
        db.create_all()
        for uid in (1,2):
            db.session.add(User(id=uid,username=f'user{uid}',password_hash='x'))
            db.session.add(Settings(user_id=uid,shop_name='Test shop',address='Street',phone='123',whatsapp='123'))
            p=Purchase(id=uid,user_id=uid,purchase_number=f'P{uid}',purchase_date=date(2026,10,1),total_cost=80)
            i=Invoice(id=uid,user_id=uid,invoice_number=f'I{uid}',invoice_date=date(2026,10,2),status='posted',customer_name_snap=f'Customer {uid}')
            db.session.add_all([p,i]);db.session.flush()
            db.session.add(PurchaseLine(purchase_id=p.id,item_name='Medicine',qty=1,tp=80,line_total=80))
            db.session.add(InvoiceLine(invoice_id=i.id,item_name='Medicine',qty=1,tp=150,line_net=150))
        db.session.commit()
        self.client=service.app.test_client()
        with self.client.session_transaction() as s:s['user_id']=1

    def tearDown(self):
        db.session.remove();db.drop_all();self.ctx.pop()

    def get_report(self, query=''):
        return self.client.get('/api/profit?start=2026-10-01&end=2026-10-31'+query,headers={'Content-Type':'application/json'})

    def test_account_isolation_and_render(self):
        response=self.get_report()
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        self.assertEqual(response.json['summary']['profit'],70)
        self.assertEqual([r['label'] for r in response.json['rows']],['Customer 1'])
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.assertEqual(self.client.get('/profit').status_code,200)
        self.assertIn(b'/static/js/profit.js',self.client.get('/profit').data)

    def test_validation_and_access(self):
        self.assertEqual(self.get_report('&group_by=wrong').status_code,400)
        self.assertEqual(self.client.get('/api/profit?start=2026-10-40',headers={'Content-Type':'application/json'}).status_code,400)
        self.assertEqual(self.client.get('/api/profit?start=2026-11-01&end=2026-10-01',headers={'Content-Type':'application/json'}).status_code,400)
        with self.client.session_transaction() as s:s.clear()
        self.assertEqual(self.get_report().status_code,401)
        with self.client.session_transaction() as s:s['is_guest']=True
        self.assertEqual(self.get_report().status_code,403)

    def test_purchase_edit_delete_recalculates_and_groups(self):
        p=db.session.get(Purchase,1)
        p.lines[0].line_total=100;p.total_cost=100;db.session.commit()
        self.assertEqual(self.get_report().json['summary']['profit'],50)
        for group in ('item','day','month'):
            self.assertEqual(self.get_report('&group_by='+group).json['summary']['profit'],50)
        db.session.delete(p);db.session.commit()
        report=self.get_report().json
        self.assertFalse(report['summary']['complete'])
        self.assertEqual(report['summary']['missing_qty'],1)
        self.assertEqual(report['summary']['profit'],0)

if __name__=='__main__':unittest.main()
