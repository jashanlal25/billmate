import unittest
from datetime import date
from test_billed_item_search import service, db, User, Item, Invoice, InvoiceLine
from models import POSPurchase, Purchase, Supplier, Settings


def bill():
    return dict(pos_invoice_number='001',purchase_date='2026-10-01',supplier_code='5',
        supplier_name='Supplier',total_cost=180,cancelled=False,lines=[dict(
            pos_item_code='9',item_name='Medicine',qty=3,paid_qty=2,bonus_qty=1,pack_qty=10,
            tp=100,retail=120,disc_pct=10,tax=0,line_total=180)])

class POSPurchaseTest(unittest.TestCase):
    def setUp(self):
        self.ctx=service.app.app_context();self.ctx.push();db.create_all()
        db.session.add_all([User(id=1,username='one',password_hash='x'),User(id=2,username='two',password_hash='x')])
        db.session.add_all([Settings(user_id=uid,shop_name='Test',address='Street',phone='1',whatsapp='1') for uid in (1,2)])
        db.session.add(Item(id=1,user_id=1,is_global=False,code='POS-9',name='Medicine',tp=100,retail_price=120,qty=8))
        db.session.add(Supplier(id=1,user_id=1,name='Supplier',balance=500,opening_balance=500))
        inv=Invoice(id=1,user_id=1,invoice_number='S1',invoice_date=date(2026,10,2),status='posted',customer_name_snap='Customer')
        db.session.add(inv);db.session.flush()
        db.session.add(InvoiceLine(invoice_id=1,item_id=1,item_name='Medicine',qty=1,tp=100,line_net=100))
        db.session.commit();self.client=service.app.test_client()
        with self.client.session_transaction() as s:s['user_id']=1

    def tearDown(self):
        db.session.remove();db.drop_all();self.ctx.pop()

    def sync(self,bills=None):
        return self.client.post('/api/pos-backup/purchases',json={'bills':bills if bills is not None else [bill()]})

    def test_repeat_update_and_no_double_stock_or_payable(self):
        self.assertEqual(self.sync().json['created'],1)
        self.assertEqual(self.sync().json['unchanged'],1)
        self.assertEqual(POSPurchase.query.count(),1)
        updated=bill();updated['total_cost']=150;updated['lines'][0]['line_total']=150
        self.assertEqual(self.sync([updated]).json['updated'],1)
        self.assertEqual(db.session.get(Item,1).qty,8)
        self.assertEqual(db.session.get(Supplier,1).opening_balance,500)
        self.assertEqual(Purchase.query.count(),0)
        self.assertEqual(Item.query.count(),1)
        self.assertEqual(self.client.get('/api/purchase-history?source=pos').json['total'],1)

    def test_profit_uses_latest_cost_not_old_unlimited_fifo_stock(self):
        old=bill();old['pos_invoice_number']='old';old['purchase_date']='2026-09-01';old['total_cost']=3;old['lines'][0]['line_total']=3
        self.sync([old,bill()])
        r=self.client.get('/api/profit?start=2026-10-01&end=2026-10-31').json
        self.assertEqual(r['summary']['cost'],60)
        self.assertEqual(r['summary']['profit'],40)
        self.assertEqual(r['summary']['pos_cost_qty'],1)
        self.assertEqual(r['summary']['purchases'],180)

    def test_bill_adjustments_returns_and_cancellations(self):
        source=bill();source['total_cost']=183
        self.sync([source])
        r=self.client.get('/api/profit?start=2026-10-01&end=2026-10-31').json
        self.assertEqual(r['summary']['cost'],61)
        source['cancelled']=True;self.sync([source])
        self.assertEqual(self.client.get('/api/purchase-history').json['total'],0)
        r=self.client.get('/api/profit?start=2026-10-01&end=2026-10-31').json
        self.assertEqual(r['summary']['missing_qty'],1)
        returned=bill();returned['pos_invoice_number']='R1';returned['total_cost']=-60
        for field in ('qty','paid_qty','bonus_qty','line_total'):returned['lines'][0][field]*=-1
        self.assertEqual(self.sync([returned]).status_code,200)
        self.assertEqual(self.client.get('/api/purchase-history').json['total_cost'],-60)

    def test_account_isolation_detail_permissions_and_atomic_validation(self):
        self.sync();pid=POSPurchase.query.first().id
        self.assertEqual(self.client.get(f'/api/purchase-history/pos/{pid}').json['lines'][0]['bonus_qty'],1)
        with self.client.session_transaction() as s:s['user_id']=2
        self.assertEqual(self.client.get(f'/api/purchase-history/pos/{pid}').status_code,404)
        self.assertEqual(self.client.get('/api/purchase-history').json['total'],0)
        with self.client.session_transaction() as s:s['user_id']=1
        bad=bill();bad['pos_invoice_number']='bad';bad['lines'][0]['qty']=0
        good=bill();good['pos_invoice_number']='next'
        self.assertEqual(self.sync([good,bad]).status_code,400)
        self.assertEqual(POSPurchase.query.count(),1)
        user=db.session.get(User,1);user.perm_purchases=False;db.session.commit()
        self.assertEqual(self.sync().status_code,403)
        with self.client.session_transaction() as s:s.clear();s['is_guest']=True
        self.assertEqual(self.sync().status_code,403)

    def test_backup_roundtrip_keeps_source_identity_and_older_backups_valid(self):
        self.sync()
        with service.app.test_request_context('/'):
            backup=service._backup_payload(1)
        self.assertEqual(len(backup['data']['pos_purchase_history']),1)
        old=dict(backup,data=dict(backup['data']))
        old['data'].pop('pos_purchase_history')
        self.assertIsNone(service._validate_backup(old))
        from pos_purchase_history import restore_history
        self.assertEqual(restore_history(2,backup['data']['pos_purchase_history']),1)
        self.assertEqual(restore_history(2,backup['data']['pos_purchase_history']),0)
        db.session.commit()
        self.assertEqual(POSPurchase.query.filter_by(user_id=2).count(),1)

    def test_schema_compatibility_and_lazy_creation(self):
        POSPurchase.__table__.drop(db.engine)
        self.assertEqual(self.client.get('/api/purchase-history').json['total'],0)
        self.assertEqual(self.sync().status_code,200)
        db.session.remove();db.session.execute(db.text('DROP INDEX ix_purchases_source_invoice_id'))
        for column in ('source_invoice_id','source_invoice_number','source_invoice_vendor'):
            db.session.execute(db.text('ALTER TABLE purchases DROP COLUMN '+column))
        db.session.commit()
        self.assertEqual(self.client.get('/api/purchase-history').status_code,200)
        self.assertEqual(self.client.get('/api/profit').status_code,200)

if __name__=='__main__':unittest.main()
