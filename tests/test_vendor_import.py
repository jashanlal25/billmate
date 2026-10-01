"""Supplier identity survives imports and invoice snapshots (isolated SQLite DB)."""
import os
import sys
import io
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
from models import db, User, Item, Settings, Supplier, UserItemDiscount, Purchase
service._defaults_seeded = True

class VendorImportTest(unittest.TestCase):
    def setUp(self):
        self.ctx = service.app.app_context(); self.ctx.push()
        db.create_all()
        db.session.add(User(id=1, username='test', password_hash='unused'))
        db.session.add(Settings(user_id=1, shop_name='SSD MEDICOS', address='test', phone='1', whatsapp='1'))
        db.session.commit()
        self.client = service.app.test_client()
        with self.client.session_transaction() as s: s['user_id']=1

    def tearDown(self):
        db.session.remove(); db.drop_all(); self.ctx.pop()

    def upload(self, vendor='A', code='0296', name='EXACT  NAME.', bonus='10+1', list_no='000052', admin=False):
        html=f'<div>List No : {list_no}</div><table><tr class="item"><td>{code}</td><td>{name}</td><td><input></td><td>13%</td><td>{bonus}</td><td>100</td><td>0</td></tr></table>'
        if admin:
            with self.client.session_transaction() as s: s['is_superadmin']=True
        r=self.client.post('/api/superadmin/items/import' if admin else '/api/items/import',data={'vendor':vendor,'file':(io.BytesIO(html.encode()),'offer.htm')})
        self.assertEqual(r.status_code,200,r.get_data(as_text=True))
        return r.json

    def test_identity_and_reimport(self):
        self.upload();self.upload(vendor='B');self.upload(code='+021');self.upload(list_no='000053')
        self.assertEqual(Item.query.count(),3)
        self.assertEqual(Item.query.filter_by(vendor='A',is_active=True).count(),1)
        self.assertEqual(self.upload(name='RENAMED.',bonus='')['updated'],1)
        self.assertEqual(Item.query.count(),3)
        i=Item.query.filter_by(vendor='A',vendor_code='0296',vendor_list_no='000052').one()
        self.assertEqual((i.to_dict()['code'],i.vendor_name,i.bonus_text),('0296','RENAMED.',''))

    def test_serial_numbers_are_not_supplier_item_codes(self):
        def send(names):
            rows=''.join(f'<tr class="item"><td>{idx}</td><td>{name}</td><td><input></td><td>10%</td><td></td><td>100</td></tr>' for idx,name in enumerate(names,1))
            return self.client.post('/api/items/import',data={'vendor':'A','file':(io.BytesIO(('<div>List No : 1</div><table>'+rows+'</table>').encode()),'offer.htm')})
        self.assertEqual(send(['MED A','MED B']).status_code,200)
        ids={i.name:i.id for i in Item.query.all()}
        self.assertEqual(send(['MED B','MED A']).json['added'],0)
        self.assertEqual({i.name:i.id for i in Item.query.all()},ids)
        self.assertTrue(all(i.vendor_code is None for i in Item.query.all()))

    def test_own_stock_import_keeps_message_details_without_creating_supplier(self):
        html = ('<title>Stock List</title><table><tr class="item">'
                '<td>1</td><td>58</td><td>ACNE SOFT SOAP</td><td>11%</td>'
                '<td>238</td><td>2</td><td>0</td><td>211.82</td><td>423.64</td>'
                '</tr></table>')
        db.session.add(Item(user_id=1, code='ITM0001', name='ACNE SOFT SOAP',
                            vendor='STOCK', vendor_code='58', tp=238, retail_price=280, qty=1))
        db.session.commit()
        for _ in range(2):
            r=self.client.post('/api/items/import',data={
                'vendor':'STOCK','file':(io.BytesIO(html.encode()),'STOCK (5).HTM')})
            self.assertEqual(r.status_code,200,r.get_data(as_text=True))
            self.assertTrue(r.json['own_stock'])
        self.assertEqual(Item.query.count(),1)
        item=Item.query.one()
        self.assertEqual((item.vendor,item.vendor_code,item.vendor_discount_pct,item.qty),
                         ('STOCK','58',11,2))
        self.assertEqual(Supplier.query.filter_by(user_id=1,name='STOCK').count(),0)

    def test_stock_export_footers_are_not_incomplete_items(self):
        row = ('<tr class="item"><td>1</td><td>58</td><td>SOAP</td>'
               '<td>11%</td><td>238</td><td>2</td><td>0</td><td>0</td><td>0</td></tr>')
        footer = ('<tr class="item"><td colspan="9"><b><hr></b></td></tr>'
                  '<tr class="item"><td colspan="8"><b>Total Items :</b></td><td>1</td></tr>')
        def send(extra):
            html = '<title>Stock List</title><table>' + row + extra + '</table>'
            return self.client.post('/api/items/import', data={
                'file': (io.BytesIO(html.encode()), 'STOCK.HTM')})
        for _ in range(2):
            result = send(footer)
            self.assertEqual(result.status_code, 200, result.get_data(as_text=True))
        self.assertEqual(Item.query.count(), 1)
        self.assertEqual(Item.query.one().qty, 2)
        broken = send('<tr class="item"><td colspan="9">Broken medicine</td></tr>')
        self.assertEqual(broken.status_code, 500)
        self.assertIn("Incomplete item row", broken.json["error"])
        self.assertEqual(Item.query.count(), 1)
        self.assertEqual(Item.query.one().qty, 2)

    def test_uploaded_stock_export_reimports_without_duplicates(self):
        file = Path(__file__).resolve().parents[2] / 'upload' / 'STOCK.HTM'
        if not file.exists():
            self.skipTest('User stock fixture unavailable')
        for added in (104, 0):
            result = self.client.post('/api/items/import', data={
                'file': (io.BytesIO(file.read_bytes()), 'STOCK.HTM')})
            self.assertEqual(result.status_code, 200, result.get_data(as_text=True))
            self.assertTrue(result.json['own_stock'])
            self.assertEqual(result.json['added'], added)
        self.assertEqual(Item.query.count(), 104)
        self.assertEqual(Supplier.query.count(), 0)

    def test_legacy_upgrade_and_global(self):
        db.session.add(Item(user_id=1,code='ITM0001',name='EXACT NAME.',vendor='A',tp=100,retail_price=100))
        db.session.commit(); self.upload()
        self.assertEqual(Item.query.count(),1)
        self.assertEqual(Item.query.one().code,'ITM0001')
        self.upload(admin=True)
        self.assertEqual(Item.query.filter_by(is_global=True).one().vendor_code,'0296')

    def test_invoice_edit_totals_use_new_lines_once(self):
        self.upload()
        item=Item.query.one()
        created=self.client.post('/api/invoices',json={'lines':[
            {'item_id':item.id,'qty':1,'tp':100,'discount_pct':0,'tax_pct':0}]})
        self.assertEqual(created.status_code,201)
        inv=created.json
        updated=self.client.put('/api/invoices/'+str(inv['id']),json={'lines':[
            {'item_id':item.id,'qty':2,'tp':100,'discount_pct':10,'tax_pct':12}],
            'discount_amount':5})
        self.assertEqual(updated.status_code,200)
        result=updated.json
        self.assertEqual(result['subtotal'],180)
        self.assertEqual(result['tax_amount'],24)
        self.assertEqual(result['total'],199)
        self.assertEqual(len(result['lines']),1)
        self.assertEqual(result['lines'][0]['qty'],2)
        stock=float(Item.query.one().qty)
        again=self.client.put('/api/invoices/'+str(inv['id']),json={
            'lines':result['lines'],'discount_amount':5})
        self.assertEqual(again.status_code,200)
        self.assertEqual(again.json['total'],199)
        self.assertEqual(float(Item.query.one().qty),stock)

    def test_invoice_snapshot(self):
        self.upload(); item=Item.query.one()
        r=self.client.post('/api/invoices',json={'lines':[{'item_id':item.id,'qty':2,'tp':100,'discount_pct':4}]})
        self.assertEqual(r.status_code,201,r.get_data(as_text=True))
        inv=r.json; line=inv['lines'][0]
        self.assertEqual((line['vendor_code'],line['vendor_name'],line['vendor_list_no']),('0296','EXACT  NAME.','000052'))
        self.assertEqual(line['vendor_discount_pct'],13)
        self.assertEqual(line['discount_pct'],4)
        self.upload(name='NEW NAME')
        r=self.client.put('/api/invoices/'+str(inv['id']),json={'lines':[line]})
        self.assertEqual(r.status_code,200,r.get_data(as_text=True))
        self.assertEqual(r.json['lines'][0]['vendor_name'],'EXACT  NAME.')

    def test_backfill_preserves_customer_rates_and_existing_snapshots(self):
        from models import InvoiceLine
        from supplier_discount import backfill_supplier_discounts
        self.upload(); item=Item.query.one()
        response=self.client.post('/api/invoices',json={'lines':[{'item_id':item.id,'qty':1,'tp':100,'discount_pct':4}]})
        self.assertEqual(response.status_code,201)
        line=InvoiceLine.query.one()
        item.vendor_discount_pct=None; line.vendor_discount_pct=None
        db.session.commit()
        backfill_supplier_discounts(db.session); db.session.commit(); db.session.expire_all()
        self.assertEqual(float(line.vendor_discount_pct),13)
        self.assertEqual(float(line.discount_pct),4)
        item.vendor_discount_pct=20; db.session.commit()
        backfill_supplier_discounts(db.session); db.session.commit(); db.session.expire_all()
        self.assertEqual(float(line.vendor_discount_pct),13)
        line.vendor_discount_pct=None;line.vendor_list_no='DIFFERENT';db.session.commit()
        backfill_supplier_discounts(db.session);db.session.commit();db.session.expire_all()
        self.assertIsNone(line.vendor_discount_pct)

    def test_supplier_purchase_keeps_customer_discount_separate(self):
        self.upload(vendor='DOSANI')
        item=Item.query.one()
        db.session.add(UserItemDiscount(user_id=1,item_id=item.id,discount_pct=4))
        supplier=Supplier.query.filter_by(user_id=1,name='DOSANI').one()
        response=self.client.post('/api/purchase',json={
            'supplier_id':supplier.id,'supplier_name':'DOSANI',
            'lines':[{'item_id':item.id,'qty':2,'tp':100,'retail':120,'disc':13,'tax':0}]
        })
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        self.assertEqual(float(Purchase.query.one().lines[0].disc_pct),13)
        self.assertEqual(float(Purchase.query.one().total_cost),174)
        self.assertEqual(float(supplier.balance),174)
        self.assertEqual(float(UserItemDiscount.query.one().discount_pct),4)
        self.assertEqual(float(Item.query.one().discount_pct),13)  # inventory offer remains its own field

    def test_new_purchase_item_is_linked_to_supplier_not_customer_rate(self):
        supplier=Supplier(user_id=1,name='DOSANI')
        db.session.add(supplier);db.session.commit()
        response=self.client.post('/api/purchase',json={
            'supplier_id':supplier.id,'supplier_name':'DOSANI',
            'lines':[{'item_name':'NEW MED','qty':3,'tp':100,'retail':120,'disc':12,
                      'vendor_code':'A42','vendor_name':'NEW MED ORIGINAL','supplier_bonus':'10+1'}]
        })
        self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        item=Item.query.one()
        self.assertEqual((item.vendor,item.vendor_code,item.vendor_name,item.bonus_text),
                         ('DOSANI','A42','NEW MED ORIGINAL','10+1'))
        self.assertEqual(float(item.discount_pct),0)
        self.assertEqual(float(item.vendor_discount_pct),12)
        self.assertEqual(float(item.qty),3)

    def test_saved_counter_purchase_can_be_linked_to_supplier(self):
        created=self.client.post('/api/purchase',json={
            'supplier_name':'Counter','lines':[{'item_name':'MED A','qty':2,'tp':100,'retail':120,'disc':10}]
        })
        self.assertEqual(created.status_code,200,created.get_data(as_text=True))
        purchase=created.json
        self.assertIsNone(purchase['supplier_id'])
        self.assertEqual(len(self.client.get('/api/purchases').json),1)
        supplier=Supplier(user_id=1,name='DOSANI')
        db.session.add(supplier);db.session.commit()
        updated=self.client.put('/api/purchases/'+str(purchase['id']),json={
            'supplier_id':supplier.id,'supplier_name':'DOSANI',
            'lines':[{'item_id':purchase['lines'][0]['item_id'],'item_name':'MED A',
                      'qty':2,'tp':100,'retail':120,'disc':10,'tax':0}]
        })
        self.assertEqual(updated.status_code,200,updated.get_data(as_text=True))
        self.assertEqual(updated.json['supplier_id'],supplier.id)
        self.assertEqual(float(supplier.balance),180)
        self.assertEqual(Item.query.one().vendor,'DOSANI')
        self.assertEqual(float(Item.query.one().qty),2)

if __name__=='__main__': unittest.main()
