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
from models import db, User, Item, Settings
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
        self.assertEqual(Item.query.count(),4)
        self.assertEqual(self.upload(name='RENAMED.',bonus='')['updated'],1)
        self.assertEqual(Item.query.count(),4)
        i=Item.query.filter_by(vendor='A',vendor_code='0296',vendor_list_no='000052').one()
        self.assertEqual((i.to_dict()['code'],i.vendor_name,i.bonus_text),('0296','RENAMED.',''))

    def test_legacy_upgrade_and_global(self):
        db.session.add(Item(user_id=1,code='ITM0001',name='EXACT NAME.',vendor='A',tp=100,retail_price=100))
        db.session.commit(); self.upload()
        self.assertEqual(Item.query.count(),1)
        self.assertEqual(Item.query.one().code,'ITM0001')
        self.upload(admin=True)
        self.assertEqual(Item.query.filter_by(is_global=True).one().vendor_code,'0296')

    def test_invoice_snapshot(self):
        self.upload(); item=Item.query.one()
        r=self.client.post('/api/invoices',json={'lines':[{'item_id':item.id,'qty':2,'tp':100,'discount_pct':13}]})
        self.assertEqual(r.status_code,201,r.get_data(as_text=True))
        inv=r.json; line=inv['lines'][0]
        self.assertEqual((line['vendor_code'],line['vendor_name'],line['vendor_list_no']),('0296','EXACT  NAME.','000052'))
        self.upload(name='NEW NAME')
        r=self.client.put('/api/invoices/'+str(inv['id']),json={'lines':[line]})
        self.assertEqual(r.status_code,200,r.get_data(as_text=True))
        self.assertEqual(r.json['lines'][0]['vendor_name'],'EXACT  NAME.')

if __name__=='__main__': unittest.main()
