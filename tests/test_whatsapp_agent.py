"""Real setup/runner routes, private storage and shared Demand Search rules."""
import os
import sys
import json
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['SECRET_KEY'] = 'test-only-stable-agent-secret'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
original_init = SQLAlchemy.init_app
def sqlite_init(self, app):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    original_init(self, app)
with patch.object(SQLAlchemy, 'init_app', sqlite_init):
    import app as service
import whatsapp_agent as agent
from models import db, User, Settings, Item, WhatsAppAgent
service._defaults_seeded = True

class AgentTest(unittest.TestCase):
    def setUp(self):
        self.ctx = service.app.app_context(); self.ctx.push(); db.create_all()
        for uid in (1, 2):
            db.session.add(User(id=uid, username=str(uid), password_hash=generate_password_hash('password'), perm_items=True))
            db.session.add(Settings(user_id=uid, shop_name='Shop', address='Address', phone='1', whatsapp='1'))
            db.session.add(Item(user_id=uid, code=str(uid), name='PANADOL TAB', retail_price=100, tp=90, discount_pct=uid, vendor='Vendor '+str(uid), is_active=True))
        db.session.commit()
        self.client = service.app.test_client()
        self.signin(1)

    def tearDown(self):
        db.session.remove(); db.drop_all(); self.ctx.pop()

    def signin(self, uid, admin=True):
        with self.client.session_transaction() as session:
            session.clear(); session['user_id'] = uid; session['is_admin'] = admin; session['agent_csrf'] = 'csrf'

    def call(self, path='', method='POST', data=None, csrf=True):
        return self.client.open('/api/whatsapp-agent'+path, method=method, json=data or {}, headers={'X-Agent-CSRF':'csrf'} if csrf else {})

    def save(self):
        with patch.object(agent, 'remote', return_value={}):
            response=self.call(data={'key':'fake-agent-secret'})
        self.assertEqual(response.status_code,200)
        return response

    def test_key_encrypted_never_exposed_and_bound_to_account(self):
        saved=self.save()
        self.assertNotIn('fake-agent-secret', saved.get_data(as_text=True))
        row=db.session.get(WhatsAppAgent,1)
        self.assertNotIn('fake-agent-secret',row.encrypted_key)
        self.assertEqual(agent.cipher().decrypt(row.encrypted_key.encode()),b'fake-agent-secret')
        response=self.call(method='GET')
        self.assertNotIn('encrypted_key',response.json)
        self.assertEqual(response.headers['Cache-Control'],'no-store')
        self.signin(2)
        self.assertFalse(self.call(method='GET').json['configured'])

    def test_csrf_and_admin_access_required(self):
        self.assertEqual(self.call(data={'key':'test'},csrf=False).status_code,403)
        self.signin(1,False)
        self.assertEqual(self.call(data={'key':'test'}).status_code,403)
        self.assertIsNone(db.session.get(WhatsAppAgent,1))

    def test_invalid_key_does_not_replace_saved_key(self):
        self.save();before=db.session.get(WhatsAppAgent,1).encrypted_key
        with patch.object(agent,'remote',side_effect=RuntimeError('WhatsApp connection failed (401).')):
            self.assertEqual(self.call(data={'key':'bad-secret'}).status_code,400)
        self.assertEqual(db.session.get(WhatsAppAgent,1).encrypted_key,before)

    def test_stable_secret_is_required(self):
        with patch.dict(os.environ,{'SECRET_KEY':''}):
            self.assertEqual(self.call(data={'key':'test'}).status_code,400)
        self.assertIsNone(db.session.get(WhatsAppAgent,1))

    def test_runner_scope_rotation_and_removal(self):
        self.save()
        first=self.call('/runner-token').json['token']
        second=self.call('/runner-token').json['token']
        def run(uid,token):
            return self.client.post(f'/api/whatsapp-agent/runner/{uid}',headers={'Authorization':'Bearer '+token},json={})
        self.assertEqual(run(1,first).status_code,401)
        self.assertEqual(run(2,second).status_code,401)
        self.client.get('/auth/logout')
        with patch.object(agent,'remote',return_value={}):
            self.assertEqual(run(1,second).status_code,200)
        self.signin(1)
        self.assertEqual(self.call(method='DELETE').status_code,200)
        self.assertEqual(run(1,second).status_code,401)

    def test_poll_matches_only_owner_inventory_and_sends_to_creator(self):
        self.save()
        update={'next_offset':12,'entry':[{'changes':[{'value':{'messages':[{'id':'m1','from':'user:owner','type':'text','text':{'body':'PANADOL TAB (2)'}}]}}]}]}
        calls=[]
        def remote(token,endpoint,payload=None,raw=False):
            calls.append((endpoint,payload))
            return update if endpoint.startswith('/updates') else {}
        with patch.object(agent,'remote',side_effect=remote):
            response=self.call('/poll')
        self.assertEqual(response.status_code,200)
        message=calls[-1][1]
        self.assertEqual(message['to'],'user:owner')
        self.assertIn('Vendor: Vendor 1',message['text']['body'])
        self.assertNotIn('Vendor 2',message['text']['body'])
        self.assertIn('Qty: 2',message['text']['body'])
        self.assertEqual(db.session.get(WhatsAppAgent,1).offset,12)
        self.assertEqual(Item.query.count(),2)
        self.assertEqual(Item.query.filter_by(user_id=1).one().discount_pct,1)

    def test_failed_delivery_retains_offset_and_releases_lease(self):
        self.save()
        update={'next_offset':9,'entry':[{'changes':[{'value':{'messages':[{'id':'m1','from':'user:owner','type':'text','text':{'body':'help'}}]}}]}]}
        def remote(token,endpoint,payload=None,raw=False):
            if endpoint.startswith('/updates'):return update
            raise RuntimeError('Unavailable')
        with patch.object(agent,'remote',side_effect=remote):
            self.assertEqual(self.call('/poll').status_code,502)
        row=db.session.get(WhatsAppAgent,1)
        self.assertEqual(row.offset,0);self.assertEqual(json.loads(row.handled),[])
        self.assertIsNone(row.lease_until)

    def test_lease_and_rate_limit_prevent_duplicate_polling(self):
        self.save();row=db.session.get(WhatsAppAgent,1)
        row.lease_until=datetime.utcnow()+timedelta(seconds=50);db.session.commit()
        with patch.object(agent,'remote') as remote:
            self.assertEqual(self.call('/poll').status_code,409);remote.assert_not_called()
        row.lease_until=None;row.last_poll=datetime.utcnow();db.session.commit()
        with patch.object(agent,'remote') as remote:
            self.assertEqual(self.call('/poll').status_code,429);remote.assert_not_called()

    def test_shared_matcher_excludes_conflicting_strength(self):
        results=agent.match_rows([{'name':'PANADOL 500MG TAB','qty':'2'}],[{'name':'PANADOL 500MG TABLET','vendor':'A'},{'name':'PANADOL 250MG TAB','vendor':'B'}],False,service._frontend)
        self.assertEqual([o['item']['vendor'] for o in results[0]['offers']],['A'])

    def test_html_and_text_parsing_preserve_quantities(self):
        self.assertEqual(agent.parse_text('PANADOL TAB (3) lazmi',service._frontend)[0]['qty'],'3')
        rows=agent.html_rows('<script>throw 1</script><table><tr><th>Item Name</th><th>Box</th><th>PCS</th></tr><tr><td>PANADOL TAB</td><td>2</td><td>4</td></tr></table>')
        self.assertEqual(rows[0]['box'],'2');self.assertEqual(rows[0]['pcs'],'4')

    def test_download_host_is_validated_before_network_access(self):
        with self.assertRaises(ValueError):agent.remote('private-secret','https://example.com/file',raw=True)

    def test_setup_page_has_private_key_field_and_trial_limit(self):
        page=self.client.get('/admin/whatsapp-agent')
        self.assertEqual(page.status_code,200)
        self.assertIn('type="password"',page.get_data(as_text=True))
        self.assertIn('Keep this page open',page.get_data(as_text=True))

    def test_backups_do_not_include_agent_secret_or_runner(self):
        self.save();self.call('/runner-token')
        with service.app.test_request_context('/'):
            body=json.dumps(service._backup_payload(1))
        self.assertNotIn('fake-agent-secret',body)
        self.assertNotIn('encrypted_key',body)
        self.assertNotIn('runner_hash',body)

    def test_pdf_rows_preserve_demand_quantity(self):
        from io import BytesIO
        from PyPDF2 import PdfWriter
        stream=BytesIO();writer=PdfWriter();writer.add_blank_page(width=100,height=100);writer.write(stream)
        from PyPDF2._page import PageObject
        with patch.object(agent,'remote',side_effect=[{'url':'https://lookaside.fbsbx.com/agent/v1/media/x/content'},stream.getvalue()]), patch.object(PageObject,'extract_text',return_value='PANADOL TAB (2)'):
            rows=agent.document_rows({'document':{'filename':'demand.pdf','id':'x'}},'key',service._frontend,service._parse_demand_pdf_table)
        self.assertEqual(rows[0]['qty'],'2')

    def test_long_results_are_returned_as_document(self):
        calls=[]
        def remote(token,endpoint,payload=None,raw=False):
            calls.append((endpoint,payload));return {'id':'report-id'} if endpoint=='/media' else {}
        with patch.object(agent,'remote',side_effect=remote):
            agent.reply('key','user:owner','Long results\n'+'A'*5000)
        self.assertEqual(calls[-1][1]['type'],'document')
        self.assertEqual(calls[-1][1]['document']['id'],'report-id')

if __name__=='__main__':unittest.main()
