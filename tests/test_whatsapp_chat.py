"""Exercise guided workflows through the real polling endpoint and persisted state."""
import json
import unittest
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from unittest.mock import patch
import tests.test_whatsapp_agent as base
import whatsapp_chat as chat
from models import (db, Customer, Supplier, Invoice, InvoiceLine, Purchase,
                    CustomerPayment, SupplierPayment, WhatsAppAgent, WhatsAppConversation, WhatsAppDraft, User, Item)


class ChatTest(unittest.TestCase):
    signin=base.AgentTest.signin
    call=base.AgentTest.call
    save=base.AgentTest.save
    tearDown=base.AgentTest.tearDown
    def setUp(self):
        base.AgentTest.setUp(self);self.save();self.serial=0
        today=datetime.now(ZoneInfo('Asia/Karachi')).date()
        self.customer=Customer(user_id=1,name='Ali',code='C-1',opening_balance=100)
        self.supplier=Supplier(user_id=1,name='Vendor 1',code='S-1',opening_balance=20)
        db.session.add_all([self.customer,self.supplier,Customer(user_id=2,name='SECRET CUSTOMER'),Supplier(user_id=2,name='SECRET SUPPLIER')]);db.session.flush()
        self.invoice=Invoice(user_id=1,invoice_number='SSD-0013',customer_id=self.customer.id,customer_name_snap='Ali',invoice_date=today,status='posted',total=200,amount_paid=50,subtotal=180,tax_amount=20)
        db.session.add(self.invoice);db.session.flush()
        item=Item.query.filter_by(user_id=1).one();item.qty=12;item.vendor_discount_pct=11;item.vendor_code='SUP-22';item.vendor_list_no='0052'
        db.session.add(InvoiceLine(invoice_id=self.invoice.id,item_id=item.id,item_name='PANADOL TAB',item_code=item.code,qty=2,tp=90,discount_pct=1,tax_pct=10,line_net=178.2,vendor='Vendor 1',vendor_code='SUP-22',vendor_list_no='0052',vendor_discount_pct=11))
        db.session.add_all([CustomerPayment(user_id=1,customer_id=self.customer.id,amount=30,payment_date=today),
                           CustomerPayment(user_id=2,customer_id=self.customer.id,amount=9000,payment_date=today),
                           Purchase(user_id=1,purchase_number='PUR-0001',supplier_id=self.supplier.id,supplier_name='Vendor 1',total_cost=100,purchase_date=today),
                           SupplierPayment(user_id=1,supplier_id=self.supplier.id,amount=40,payment_date=today),
                           Invoice(user_id=2,invoice_number='SECRET-1',customer_name_snap='SECRET CUSTOMER',status='posted',total=9999,invoice_date=today)])
        db.session.commit()

    def send(self,text,fail=False):
        self.serial+=1
        row=db.session.get(WhatsAppAgent,1);row.last_poll=None;db.session.commit()
        update={'next_offset':self.serial,'entry':[{'changes':[{'value':{'messages':[{'id':'chat-'+str(self.serial),'from':'user:owner','type':'text','text':{'body':text}}]}}]}]}
        calls=[]
        def remote(token,endpoint,payload=None,raw=False):
            if endpoint.startswith('/updates'): return update
            calls.append((endpoint,payload))
            if fail and endpoint=='/messages': raise RuntimeError('delivery failed')
            return {'id':'media-id'} if endpoint=='/media' else {}
        with patch.object(base.agent,'remote',side_effect=remote): response=self.call('/poll')
        self.assertEqual(response.status_code,502 if fail else 200)
        self.calls=calls
        message=next((p for e,p in reversed(calls) if e=='/messages'),{})
        return message.get('text',{}).get('body','') or message.get('document',{}).get('caption','')

    def state(self): return json.loads(db.session.get(WhatsAppConversation,(1,'user:owner')).state)

    def confirm(self): return self.send('confirm '+self.state()['confirmation_id'][:6])

    def test_menu_and_direct_demand(self):
        answer=self.send('menu');self.assertIn('10. Create draft purchase',answer)
        answer=self.send('PANADOL TAB (2)');self.assertIn('Matched: 1',answer);self.assertNotIn('Vendor 2',answer)

    def test_customer_selection_balance_and_navigation(self):
        self.send('menu');answer=self.send('6')
        self.assertIn('1. Ali',answer);self.assertNotIn('SECRET',answer)
        self.assertIn('Rs. 220.00',self.send('1'))
        self.assertIn('SSD-0013',self.send('1'))
        self.assertIn('Payment history',self.send('back'))
        self.assertIn('Rs. 30.00',self.send('2'));self.assertNotIn('9,000',self.send('back'))
        self.assertIn('Opening balance',self.send('3'))

    def test_supplier_selection_balance_payments(self):
        self.send('menu');answer=self.send('7');self.assertNotIn('SECRET',answer)
        self.assertIn('Payable: Rs. 80.00',self.send('1'))
        self.assertIn('PUR-0001',self.send('1'));self.send('back')
        self.assertIn('Rs. 40.00',self.send('2'))

    def test_party_pagination_search_and_restart(self):
        db.session.add_all(Customer(user_id=1,name=f'Zed {i:02d}') for i in range(20));db.session.commit()
        self.send('6');self.assertIn('page 2/2',self.send('next'))
        self.assertIn('page 1/2',self.send('previous'))
        self.assertIn('21. Zed 19',self.send('Zed 19'))
        db.session.expire_all();self.assertIn('Zed 19',self.send('21'))
        self.assertIn('Select customer',self.send('back'))

    def test_continuous_numbers_and_direct_selection_from_any_page(self):
        db.session.add_all(Customer(user_id=1,name=f'Zed {i:02d}') for i in range(39));db.session.commit()
        self.send('6');page=self.send('next');self.assertIn('16. Zed 14',page);self.assertNotIn('\n1. ',page)
        page=self.send('next');self.assertIn('31. Zed 29',page)
        self.send('menu');self.send('6');self.assertIn('Zed 29',self.send('31'))
        self.send('back');self.assertIn('Select customer',self.send('previous'))
        self.assertIn('Ali',self.send('C-1'))

    def test_supplier_numbers_do_not_restart_and_selection_is_owner_scoped(self):
        db.session.add_all(Supplier(user_id=1,name=f'Zed {i:02d}',code=f'S-{i+2}') for i in range(20));db.session.commit()
        self.send('7');self.assertIn('16. Zed 14',self.send('next'))
        self.send('previous');self.assertIn('Zed 14',self.send('16'))
        self.send('back');self.assertIn('Choose a number from 1 to 21',self.send('22'))

    def test_number_selection_does_not_shift_if_a_customer_is_added(self):
        self.send('6')
        db.session.add(Customer(user_id=1,name='Aaron',code='C-NEW'));db.session.commit()
        self.assertIn('Ali',self.send('1'))
        self.send('menu');page=self.send('6')
        self.assertIn('1. Ali',page);self.assertIn('2. Aaron',page)
        self.assertIn('Ali',self.send('1'))

    def test_old_page_local_numbers_require_refreshed_list(self):
        self.send('6');state=self.state();state.pop('numbering_version');state.pop('party_numbers')
        db.session.get(WhatsAppConversation,(1,'user:owner')).state=json.dumps(state);db.session.commit()
        answer=self.send('1');self.assertIn('Numbering has been updated',answer);self.assertNotIn('Receivable:',answer)

    def test_invoice_pdf_uses_existing_renderer(self):
        self.send('5');self.assertNotIn('SECRET',self.send('1'))
        self.send('1');upload=self.calls[0][1]
        self.assertIn(b'%PDF',upload[0]);self.assertIn(b'Content-Type: application/pdf',upload[0])
        self.assertEqual(self.calls[-1][1]['document']['filename'],'SSD-0013.pdf')

    def test_invoice_orders_use_supplier_snapshot_discount(self):
        self.send('5');self.send('1');answer=self.send('2')
        self.assertIn('*Disc*: 11%',answer);self.assertNotIn('*Disc*: 1%',answer)
        answer=self.confirm();self.assertIn('*Code*: SUP-22',answer);self.assertIn('Nothing was sent to suppliers',answer)
        self.assertEqual(Purchase.query.count(),1)

    def test_stock_and_supplier_comparison(self):
        self.send('2');answer=self.send('PANADOL');self.assertIn('Qty: 12',answer)
        self.send('menu');self.send('3');answer=self.send('PANADOL TAB')
        self.assertIn('Discount: 11%',answer);self.assertNotIn('Vendor 2',answer)

    def test_orders_require_quantity_and_one_offer_per_item(self):
        self.send('4');self.assertIn('Specify a unit quantity',self.send('PANADOL TAB'))
        self.assertIn('Supplier disc 11%',self.send('PANADOL TAB (3)'))
        self.assertIn('exactly one offer',self.send('1 1'))
        self.assertIn('PREVIEW',self.send('1'));self.assertIn('*QTY*: 3',self.confirm())

    def prepare_invoice(self):
        self.send('menu');self.send('9');self.send('1');self.send('PANADOL TAB (3)');return self.send('1')

    def test_invoice_draft_requires_confirmation_no_stock_or_balance_write(self):
        answer=self.prepare_invoice();self.assertIn('Invoice preparation for Ali',answer)
        self.assertEqual(WhatsAppDraft.query.count(),0)
        self.assertIn('Reply confirm ',self.send('confirm'))
        answer=self.confirm();draft=WhatsAppDraft.query.one();self.assertIn('/whatsapp-drafts/'+str(draft.id),answer)
        self.assertEqual(Invoice.query.count(),2);self.assertEqual(Item.query.filter_by(user_id=1).one().qty,12)
        self.assertEqual(chat.balance(1,self.customer),220)
        page=self.client.get('/whatsapp-drafts/'+str(draft.id));self.assertEqual(page.status_code,200);self.assertIn('Open in Billing',page.get_data(as_text=True))
        self.assertEqual(self.client.get('/api/whatsapp-agent/drafts/'+str(draft.id)).json['kind'],'invoice')
        self.signin(2);self.assertEqual(self.client.get('/api/whatsapp-agent/drafts/'+str(draft.id)).status_code,404)

    def test_purchase_draft_has_supplier_terms_and_does_not_receive_stock(self):
        self.send('10');self.send('1');self.send('PANADOL TAB (4)');answer=self.send('1');self.assertIn('Disc 11%',answer)
        self.confirm();draft=WhatsAppDraft.query.one();self.assertEqual(draft.kind,'purchase')
        self.assertEqual(Purchase.query.count(),1);self.assertEqual(Item.query.filter_by(user_id=1).one().qty,12)
        self.assertIn('Open in Purchase',self.client.get('/whatsapp-drafts/'+str(draft.id)).get_data(as_text=True))

    def test_failed_confirmation_delivery_rolls_back_draft_and_state(self):
        self.prepare_invoice();before=self.state();self.send('confirm '+before['confirmation_id'][:6],fail=True)
        self.assertEqual(WhatsAppDraft.query.count(),0);self.assertEqual(self.state(),before)
        self.confirm();self.assertEqual(WhatsAppDraft.query.count(),1)

    def test_preview_expiry_and_cancel_do_not_create_drafts(self):
        self.prepare_invoice();state=self.state();state['expires']=(datetime.utcnow()-timedelta(seconds=1)).isoformat()
        db.session.get(WhatsAppConversation,(1,'user:owner')).state=json.dumps(state);db.session.commit()
        self.assertIn('Preview expired',self.send('confirm '+state['confirmation_id'][:6]));self.assertEqual(WhatsAppDraft.query.count(),0)
        self.prepare_invoice();self.assertIn('Task cancelled',self.send('cancel'));self.assertEqual(WhatsAppDraft.query.count(),0)

    def test_permissions_rechecked_during_conversation(self):
        self.send('6');user=db.session.get(User,1);user.perm_customers=False;db.session.commit()
        self.assertIn('Access disabled',self.send('1'))
        self.send('menu');self.assertIn('Access to this option is disabled',self.send('6'))

    def test_reports_scope_and_exclude_other_accounts(self):
        self.send('8');answer=self.send('1')
        self.assertIn('Posted sales: Rs. 200.00 (1 bills)',answer);self.assertIn('Purchases: Rs. 100.00',answer)
        self.assertIn('Customer payment entries: Rs. 30.00',answer);self.assertNotIn('9,999',answer)

    def test_deleted_item_cannot_be_confirmed_or_reopened(self):
        self.prepare_invoice();item=Item.query.filter_by(user_id=1).one();item.is_active=False;db.session.commit()
        self.assertIn('no longer available',self.confirm());self.assertEqual(WhatsAppDraft.query.count(),0)
        item.is_active=True;db.session.commit();self.confirm();draft=WhatsAppDraft.query.one()
        item.user_id=2;db.session.commit()
        self.assertEqual(self.client.get('/api/whatsapp-agent/drafts/'+str(draft.id)).status_code,409)

    def test_failed_menu_delivery_does_not_advance_selection(self):
        self.send('menu');before=self.state();self.send('6',fail=True)
        self.assertEqual(self.state(),before)
        self.assertIn('Select customer',self.send('6'))

    def test_balance_option_does_not_bypass_bill_permissions(self):
        self.send('6');self.send('1');user=db.session.get(User,1);user.perm_bill=False;db.session.commit()
        self.assertIn('Invoice access disabled',self.send('1'))
        self.assertIn('Rs. 30.00',self.send('2'))

    def test_purchase_preparation_cannot_use_another_accounts_shared_stock(self):
        db.session.add(Item(user_id=2,is_global=True,code='SHARED',name='PANADOL TAB',retail_price=100,tp=70,vendor='Vendor 1',vendor_discount_pct=50,is_active=True));db.session.commit()
        self.send('10');self.send('1');self.send('PANADOL TAB (2)')
        self.assertTrue(all(c['item']['user_id']==1 for c in self.state()['choices']))
        self.send('1');self.confirm();draft=WhatsAppDraft.query.one()
        payload=self.client.get('/api/whatsapp-agent/drafts/'+str(draft.id)).json['payload']
        self.assertEqual(payload['lines'][0]['current_stock'],12)

    def test_user_deletion_cleans_chat_credentials_and_preparations(self):
        self.prepare_invoice();self.confirm()
        db.session.add(User(id=3,username='admin-test',password_hash='unused',is_superadmin=True));db.session.commit()
        with self.client.session_transaction() as session:
            session.clear();session['is_superadmin']=True;session['superadmin_uid']=3
        response=self.client.delete('/api/superadmin/users/1')
        self.assertEqual(response.status_code,200)
        self.assertEqual(WhatsAppDraft.query.filter_by(user_id=1).count(),0)
        self.assertEqual(WhatsAppConversation.query.filter_by(user_id=1).count(),0)
        self.assertIsNone(db.session.get(WhatsAppAgent,1))


if __name__=='__main__': unittest.main()
