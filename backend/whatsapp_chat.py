"""Account-scoped guided WhatsApp workflows. Only confirmed preparation drafts are written.

Business records, stock and payments are changed only through the existing web editors.
Conversation updates and draft saves share the poll's delivery transaction.
"""
import json
import math
import secrets
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from html import escape
from sqlalchemy import func
from models import (db, User, Settings, Item, Customer, Supplier, Invoice, Purchase,
                    CustomerPayment, SupplierPayment, WhatsAppConversation, WhatsAppDraft, WhatsAppPartyNumber)

HOME = 'https://billmate-med.vercel.app'
LABELS = ['Demand Search', 'Check own stock', 'Compare supplier offers', 'Prepare supplier orders',
          'Find invoice / PDF', 'Customer receivables', 'Supplier payables',
          'Sales and purchase reports', 'Create draft invoice', 'Create draft purchase']
PERMISSIONS = {1:['perm_items'],2:['perm_items'],3:['perm_items'],4:['perm_items'],
               5:['perm_bill'],6:['perm_customers'],7:['perm_suppliers'],
               8:['perm_bill','perm_purchases'],9:['perm_bill','perm_items','perm_customers'],
               10:['perm_purchases','perm_items','perm_suppliers']}


def ensure():
    for model in (WhatsAppConversation, WhatsAppDraft, WhatsAppPartyNumber):
        model.__table__.create(db.engine, checkfirst=True)


def permitted(user, mode):
    return all(getattr(user, name) for name in PERMISSIONS.get(mode, []))


def menu(user):
    return 'BillMate Assistant\n' + '\n'.join(f'{i}. {name}' + ('' if permitted(user,i) else ' (access disabled)') for i,name in enumerate(LABELS,1)) + '\n\nReply with a number. menu = home; back = previous step; cancel = end task.\nOr send an item name directly for Demand Search. Inventory imports use the separate agent.'


def money(value):
    return f'Rs. {float(value or 0):,.2f}'


def validate_draft(uid,payload,kind):
    """Recheck ownership when confirming and when opening an old preparation."""
    party_id=payload.get('party_id')
    if party_id:
        model=Supplier if kind=='purchase' else Customer
        if not model.query.filter_by(id=party_id,user_id=uid,is_active=True).first():
            raise ValueError('Selected account is no longer available. Start a new draft.')
    ids={l['item_id'] for l in payload['lines']}
    visibility=(Item.user_id==uid) if kind=='purchase' else db.or_(Item.user_id==uid,Item.is_global.is_(True))
    allowed={i.id for i in Item.query.filter(Item.id.in_(ids),Item.is_active.is_(True),visibility).all()}
    if ids!=allowed:
        raise ValueError('Some draft items are no longer available to this account. Start a new draft.')


def balance(uid, entity, supplier=False):
    if supplier:
        invoices = db.session.query(func.sum(Purchase.total_cost)).filter_by(user_id=uid, supplier_id=entity.id).scalar()
        paid = db.session.query(func.sum(SupplierPayment.amount)).filter_by(user_id=uid, supplier_id=entity.id).scalar()
    else:
        invoices = db.session.query(func.sum(Invoice.total-Invoice.amount_paid)).filter(
            Invoice.user_id==uid, Invoice.customer_id==entity.id, Invoice.status.in_(['posted','finalised'])).scalar()
        paid = db.session.query(func.sum(CustomerPayment.amount)).filter_by(user_id=uid, customer_id=entity.id).scalar()
    return round(float(entity.opening_balance or 0)+float(invoices or 0)-float(paid or 0),2)


def ledger(uid, entity, supplier=False, section='statement'):
    lines = [entity.name, ('Payable: ' if supplier else 'Receivable: ') + money(balance(uid,entity,supplier))]
    if section=='statement': lines.append('Opening balance: '+money(entity.opening_balance))
    if section in ('statement','bills'):
        model = Purchase if supplier else Invoice
        q = model.query.filter_by(user_id=uid, **({'supplier_id':entity.id} if supplier else {'customer_id':entity.id}))
        if not supplier: q=q.filter(Invoice.status.in_(['posted','finalised']))
        rows=q.order_by(model.id.desc()).limit(31).all()
        lines.append('Recent purchases:' if supplier else 'Recent posted invoices:')
        for obj in rows[:30]:
            lines.append(f'{obj.purchase_date if supplier else obj.invoice_date} | {obj.purchase_number if supplier else obj.invoice_number} | {money(obj.total_cost if supplier else obj.total)}' + ('' if supplier else ' | Paid at billing: '+money(obj.amount_paid)))
        if not rows: lines.append('None.')
        if len(rows)>30: lines.append('Showing latest 30; balance includes all records.')
    if section in ('statement','payments'):
        model=SupplierPayment if supplier else CustomerPayment
        rows=model.query.filter_by(user_id=uid,**({'supplier_id':entity.id} if supplier else {'customer_id':entity.id})).order_by(model.id.desc()).limit(31).all()
        lines.append('Recent payments:')
        lines += [f'{p.payment_date} | {money(p.amount)} | {p.notes or ""}' for p in rows[:30]] or ['None.']
        if len(rows)>30: lines.append('Showing latest 30; balance includes all payments.')
    lines.append('back = account options; menu = main menu')
    return '\n'.join(lines)


class Chat:
    def __init__(self, app, frontend, inventory, agent, uid, recipient):
        self.app,self.frontend,self.inventory,self.agent=app,frontend,inventory,agent
        self.uid,self.recipient=uid,recipient
        self.user=db.session.get(User,uid)
        if not self.user or self.user.is_suspended:
            raise ValueError('Account unavailable.')
        if not isinstance(recipient,str) or not recipient.startswith('user:') or len(recipient)>200:
            raise ValueError('Invalid agent recipient.')
        self.row=db.session.get(WhatsAppConversation,(uid,recipient))
        if not self.row:
            self.row=WhatsAppConversation(user_id=uid,recipient=recipient,state='{}');db.session.add(self.row)
        self.state=json.loads(self.row.state)
        if self.row.updated_at and datetime.utcnow()-self.row.updated_at>timedelta(hours=24): self.state={}

    def set(self,state,remember=True):
        history=self.state.get('history',[])
        if remember and self.state: history=(history+[ {k:v for k,v in self.state.items() if k!='history'} ])[-8:]
        self.state=dict(state,history=history)

    def done(self,text):
        self.row.state=json.dumps(self.state);self.row.updated_at=datetime.utcnow()
        return text

    def start(self,mode):
        if not permitted(self.user,mode): return 'Access to this option is disabled for your account. Send menu.'
        self.set({'mode':mode,'phase':'input'})
        if mode in (6,7,9,10): return self.party_list()
        if mode==5: return self.invoice_list()
        if mode==8: return 'Reports:\n1. Today\n2. Last 7 days\n3. This month\nOr send YYYY-MM-DD to YYYY-MM-DD.\nback / menu'
        return {1:'Send a demand file (TXT/PDF/HTM) or item list.',2:'Send an item name to check your own stock.',3:'Send item names to compare supplier offers, highest discount first.',4:'Send a demand with quantities, e.g. PANADOL TAB (10). Or send invoice SSD-0013 to use a saved bill.'}[mode]+'\nback / menu'

    def party_list(self,query='',page=0):
        mode=self.state['mode'];supplier=mode in (7,10);model=Supplier if supplier else Customer
        accounts=model.query.filter_by(user_id=self.uid,is_active=True).order_by(model.name,model.id).with_entities(model.id,model.name,model.code).all()
        # Permanent per-account numbers: new names append rather than renumbering
        # remembered customers/suppliers. Deleted or inactive numbers aren't reused.
        kind='supplier' if supplier else 'customer'
        assigned=WhatsAppPartyNumber.query.filter_by(user_id=self.uid,kind=kind).order_by(WhatsAppPartyNumber.number).all()
        if {p.id for p in accounts}-{n.entity_id for n in assigned}:
            User.query.filter_by(id=self.uid).with_for_update().first()
            assigned=WhatsAppPartyNumber.query.filter_by(user_id=self.uid,kind=kind).order_by(WhatsAppPartyNumber.number).all()
            known={n.entity_id for n in assigned};last=assigned[-1].number if assigned else 0
            for p in accounts:
                if p.id not in known:
                    last+=1;n=WhatsAppPartyNumber(user_id=self.uid,kind=kind,number=last,entity_id=p.id)
                    db.session.add(n);assigned.append(n);known.add(p.id)
            db.session.flush()
        self.state['party_numbers']=[n.entity_id for n in assigned]
        by_id={p.id:p for p in accounts}
        matches=[(n,by_id[iid]) for n,iid in enumerate(self.state['party_numbers'],1)
                 if iid in by_id and query.casefold() in by_id[iid].name.casefold()]
        total=len(matches);page=max(0,min(page,max(0,(total-1)//15)))
        rows=matches[page*15:page*15+15]
        self.state.update(phase='party',choices=[p.id for n,p in rows],page=page,query=query,numbering_version=3)
        title='Select supplier' if supplier else 'Select customer'
        lines=[title+f' — page {page+1}/{max(1,math.ceil(total/15))}']
        if mode==9: lines.append('0. Walk-in customer')
        lines += [f'{n}. {p.name} [{p.code or p.id}]' for n,p in rows]
        if not rows: lines.append('No names found. Try another name.')
        lines.append('Enter any customer/supplier number directly, even from another page, or an account code (e.g. CUST-0017). Type a name to search. next / previous / back / menu')
        return '\n'.join(lines)

    def party_options(self):
        supplier=self.state['mode']==7;model=Supplier if supplier else Customer
        p=model.query.filter_by(user_id=self.uid,id=self.state['party_id'],is_active=True).first()
        if not p: raise ValueError('Account no longer available. Send menu.')
        self.state['phase']='account'
        return p.name+'\n'+('Payable: ' if supplier else 'Receivable: ')+money(balance(self.uid,p,supplier))+'\n1. '+('Purchases' if supplier else 'Invoices')+'\n2. Payment history\n3. Statement\nback = select another name; menu = home'

    def invoice_list(self,query='',page=0):
        q=Invoice.query.filter(Invoice.user_id==self.uid,Invoice.status!='deleted',~Invoice.invoice_number.like('DRAFT-%'))
        if query: q=q.filter(Invoice.invoice_number.contains(query,autoescape=True))
        total=q.count();page=max(0,min(page,max(0,(total-1)//10)))
        rows=q.order_by(Invoice.id.desc()).offset(page*10).limit(10).all()
        self.state.update(phase='invoices',choices=[p.id for p in rows],page=page,query=query)
        return 'Select invoice — page '+str(page+1)+'\n'+'\n'.join(f'{i}. {p.invoice_number} | {p.customer_name_snap or "Walk-in"} | {money(p.total)}' for i,p in enumerate(rows,1))+'\nReply with a number or invoice number. next / previous / back / menu'

    def invoice(self,iid):
        p=Invoice.query.filter_by(user_id=self.uid,id=iid).filter(Invoice.status!='deleted').first()
        if not p: raise ValueError('Invoice not available in your account.')
        return p

    def invoice_info(self):
        p=self.invoice(self.state['invoice_id']);self.state['phase']='invoice'
        return f'{p.invoice_number} | {p.invoice_date} | {p.status}\nCustomer: {p.customer_name_snap or "Walk-in"}\nTotal: {money(p.total)}\nPaid at billing: {money(p.amount_paid)}\nItems: {len(p.lines)}\n1. Get PDF\n2. Prepare supplier order messages\n{HOME}/billing?edit={p.id}\nback / menu'

    def pdf(self):
        p=self.invoice(self.state['invoice_id']);settings=Settings.query.filter_by(user_id=self.uid).first()
        if not p.lines: raise ValueError('This invoice has no lines for PDF.')
        data={'invoice':p.to_dict(),'shop_name':settings.shop_name if settings else '',
              'shop_phone':settings.phone if settings else '', 'shop_address':settings.address if settings else '',
              'shop_ntn':settings.ntn if settings else '', 'show_phone':True}
        # The existing renderer uses ReportLab Paragraph markup. Escape stored text.
        def safe(v):
            if isinstance(v,str): return escape(v)
            if isinstance(v,list): return [safe(x) for x in v]
            if isinstance(v,dict): return {k:safe(x) for k,x in v.items()}
            return v
        with self.app.test_request_context('/api/invoice/pdf',method='POST',json=safe(data)):
            response=self.app.make_response(self.app.view_functions['invoice_pdf']())
            response.direct_passthrough=False
            content=response.get_data()
        if response.status_code!=200 or not content.startswith(b'%PDF'): raise ValueError('PDF generation failed. Open the invoice in BillMate.')
        filename=re_filename(p.invoice_number)+'.pdf'
        return {'text':'Invoice '+p.invoice_number,'file':content,'filename':filename,'mime':'application/pdf'}

    def orders(self,lines):
        groups={}
        for l in lines:
            vendor=str(l.get('vendor_name') or l.get('vendor') or '').strip()
            if not vendor or vendor.lower()=='stock': continue
            disc=l.get('vendor_discount_pct')
            if disc is None: raise ValueError('Supplier discount is missing for '+l['item_name']+'. Verify it in BillMate first; customer discounts are not used.')
            key=(vendor,str(l.get('vendor_list_no') or 'unspecified'))
            groups.setdefault(key,[]).append(f'*Code*: {l.get("vendor_code") or l.get("item_code") or "unspecified"}\n*QTY*: {l["qty"]:g}\n*Disc*: {float(disc):g}%\n*ITM*: {l["item_name"]}\n--------------------')
        if not groups: raise ValueError('No supplier items found. Own stock is excluded.')
        settings=Settings.query.filter_by(user_id=self.uid).first()
        customer=settings.shop_name if settings else ''
        return '\n\n'.join(f'Supplier: {vendor}\n*Customer*: {customer}\n*List No*: {number}\n====================\n'+'\n'.join(rows) for (vendor,number),rows in groups.items())

    def preview(self,payload,kind):
        text=self.orders(payload['lines']) if kind=='orders' else draft_summary(payload,kind)
        self.set({'mode':self.state['mode'],'phase':'confirm','payload':payload,'kind':kind,
                  'confirmation_id':secrets.token_hex(24),'expires':(datetime.utcnow()+timedelta(minutes=30)).isoformat()})
        return 'PREVIEW\n'+text+'\n\nReply confirm '+self.state['confirmation_id'][:6]+' to '+('generate order messages for you to forward' if kind=='orders' else 'save this preparation draft')+'.\nNo stock, payments or posted bills will change. back / cancel'

    def choose_offers(self,rows):
        if not 1<=len(rows)<=100: raise ValueError('For orders/drafts, send 1–100 items at a time.')
        items=self.inventory(self.uid)
        if self.state['mode']==10:
            party=self.state['party_name'].casefold()
            items=[i for i in items if i.get('user_id')==self.uid and party in (str(i.get('vendor') or '').casefold(),str(i.get('vendor_name') or '').casefold())]
        results=self.agent.match_rows(rows,items,False,self.frontend)
        choices=[];lines=['Choose one offer for EVERY demand item. Reply with offer numbers separated by spaces, e.g. 1 3.']
        for index,r in enumerate(results):
            d=r['demand'];qty=quantity(d)
            lines.append(f'\nItem {index+1}: {d["name"]} | Qty: {qty:g}')
            if not r['offers']: raise ValueError('No offer found for '+d['name']+'. Correct it and resend the full list.')
            for o in r['offers'][:10]:
                choices.append({'demand_index':index,'qty':qty,'item':o['item']})
                i=o['item'];disc=i.get('discount_pct',0) if self.state['mode']==9 else i.get('vendor_discount_pct')
                lines.append(f'{len(choices)}. {i["name"]} | TP {money(i.get("tp"))} | '+('Customer disc' if self.state['mode']==9 else 'Supplier disc')+f' {str(disc)+"%" if disc is not None else "missing"} | {i.get("vendor") or "unspecified"} | {o["status"]}'+(' — '+o.get('reason','') if o['status']=='review' else ''))
        self.set(dict(self.state,phase='offers',choices=choices,demand_count=len(rows)))
        return '\n'.join(lines)+'\nSelecting a REVIEW offer means you have verified its form, strength and pack. back / cancel'

    def reports(self,text):
        today=datetime.now(ZoneInfo('Asia/Karachi')).date()
        if text=='1': start,end=today,today
        elif text=='2': start,end=today-timedelta(days=6),today
        elif text=='3': start,end=today.replace(day=1),today
        else:
            try: start,end=[date.fromisoformat(s.strip()) for s in text.split(' to ')]
            except Exception: raise ValueError('Choose 1, 2, 3, or YYYY-MM-DD to YYYY-MM-DD.') from None
        if start>end or (end-start).days>366: raise ValueError('Choose an ordered date range of at most 366 days.')
        purchases=Purchase.query.filter(Purchase.user_id==self.uid,Purchase.purchase_date.between(start,end))
        sales,count=db.session.query(func.sum(Invoice.total),func.count(Invoice.id)).filter(Invoice.user_id==self.uid,Invoice.status.in_(['posted','finalised']),Invoice.invoice_date.between(start,end)).one()
        purchase_total= db.session.query(func.sum(Purchase.total_cost)).filter(Purchase.user_id==self.uid,Purchase.purchase_date.between(start,end)).scalar()
        receipts=db.session.query(func.sum(CustomerPayment.amount)).filter(CustomerPayment.user_id==self.uid,CustomerPayment.payment_date.between(start,end)).scalar()
        payments=db.session.query(func.sum(SupplierPayment.amount)).filter(SupplierPayment.user_id==self.uid,SupplierPayment.payment_date.between(start,end)).scalar()
        billing_paid=db.session.query(func.sum(Invoice.amount_paid)).filter(Invoice.user_id==self.uid,Invoice.status.in_(['posted','finalised']),Invoice.invoice_date.between(start,end)).scalar()
        return f'Report {start} to {end} (Pakistan dates)\nPosted sales: {money(sales)} ({count} bills)\nPurchases: {money(purchase_total)} ({purchases.count()} bills)\nCash at billing: {money(billing_paid)}\nCustomer payment entries: {money(receipts)}\nSupplier payment entries: {money(payments)}\nDraft/cancelled sales excluded.\nChoose another period or send menu.'

    def process(self,text='',rows=None):
        text=text.strip();command=text.lower()
        if rows is None and command in ('hi','hello','help','/help','start','menu','/menu','cancel'):
            self.state={};return self.done(('Task cancelled.\n' if command=='cancel' else '')+menu(self.user))
        if rows is None and command=='back':
            history=self.state.get('history',[])
            if not history: self.state={};return self.done(menu(self.user))
            self.state=dict(history[-1],history=history[:-1])
            return self.done(self.prompt())
        if not self.state and rows is None and command in [str(i) for i in range(1,11)]: return self.done(self.start(int(command)))
        mode=self.state.get('mode',1)
        if not permitted(self.user,mode): raise ValueError('Access disabled for this account. Send menu.')
        phase=self.state.get('phase','input')
        if phase=='confirm':
            if rows is not None or command!='confirm '+self.state['confirmation_id'][:6]: return self.done(self.prompt())
            if datetime.utcnow()>datetime.fromisoformat(self.state['expires']): self.state={};return self.done('Preview expired. Send menu to start again.')
            kind=self.state['kind'];payload=self.state['payload']
            if kind=='orders': answer=self.orders(payload['lines'])+'\nThese messages are for you to forward. Nothing was sent to suppliers.'
            else:
                validate_draft(self.uid,payload,kind)
                draft=WhatsAppDraft.query.filter_by(user_id=self.uid,confirmation_id=self.state['confirmation_id']).first()
                if not draft:
                    draft=WhatsAppDraft(user_id=self.uid,confirmation_id=self.state['confirmation_id'],kind=kind,payload=json.dumps(payload));db.session.add(draft);db.session.flush()
                answer=f'Preparation draft #{draft.id} saved. No stock or balances changed.\nReview and open in '+('Billing' if kind=='invoice' else 'Purchase')+f':\n{HOME}/whatsapp-drafts/{draft.id}\nSend menu for another task.'
            self.state={};return self.done(answer)
        if phase=='party':
            if rows is not None: raise ValueError('Select an account number first.')
            if command in ('next','previous'): return self.done(self.party_list(self.state['query'],self.state['page']+(1 if command=='next' else -1)))
            if self.state.get('numbering_version')!=3:
                return self.done('Numbering has been updated. Use the refreshed list below.\n'+self.party_list(self.state.get('query',''),self.state.get('page',0)))
            numbers=self.state['party_numbers'];number=int(text) if text.isdigit() else -1
            model=Supplier if mode in (7,10) else Customer
            if mode==9 and number==0: p=None
            elif 1<=number<=len(numbers):
                p=model.query.filter_by(user_id=self.uid,id=numbers[number-1],is_active=True).first()
                if not p: raise ValueError('Selected name no longer available.')
            elif number>=0: raise ValueError('Choose a number from 1 to '+str(len(numbers))+', or search by name/account code.')
            else:
                p=model.query.filter(model.user_id==self.uid,model.is_active.is_(True),func.lower(model.code)==text.lower()).first()
                if not p: return self.done(self.party_list(text))
            self.set(dict(self.state,party_id=p.id if p else None,party_name=p.name if p else 'Walk-in',phase='input'))
            if mode in (6,7): return self.done(self.party_options())
            return self.done('Selected '+self.state['party_name']+'. Send items with quantities, e.g. PANADOL TAB (10).\nback / cancel')
        if phase=='account':
            if command not in ('1','2','3'): return self.done(self.party_options())
            if command in ('1','3') and not (self.user.perm_purchases if mode==7 else self.user.perm_bill):
                raise ValueError(('Purchase' if mode==7 else 'Invoice')+' access disabled. You can still view payment history (2).')
            model=Supplier if mode==7 else Customer;p=model.query.filter_by(id=self.state['party_id'],user_id=self.uid,is_active=True).first()
            if not p: raise ValueError('Selected account no longer available.')
            self.set(dict(self.state,phase='ledger',section={'1':'bills','2':'payments','3':'statement'}[command]))
            return self.done(ledger(self.uid,p,mode==7,self.state['section']))
        if phase=='ledger': return self.done('Send back for account options, or menu.')
        if phase=='invoices':
            if command in ('next','previous'): return self.done(self.invoice_list(self.state['query'],self.state['page']+(1 if command=='next' else -1)))
            if text.isdigit():
                n=int(text)
                if not 1<=n<=len(self.state['choices']): raise ValueError('Choose a displayed invoice number.')
                iid=self.state['choices'][n-1]
            else:
                p=Invoice.query.filter(Invoice.user_id==self.uid,func.lower(Invoice.invoice_number)==text.lower(),Invoice.status!='deleted').first()
                if not p: return self.done(self.invoice_list(text))
                iid=p.id
            self.set(dict(self.state,invoice_id=iid));return self.done(self.invoice_info())
        if phase=='invoice':
            if command=='1': return self.done(self.pdf())
            if command=='2':
                if not permitted(self.user,4): raise ValueError('Item access is disabled.')
                p=self.invoice(self.state['invoice_id']);return self.done(self.preview({'lines':[l.to_dict() for l in p.lines]},'orders'))
            return self.done(self.invoice_info())
        if phase=='offers':
            try: indexes=[int(n)-1 for n in text.replace(',',' ').split()]
            except ValueError: raise ValueError('Reply with offer numbers separated by spaces.') from None
            choices=self.state['choices']
            if any(n<0 or n>=len(choices) for n in indexes): raise ValueError('Choose displayed offer numbers.')
            selected=[choices[n] for n in indexes]
            if len(selected)!=self.state['demand_count'] or len({c['demand_index'] for c in selected})!=len(selected): raise ValueError('Select exactly one offer for each demand item.')
            lines=[]
            for c in sorted(selected,key=lambda c:c['demand_index']):
                i=c['item'];disc=i.get('vendor_discount_pct')
                if disc is None and mode in (4,10): raise ValueError('Supplier discount is missing. Verify supplier terms in BillMate first.')
                lines.append(dict(item_id=i['id'],item_name=i['name'],item_code=i.get('code',''),qty=c['qty'],tp=i.get('tp',0),retail=i.get('retail_price',0),discount_pct=i.get('discount_pct',0) if mode==9 else disc,
                                  tax_pct=i.get('tax_pct',0),vendor=i.get('vendor',''),vendor_name=i.get('vendor_name',''),vendor_code=i.get('vendor_code',''),vendor_list_no=i.get('vendor_list_no',''),vendor_discount_pct=disc,bonus_text=''))
            payload={'lines':lines,'party_id':self.state.get('party_id'),'party_name':self.state.get('party_name','')}
            return self.done(self.preview(payload,{4:'orders',9:'invoice',10:'purchase'}[mode]))
        if mode==8: return self.done(self.reports(text))
        if mode in (6,7): return self.done(self.party_list())
        if mode==5: return self.done(self.invoice_list(text))
        if mode==4 and command.startswith('invoice '):
            if not self.user.perm_bill: raise ValueError('Invoice access disabled.')
            p=Invoice.query.filter(Invoice.user_id==self.uid,func.lower(Invoice.invoice_number)==text[8:].strip().lower(),Invoice.status!='deleted').first()
            if not p: raise ValueError('Invoice not found in your account.')
            return self.done(self.preview({'lines':[l.to_dict() for l in p.lines]},'orders'))
        if mode in (4,9,10): return self.done(self.choose_offers(rows if rows is not None else self.agent.parse_text(text,self.frontend)))
        if mode==2:
            if rows is not None or not text: raise ValueError('Send an item name as text for stock lookup.')
            items=Item.query.filter_by(user_id=self.uid,is_active=True).filter(Item.qty>0,Item.name.contains(text,autoescape=True)).order_by(Item.name).limit(51).all()
            return self.done('Own stock:\n'+('\n'.join(f'{i.name} | Qty: {float(i.qty):g} | TP: {money(i.tp)}' for i in items[:50]) or 'No stocked items found.')+ ('\nShowing first 50; narrow your search.' if len(items)>50 else '')+'\nSend another name or menu.')
        demands=rows if rows is not None else self.agent.parse_text(text,self.frontend)
        if not 1<=len(demands)<=2000: raise ValueError('Send 1–2,000 demand items.')
        results=self.agent.match_rows(demands,self.inventory(self.uid),self.agent_row.ignore_shelf,self.frontend)
        if mode==3:
            for r in results: r['offers'].sort(key=lambda o:float(o['item'].get('vendor_discount_pct') if o['item'].get('vendor_discount_pct') is not None else o['item'].get('discount_pct') or 0),reverse=True)
            for r in results:
                for o in r['offers']:
                    i=o['item'];i['discount_pct']=i.get('vendor_discount_pct') if i.get('vendor_discount_pct') is not None else i.get('discount_pct',0)
            return self.done('Supplier comparison — highest discount first; missing supplier terms use listed discount.\n'+self.agent.report(results))
        return self.done(self.agent.report(results))

    def prompt(self):
        phase=self.state.get('phase');mode=self.state.get('mode')
        if not mode: return menu(self.user)
        if phase=='party': return self.party_list(self.state.get('query',''),self.state.get('page',0))
        if phase=='account': return self.party_options()
        if phase=='invoices': return self.invoice_list(self.state.get('query',''),self.state.get('page',0))
        if phase=='invoice': return self.invoice_info()
        if phase=='confirm': return 'Reply confirm '+self.state['confirmation_id'][:6]+' to approve the preview, or back / cancel.'
        if phase=='offers': return 'Reply with one displayed offer number per demand item, or back / cancel.'
        return LABELS[mode-1]+': send '+('items with quantities.' if mode in (4,9,10) else 'your search or selection.')+' back / menu'


def re_filename(text):
    import re
    return re.sub(r'[^A-Za-z0-9_.-]','_',text)[:100] or 'invoice'


def quantity(demand):
    try: value=float(demand.get('qty') or '')
    except (ValueError,TypeError): raise ValueError('Specify a unit quantity for '+demand['name']+', e.g. ITEM TAB (10). Box/PCS quantities must be converted to your billing unit.') from None
    if not math.isfinite(value) or not 0<value<=100000: raise ValueError('Quantity must be positive and at most 100,000.')
    return value


def draft_summary(payload,kind):
    lines=[('Invoice' if kind=='invoice' else 'Purchase')+' preparation for '+payload['party_name']]
    total=0
    for i,l in enumerate(payload['lines'],1):
        net=round(l['qty']*float(l['tp'])*(1-float(l['discount_pct'] or 0)/100),2)+l['qty']*float(l['tax_pct'] or 0)
        total+=net
        lines.append(f'{i}. {l["item_name"]} | Qty {l["qty"]:g} | TP {money(l["tp"])} | Disc {l["discount_pct"]}% | Tax/unit {money(l["tax_pct"])} | Total {money(net)} | {l["vendor"]}')
    lines.append('Total: '+money(round(total,2)))
    return '\n'.join(lines)
