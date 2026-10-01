"""Private agent configuration and bounded, account-scoped Assistant processing."""
import base64
import hashlib
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

from flask import jsonify, render_template, request, session, abort
from cryptography.fernet import Fernet
from models import db, User, WhatsAppAgent, WhatsAppConversation, WhatsAppDraft
import whatsapp_chat

API = 'https://api.whatsapp.com/agent/v1'
MAX_BYTES = 8 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def cipher():
    key = os.environ.get('SECRET_KEY', '')
    if not key:
        raise ValueError('A stable server SECRET_KEY is required before saving an agent key.')
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(('billmate-whatsapp-v1:' + key).encode()).digest()))


def remote(token, endpoint, payload=None, raw=False):
    if endpoint.startswith('https://'):
        parsed = urlparse(endpoint)
        if parsed.hostname != 'lookaside.fbsbx.com' or parsed.username or parsed.password:
            raise ValueError('Unexpected WhatsApp attachment address.')
        url = endpoint
    else:
        url = API + endpoint
    headers = {'Authorization': 'Bearer ' + token}
    if isinstance(payload, dict):
        headers['Content-Type'] = 'application/json'
        payload = json.dumps(payload).encode()
    if isinstance(payload, tuple):
        payload, headers['Content-Type'] = payload
    req = Request(url, data=payload, headers=headers)
    try:
        with build_opener(NoRedirect()).open(req, timeout=12) as response:
            content = response.read(MAX_BYTES + 1)
            if len(content) > MAX_BYTES:
                raise ValueError('Attachment is too large. Maximum PDF size is 8 MB.')
            if raw:
                return content
            return json.loads(content) if content else {}
    except HTTPError as exc:
        # Do not put tokens, URLs or upstream bodies in responses or logs.
        raise RuntimeError(f'WhatsApp connection failed ({exc.code}). Check the agent key or retry.') from None


def js_context(frontend):
    import quickjs
    context = quickjs.Context()
    context.set_memory_limit(96 * 1024 * 1024)
    context.set_time_limit(15)
    for filename in ('demand-text-parser.js', 'demand-matcher.js'):
        context.eval((Path(frontend) / 'static' / 'js' / filename).read_text())
    return context


def parse_text(text, frontend):
    context = js_context(frontend)
    try:
        return json.loads(context.eval('JSON.stringify(DemandTextParser.parse(' + json.dumps(text) + '))'))
    except Exception:
        raise ValueError('Could not read demand items. Send one item per line, with quantity like PANADOL TAB (2).') from None


def match_rows(rows, items, ignore, frontend):
    context = js_context(frontend)
    context.eval('const demands=' + json.dumps(rows) + '; const stock=' + json.dumps(items) + ';')
    option = 'true' if ignore else 'false'
    return json.loads(context.eval(f'const prepared=DemandMatcher.prepare(stock,{option}); JSON.stringify(demands.map(d=>DemandMatcher.match(d,prepared,{option})))'))


def html_rows(text):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(text, 'html.parser')
    rows = []
    for table in soup.find_all('table'):
        columns = None
        for tr in table.find_all('tr'):
            if tr.find_parent('table') != table:
                continue
            cells = tr.find_all(['td', 'th'], recursive=False)
            values = [' '.join(c.get_text(' ', strip=True).split()) for c in cells]
            headers = [v.lower() for v in values]
            name = next((i for i, v in enumerate(headers) if re.fullmatch(r'item\s*name|product\s*name|description|item|product', v)), -1)
            if name >= 0:
                columns = {'name': name, 'box': headers.index('box') if 'box' in headers else -1, 'pcs': headers.index('pcs') if 'pcs' in headers else -1}
                continue
            if not columns or len(values) <= columns['name'] or any(c.find(['table', 'input', 'button', 'select']) for c in cells):
                continue
            item = values[columns['name']]
            if not re.search('[a-z]', item, re.I) or re.match(r'^(total|grand total|sub total)\b', item, re.I):
                continue
            read = lambda key: values[columns[key]] if 0 <= columns[key] < len(values) else ''
            rows.append({'name': item, 'qty': '', 'box': read('box'), 'pcs': read('pcs')})
    if not rows or len(rows) > 2000:
        raise ValueError('Send an HTML demand table with Item Name and at most 2,000 items.')
    return rows


def document_rows(message, token, frontend, parse_pdf_table):
    document = message.get('document') or {}
    filename = str(document.get('filename') or '').lower()
    if not re.search(r'\.(txt|pdf|html?)$', filename):
        raise ValueError('Send a TXT, PDF or HTM/HTML demand file.')
    media = remote(token, '/media/' + quote(str(document.get('id') or ''), safe=''))
    content = remote(token, media['url'], raw=True)
    if filename.endswith('.pdf'):
        from PyPDF2 import PdfReader
        try:
            reader = PdfReader(io.BytesIO(content))
            if len(reader.pages) > 100:
                raise ValueError('PDF exceeds 100 pages.')
            texts = [p.extract_text() or '' for p in reader.pages]
            rows = [r for text in texts for r in parse_pdf_table(text)]
        except Exception:
            raise ValueError('Could not read this PDF. Send a selectable-text PDF under 100 pages.') from None
        return rows or parse_text('\n'.join(texts), frontend)
    if len(content) > 4 * 1024 * 1024:
        raise ValueError('Maximum TXT or HTML size is 4 MB.')
    text = content.decode('utf-8-sig', errors='replace')
    return html_rows(text) if filename.endswith(('.htm', '.html')) else parse_text(text, frontend)


def report(results):
    lines = [f'BillMate Demand Search: {len(results)} items.',
             'Matched: %s; Review: %s; Missing: %s.' % tuple(sum(r['status'] == kind for r in results) for kind in ('match', 'review', 'missing')),
             'Review offers need verification. No stock or bills changed.', '']
    for index, result in enumerate(results, 1):
        d = result['demand']
        qty = ' / '.join(str(v) for v in (d.get('qty'), d.get('box') and str(d['box']) + ' box', d.get('pcs') and str(d['pcs']) + ' pcs') if v) or 'unspecified'
        lines.append(f"{index}. {d['name']} | Qty: {qty}")
        if not result['offers']:
            lines.append('MISSING')
        for offer in result['offers']:
            item = offer['item']
            lines.append(f"{offer['status'].upper()} | {item['name']} | TP: {item.get('tp')} | Discount: {item.get('discount_pct')}% | Vendor: {item.get('vendor') or 'unspecified'}")
            if offer['status'] == 'review':
                lines.append('Check: ' + offer['reason'])
        lines.append('')
    return '\n'.join(lines)


def reply(token, recipient, text):
    if not isinstance(recipient, str) or not recipient.startswith('user:'):
        raise ValueError('Invalid agent recipient.')
    message = {'messaging_product': 'whatsapp', 'to': recipient}
    attachment = text if isinstance(text, dict) else None
    if attachment:
        text = attachment['text']
    if not attachment and len(text) <= 4000:
        message.update(type='text', text={'body': text})
    else:
        boundary = secrets.token_hex(16)
        mime = attachment['mime'] if attachment else 'text/plain'
        filename = attachment['filename'] if attachment else 'BillMate-results.txt'
        content = attachment['file'] if attachment else text.encode()
        if len(content) > MAX_BYTES:
            raise ValueError('Result attachment exceeds 8 MB. Use BillMate to download it.')
        fields = [('messaging_product', 'whatsapp'), ('type', mime)]
        body = b''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode() for name, value in fields)
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: {mime}\r\n\r\n'.encode()
        body += content + f'\r\n--{boundary}--\r\n'.encode()
        media = remote(token, '/media', (body, 'multipart/form-data; boundary=' + boundary))
        message.update(type='document', document={'id': media['id'], 'filename': filename, 'caption': '\n'.join(text.splitlines()[:3])[:1024]})
    remote(token, '/messages', message)


def install(app, frontend, inventory, parse_pdf_table):
    def ensure():
        WhatsAppAgent.__table__.create(db.engine, checkfirst=True)
        whatsapp_chat.ensure()

    def draft_access(did):
        ensure()
        uid = session.get('user_id')
        user = db.session.get(User, uid) if uid and not session.get('is_guest') else None
        if not user or user.is_suspended:
            abort(403)
        draft = WhatsAppDraft.query.filter_by(id=did, user_id=uid).first_or_404()
        if not whatsapp_chat.permitted(user, 9 if draft.kind == 'invoice' else 10):
            abort(403)
        try:
            whatsapp_chat.validate_draft(uid,json.loads(draft.payload),draft.kind)
        except ValueError as error:
            abort(409,description=str(error))
        return draft

    @app.route('/whatsapp-drafts/<int:did>')
    def agent_draft_page(did):
        draft = draft_access(did)
        payload = json.loads(draft.payload)
        response = app.make_response(render_template('whatsapp_draft.html', draft=draft, payload=payload,
                               summary=whatsapp_chat.draft_summary(payload,draft.kind)))
        response.headers['Cache-Control']='no-store'
        return response

    @app.route('/api/whatsapp-agent/drafts/<int:did>')
    def agent_draft_data(did):
        draft = draft_access(did)
        payload=json.loads(draft.payload)
        from models import Item
        owned={i.id:float(i.qty or 0) for i in Item.query.filter(Item.user_id==draft.user_id,Item.id.in_([l['item_id'] for l in payload['lines']])).all()}
        for line in payload['lines']:
            line['current_stock']=owned.get(line['item_id'],0)
        response = jsonify(id=draft.id,kind=draft.kind,payload=payload)
        response.headers['Cache-Control']='no-store'
        return response

    def admin():
        if not session.get('user_id') or session.get('is_guest') or not session.get('is_admin'):
            return jsonify(error='Unlock Admin to configure your agent.'), 403
        user = db.session.get(User, session['user_id'])
        if not user or user.is_suspended or not user.perm_items:
            return jsonify(error='Inventory access is required.'), 403
        ensure()
        if request.method != 'GET' and not secrets.compare_digest(request.headers.get('X-Agent-CSRF', ''), session.get('agent_csrf') or 'missing'):
            return jsonify(error='Reload the setup page and retry.'), 403

    def state(row):
        return {'configured': bool(row), 'last_poll': row.last_poll.isoformat() + 'Z' if row and row.last_poll else None,
                'last_result': row.last_result if row else None, 'ignore_shelf': bool(row and row.ignore_shelf),
                'runner_configured': bool(row and row.runner_hash)}

    @app.route('/admin/whatsapp-agent')
    def agent_page():
        denied = admin()
        if denied:
            return denied
        session['agent_csrf'] = secrets.token_urlsafe(24)
        return render_template('admin/whatsapp_agent.html', agent_csrf=session['agent_csrf'])

    @app.route('/api/whatsapp-agent', methods=['GET', 'POST', 'DELETE'])
    def agent_setup():
        denied = admin()
        if denied:
            return denied
        uid = session['user_id']
        row = db.session.get(WhatsAppAgent, uid)
        if request.method == 'GET':
            response = jsonify(state(row)); response.headers['Cache-Control'] = 'no-store'; return response
        if row and row.lease_until and row.lease_until > datetime.utcnow():
            return jsonify(error='Agent is processing a message. Retry shortly.'), 409
        if request.method == 'DELETE':
            if row:
                WhatsAppConversation.query.filter_by(user_id=uid).delete()
                db.session.delete(row); db.session.commit()
            return jsonify(configured=False)
        data = request.get_json(silent=True) or {}
        key = str(data.get('key') or '').strip()
        if not key or len(key) > 8192 or re.search(r'\s', key):
            return jsonify(error='Paste the complete API key.'), 400
        try:
            encrypted = cipher().encrypt(key.encode()).decode()
            # Verify access without replaying old messages when a key is first saved.
            update = remote(key, '/updates?limit=1&timeout=0')
            # A valid poll with no queued updates can return HTTP 204 / no body.
            offset = update.get('next_offset', 0) if not update or update.get('object') == 'whatsapp_agent_platform' else update.get('next_offset')
            if not isinstance(offset, int) or offset < 0:
                raise ValueError('WhatsApp did not return a valid connection response. Retry.')
        except (RuntimeError, ValueError) as error:
            return jsonify(error=str(error)), 400
        except Exception:
            return jsonify(error='Could not connect to WhatsApp. Retry shortly.'), 502
        if not row:
            row = WhatsAppAgent(user_id=uid); db.session.add(row)
        row.encrypted_key = encrypted; row.offset = offset; row.handled = '[]'
        row.runner_hash = None; row.last_poll = None
        row.ignore_shelf = data.get('ignore_shelf') is True
        row.last_result = 'Key verified. Listener has not started.'
        WhatsAppConversation.query.filter_by(user_id=uid).delete()
        db.session.commit()
        return jsonify(state(row))

    @app.route('/api/whatsapp-agent/runner-token', methods=['POST'])
    def agent_runner_token():
        denied = admin()
        if denied:
            return denied
        row = db.session.get(WhatsAppAgent, session['user_id'])
        if not row:
            return jsonify(error='Save an agent key first.'), 400
        token = secrets.token_urlsafe(32)
        row.runner_hash = hashlib.sha256(token.encode()).hexdigest(); db.session.commit()
        response = jsonify(token=token, path=f'/api/whatsapp-agent/runner/{row.user_id}')
        response.headers['Cache-Control'] = 'no-store'; return response

    def poll(uid):
        user = db.session.get(User, uid)
        if not user or user.is_suspended or not user.perm_items:
            return jsonify(error='Account or inventory access unavailable.'), 403
        now = datetime.utcnow()
        acquired = WhatsAppAgent.query.filter(WhatsAppAgent.user_id == uid, db.or_(WhatsAppAgent.lease_until.is_(None), WhatsAppAgent.lease_until < now)).update({'lease_until': now + timedelta(seconds=120)}, synchronize_session=False)
        db.session.commit()
        if not acquired:
            return jsonify(busy=True), 409
        row = db.session.get(WhatsAppAgent, uid)
        try:
            if row.last_poll and (now - row.last_poll).total_seconds() < 5.2:
                return jsonify(busy=True), 429
            token = cipher().decrypt(row.encrypted_key.encode()).decode()
            update = remote(token, f'/updates?offset={row.offset}&limit=1&timeout=0')
            row.last_poll = now; db.session.commit()
            handled = json.loads(row.handled)
            for entry in update.get('entry', []):
                for change in entry.get('changes', []):
                    for message in change.get('value', {}).get('messages', []):
                        if message.get('id') in handled:
                            continue
                        try:
                            chat = whatsapp_chat.Chat(app,frontend,inventory,__import__(__name__),uid,message.get('from'))
                            chat.agent_row = row
                            if message.get('type') == 'text':
                                text = message.get('text', {}).get('body', '')
                                answer = chat.process(text)
                            elif message.get('type') == 'document':
                                rows = document_rows(message, token, frontend, parse_pdf_table)
                                answer = chat.process(rows=rows)
                            else:
                                raise ValueError('Send menu, an item list, or a TXT/PDF/HTM demand document.')
                        except ValueError as error:
                            answer = str(error)
                        reply(token, message.get('from'), answer)
                        row.last_result = (answer['text'] if isinstance(answer,dict) else answer).splitlines()[0][:200]
                        handled.append(message['id']); row.handled = json.dumps(handled[-500:]); db.session.commit()
            if isinstance(update.get('next_offset'), int) and update['next_offset'] >= row.offset:
                row.offset = update['next_offset']
            db.session.commit()
            return jsonify(state(row))
        except Exception:
            db.session.rollback()
            # Retain offset so a failed download/search/delivery can be retried.
            return jsonify(error='Agent processing failed. Check the key and retry. The message remains pending.'), 502
        finally:
            WhatsAppAgent.query.filter_by(user_id=uid).update({'lease_until': None}, synchronize_session=False)
            db.session.commit()

    @app.route('/api/whatsapp-agent/poll', methods=['POST'])
    def agent_poll():
        denied = admin()
        if denied:
            return denied
        if not db.session.get(WhatsAppAgent, session['user_id']):
            return jsonify(error='Save an agent key first.'), 400
        return poll(session['user_id'])

    @app.route('/api/whatsapp-agent/runner/<int:uid>', methods=['POST'])
    def agent_runner(uid):
        ensure()
        row = db.session.get(WhatsAppAgent, uid)
        bearer = request.headers.get('Authorization', '')
        actual = hashlib.sha256(bearer[7:].encode()).hexdigest() if bearer.startswith('Bearer ') else ''
        if not row or not row.runner_hash or not secrets.compare_digest(actual, row.runner_hash):
            return jsonify(error='Unauthorized'), 401
        return poll(uid)
