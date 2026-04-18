import os
import sys

# Ensure backend/ is on the path so `models` can be imported on Vercel
base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from flask import Flask, render_template, request, jsonify, redirect, session, url_for
from bs4 import BeautifulSoup
import re
import secrets
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_migrate import Migrate
from datetime import date, datetime, timedelta
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

project_dir = os.path.dirname(base_dir)  # billing_system/
load_dotenv(os.path.join(project_dir, '.env'))

# Support both local (project_dir/frontend) and Vercel (base_dir/frontend) layouts
_frontend = os.path.join(project_dir, 'frontend')
if not os.path.isdir(_frontend):
    _frontend = os.path.join(base_dir, 'frontend')

app = Flask(__name__,
    template_folder=os.path.join(_frontend, 'templates'),
    static_folder=os.path.join(_frontend, 'static'),
    static_url_path='/static'
)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
_secret = os.environ.get('SECRET_KEY', '')
if not _secret:
    import secrets as _secrets
    _secret = _secrets.token_hex(32)
app.secret_key = _secret
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = 600  # 10 minutes (frontend enforces 5-min idle logout)

# Database — must be set via DATABASE_URL environment variable
_db_url = os.environ.get('DATABASE_URL', '')
if not _db_url:
    raise RuntimeError('DATABASE_URL environment variable is not set')
# SQLAlchemy requires postgresql:// not postgres://
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Serverless-safe pool config: pre-ping drops stale connections, recycle prevents timeouts
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 5,
    'max_overflow': 2,
    'connect_args': {'connect_timeout': 10},
}
from models import db, Settings, Category, Item, Customer, Invoice, InvoiceLine, Supplier, Purchase, PurchaseLine, User, GuestLimit, UserItemDiscount, UserItemOverride, PasswordResetRequest, UserIPLog, SystemConfig, CustomerPayment, SupplierPayment
db.init_app(app)
migrate = Migrate(app, db)

# ── Auth helpers ───────────────────────────────────────────────────────────────

GUEST_ALLOWED_PREFIXES = ['/billing', '/items', '/api/invoices', '/api/items',
                           '/api/settings', '/api/guest/', '/static']

def get_client_ip():
    # On Vercel, X-Vercel-Forwarded-For is set by the edge and cannot be spoofed by clients.
    # Fall back to the rightmost entry in X-Forwarded-For (last untrusted hop),
    # then to remote_addr. Taking the rightmost prevents header injection attacks.
    vercel_ip = request.headers.get('X-Vercel-Forwarded-For', '').strip()
    if vercel_ip:
        return vercel_ip.split(',')[-1].strip()
    xff = request.headers.get('X-Forwarded-For', '').strip()
    if xff:
        return xff.split(',')[-1].strip()
    return request.remote_addr

# ── IP logging ──────────────────────────────────────────────────────────────────
# In-memory cache: (user_id, ip, date_str) → already written to DB this day.
# Avoids a DB hit on every request; resets on app restart (harmless — just
# re-writes last_seen_at for the first request after restart).
_ip_log_cache: set = set()
_reset_attempts = {'count': 0, 'locked_until': None}  # superadmin forgot-password rate limit

# Per-IP login rate limiting (in-memory; resets on restart — intentional for serverless)
_login_attempts: dict = {}  # ip -> {'count': int, 'locked_until': datetime|None}
_DUMMY_HASH = generate_password_hash('__dummy_never_matches__')  # for constant-time checks

def _login_rate_check(ip: str, max_attempts: int = 10, lockout_min: int = 15):
    """Returns (allowed: bool, wait_seconds: int)."""
    now = datetime.utcnow()
    rec = _login_attempts.get(ip, {'count': 0, 'locked_until': None})
    if rec['locked_until']:
        if now < rec['locked_until']:
            return False, int((rec['locked_until'] - now).total_seconds())
        rec = {'count': 0, 'locked_until': None}
        _login_attempts[ip] = rec
    return True, 0

def _login_rate_fail(ip: str, max_attempts: int = 10, lockout_min: int = 15):
    now = datetime.utcnow()
    rec = _login_attempts.get(ip, {'count': 0, 'locked_until': None})
    if not rec['locked_until']:
        rec['count'] += 1
        if rec['count'] >= max_attempts:
            rec['locked_until'] = now + timedelta(minutes=lockout_min)
    _login_attempts[ip] = rec

def _login_rate_clear(ip: str):
    _login_attempts.pop(ip, None)

def _log_user_ip(uid: int, username: str, ip: str):
    today = datetime.utcnow().date()
    key = (uid, ip, str(today))
    if key in _ip_log_cache:
        return
    _ip_log_cache.add(key)
    try:
        existing = UserIPLog.query.filter_by(user_id=uid, ip_address=ip, log_date=today).first()
        if existing:
            existing.last_seen_at = datetime.utcnow()
            existing.request_count = (existing.request_count or 0) + 1
        else:
            db.session.add(UserIPLog(
                user_id=uid, username=username,
                ip_address=ip, log_date=today,
            ))
            # Purge entries older than 5 days (only on new-entry path to keep it cheap)
            cutoff = datetime.utcnow() - timedelta(days=5)
            UserIPLog.query.filter(UserIPLog.first_seen_at < cutoff).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        _ip_log_cache.discard(key)

_defaults_seeded = False
@app.before_request
def seed_defaults():
    global _defaults_seeded
    if not _defaults_seeded:
        _defaults_seeded = True
        for key in ('registration_open', 'invoicing_open'):
            if not SystemConfig.query.get(key):
                db.session.add(SystemConfig(key=key, value='1'))
        # Auto-add API key columns if missing (no manual migration needed)
        try:
            from sqlalchemy import text
            db.session.execute(text("ALTER TABLE settings ADD COLUMN IF NOT EXISTS groq_api_key VARCHAR(200)"))
            db.session.execute(text("ALTER TABLE settings ADD COLUMN IF NOT EXISTS gemini_api_key VARCHAR(200)"))
            db.session.commit()
        except Exception:
            db.session.rollback()

@app.before_request
def record_ip():
    uid = session.get('user_id') or session.get('superadmin_uid')
    username = session.get('username')
    if uid and username and not session.get('is_guest'):
        _log_user_ip(int(uid), username, get_client_ip())

def get_user_settings(user_id=None):
    """Get settings for the current user. Returns None if no settings exist."""
    uid = user_id or session.get('user_id')
    if not uid:
        return None
    return Settings.query.filter_by(user_id=uid).first()

def get_or_create_user_settings(user_id=None):
    """Get or create settings for the current user."""
    uid = user_id or session.get('user_id')
    if not uid:
        return None
    s = Settings.query.filter_by(user_id=uid).first()
    if not s:
        s = Settings(user_id=uid, shop_name='')
        db.session.add(s)
        db.session.flush()
    return s

@app.before_request
def check_auth():
    session.permanent = True
    path = request.path
    # Always allow auth routes, static, and public API
    if path.startswith('/auth') or path.startswith('/static') or path == '/':
        return
    if path == '/api/forgot-password-request':
        return
    # Superadmin login page + public recovery endpoints — always accessible
    if path == '/superadmin/login':
        return
    if path in ('/api/superadmin/recovery-hint', '/api/superadmin/forgot-password', '/api/superadmin/verify-reset-code'):
        return
    # Superadmin — only their own panel + global items API
    if session.get('is_superadmin'):
        allowed_api = ('/superadmin', '/api/superadmin', '/api/items', '/api/categories', '/api/forgot-password-request')
        if any(path.startswith(p) for p in allowed_api):
            return
        return redirect('/superadmin/users')
    # Allow admin unlock and forgot password pages
    if path in ('/admin/unlock', '/admin/forgot-password'):
        return
    user_id = session.get('user_id')
    is_guest = session.get('is_guest')
    # Not logged in at all → welcome
    if not user_id and not is_guest:
        if request.is_json:
            return jsonify({'error': 'Unauthorized'}), 401
        return redirect('/')
    # Guest restrictions
    if is_guest:
        allowed = any(path.startswith(p) for p in GUEST_ALLOWED_PREFIXES)
        if not allowed:
            if request.is_json:
                return jsonify({'error': 'Registered accounts only'}), 403
            return render_template('guest_denied.html')
    # Suspension check — suspended users see locked page on every route
    if user_id:
        _u = User.query.get(user_id)
        if _u and _u.is_suspended:
            if request.is_json:
                return jsonify({'error': 'Your account has been suspended'}), 403
            return render_template('suspended.html')
    # Clear admin access when leaving admin pages
    if not path.startswith('/admin') and not path.startswith('/api'):
        session.pop('is_admin', None)

    # Setup completion check — restrict access until setup is done
    if user_id and not is_guest:
        s = get_user_settings()
        setup_done = s and s.shop_name and s.address and s.phone and s.whatsapp
        if not setup_done:
            # Auto-grant admin for setup page access
            if path.startswith('/admin/setup'):
                session['is_admin'] = True
            # Allow: billing page, api/settings, api/invoices (create/view only), admin/setup
            setup_allowed = ['/billing', '/api/settings', '/api/invoices', '/api/items',
                             '/api/customers', '/api/categories', '/admin/setup',
                             '/admin/unlock', '/admin/forgot-password', '/api/change-login-password',
                             '/api/change-admin-password']
            if not any(path.startswith(p) or path == p for p in setup_allowed):
                if request.is_json:
                    return jsonify({'error': 'Please complete shop setup first'}), 403
                return render_template('setup_required.html')

    # Admin section requires admin session
    if path.startswith('/admin'):
        if not session.get('is_admin'):
            # Registered users (non-guest) → auto-grant admin if no admin password set
            s = get_user_settings()
            if not s or not s.admin_password_hash:
                session['is_admin'] = True
            elif session.get('user_id'):
                # Registered user must unlock admin once per session
                return redirect('/admin/unlock')
            else:
                return redirect('/?denied=1')


# ── Keep-alive ────────────────────────────────────────────────────────────────

@app.route('/api/keepalive', methods=['GET'])
def keepalive():
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'detail': str(e)}), 500

# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if session.get('is_superadmin'):
        return redirect('/superadmin/users')
    if session.get('user_id') or session.get('is_guest'):
        return redirect('/billing')
    return render_template('welcome.html', denied=request.args.get('denied'))

@app.route('/admin/login', methods=['GET'])
def admin_login_page():
    # If already logged in as admin, redirect to admin dashboard
    if session.get('is_admin'):
        return redirect('/admin/sales')
    return render_template('admin/login.html')

# ── Auth routes ────────────────────────────────────────────────────────────────

@app.route('/auth/guest')
def auth_guest():
    session.clear()
    session.permanent = True
    session['is_guest'] = True
    return redirect('/billing')

@app.route('/auth/register', methods=['POST'])
def auth_register():
    ip = get_client_ip()
    # 5 registrations per IP per 24 hours prevents spam account creation
    allowed, wait = _login_rate_check(ip, max_attempts=5, lockout_min=1440)
    if not allowed:
        return jsonify({'error': f'Too many registrations from this IP. Try again in {wait//3600+1} hours.'}), 429
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    if _cfg('registration_open', '1') == '0':
        return jsonify({'error': 'New registrations are currently closed by the administrator.'}), 403
    if username.lower() == 'admin':
        return jsonify({'error': 'Username not available'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.flush()  # get user.id

    # Create per-user settings
    s = Settings(user_id=user.id, shop_name='')
    db.session.add(s)

    # Set admin password if provided during registration
    admin_password = (data.get('admin_password') or '').strip()
    if admin_password:
        s.admin_password_hash = generate_password_hash(admin_password)

    db.session.commit()
    session.clear()
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    # New user always needs setup
    session['is_admin'] = True  # auto-grant admin for initial setup
    _login_rate_fail(ip, max_attempts=5, lockout_min=1440)  # count each registration toward the limit
    return jsonify({'success': True, 'needs_setup': True})

@app.route('/auth/login', methods=['POST'])
def auth_login():
    ip = get_client_ip()
    allowed, wait = _login_rate_check(ip, max_attempts=10, lockout_min=15)
    if not allowed:
        return jsonify({'error': f'Too many failed attempts. Try again in {wait//60+1} minutes.'}), 429
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    user = User.query.filter_by(username=username).first()
    # Always run check_password_hash to prevent timing-based username enumeration
    hash_to_check = user.password_hash if user else _DUMMY_HASH
    password_valid = check_password_hash(hash_to_check, password)
    if not user or not password_valid:
        _login_rate_fail(ip, max_attempts=10, lockout_min=15)
        return jsonify({'error': 'Invalid username or password'}), 401
    if user.is_suspended:
        return jsonify({'error': 'Account suspended. Contact your administrator.'}), 403
    _login_rate_clear(ip)
    if user.is_superadmin:
        session.clear()
        session.permanent = True
        session['is_superadmin'] = True
        session['superadmin_uid'] = user.id
        session['username'] = user.username
        return jsonify({'success': True, 'redirect': '/superadmin/users'})
    session.clear()
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({'success': True})

@app.route('/auth/admin-login', methods=['POST'])
def auth_admin_login():
    ip = get_client_ip()
    allowed, wait = _login_rate_check(ip, max_attempts=10, lockout_min=15)
    if not allowed:
        return jsonify({'error': f'Too many failed attempts. Try again in {wait//60+1} minutes.'}), 429
    data = request.get_json()
    password = (data.get('password') or '').strip()
    s = get_user_settings()
    if not s or not s.admin_password_hash:
        return jsonify({'error': 'Admin password not set'}), 401
    if check_password_hash(s.admin_password_hash, password):
        _login_rate_clear(ip)
        session['is_admin'] = True  # intentionally additive — preserves user_id/username
        return jsonify({'success': True})
    _login_rate_fail(ip, max_attempts=10, lockout_min=15)
    return jsonify({'error': 'Invalid admin password'}), 401

@app.route('/auth/logout')
def auth_logout():
    session.clear()
    return redirect('/')

@app.route('/auth/superadmin-login', methods=['POST'])
def auth_superadmin_login():
    ip = get_client_ip()
    allowed, wait = _login_rate_check(ip, max_attempts=5, lockout_min=30)
    if not allowed:
        return jsonify({'error': f'Too many failed attempts. Try again in {wait//60+1} minutes.'}), 429
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    user = User.query.filter_by(username=username, is_superadmin=True).first()
    # Always hash-check to prevent timing attack even when user not found
    hash_to_check = user.password_hash if user else _DUMMY_HASH
    password_ok = user and check_password_hash(hash_to_check, password)
    code_ok = (
        not password_ok
        and user
        and user.reset_code_hash
        and user.reset_code_expiry
        and datetime.utcnow() <= user.reset_code_expiry
        and check_password_hash(user.reset_code_hash, password)
    )
    if not password_ok and not code_ok:
        _login_rate_fail(ip, max_attempts=5, lockout_min=30)
        return jsonify({'error': 'Invalid super admin credentials'}), 401
    _login_rate_clear(ip)
    session.clear()
    session.permanent = True
    session['is_superadmin'] = True
    session['superadmin_uid'] = user.id
    session['username'] = user.username
    return jsonify({'success': True})

# ── Super Admin Pages & API ───────────────────────────────────────────────────

@app.route('/superadmin/login')
def superadmin_login_page():
    if session.get('is_superadmin'):
        return redirect('/superadmin/users')
    return render_template('superadmin/login.html')

@app.route('/superadmin/users')
def superadmin_users_page():
    return render_template('superadmin/users.html')

@app.route('/superadmin/items')
def superadmin_items_page():
    return render_template('superadmin/items.html')

@app.route('/api/superadmin/users')
def superadmin_get_users():
    search = (request.args.get('search') or '').strip()
    q = User.query.filter_by(is_superadmin=False)
    if search:
        q = q.filter(User.username.ilike('%' + search + '%'))
    users = q.order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        s = Settings.query.filter_by(user_id=u.id).first()
        inv_count = Invoice.query.filter_by(user_id=u.id).count()
        item_count = Item.query.filter_by(user_id=u.id).count()
        admin_locked = bool(s and s.admin_locked_until and datetime.utcnow() < s.admin_locked_until)
        result.append({
            'id': u.id,
            'username': u.username,
            'shop_name': (s.shop_name if s else '') or '',
            'phone': (s.phone if s else '') or '',
            'whatsapp': (s.whatsapp if s else '') or '',
            'address': (s.address if s else '') or '',
            'invoice_count': inv_count,
            'item_count': item_count,
            'setup_done': bool(s and s.shop_name and s.address and s.phone),
            'is_suspended': bool(u.is_suspended),
            'admin_locked': admin_locked,
            'created_at': u.created_at.strftime('%Y-%m-%d') if u.created_at else '',
        })
    return jsonify({'users': result, 'total': len(result)})

@app.route('/api/superadmin/users/<int:uid>/reset-password', methods=['POST'])
def superadmin_reset_password(uid):
    data = request.get_json()
    new_pwd = (data.get('new_password') or '').strip()
    if not new_pwd or len(new_pwd) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    user.password_hash = generate_password_hash(new_pwd)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/users/<int:uid>', methods=['DELETE'])
def superadmin_delete_user(uid):
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    # Delete all cascading data
    for inv in Invoice.query.filter_by(user_id=uid).all():
        db.session.delete(inv)
    for pur in Purchase.query.filter_by(user_id=uid).all():
        db.session.delete(pur)
    UserItemDiscount.query.filter_by(user_id=uid).delete()
    Item.query.filter_by(user_id=uid).delete()
    Customer.query.filter_by(user_id=uid).delete()
    Supplier.query.filter_by(user_id=uid).delete()
    Settings.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/users/<int:uid>/clear-data', methods=['DELETE'])
def superadmin_clear_user_data(uid):
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    data = request.get_json() or {}
    targets = data.get('targets', [])
    if not targets:
        return jsonify({'error': 'No data types selected'}), 400
    if 'invoices' in targets:
        for inv in Invoice.query.filter_by(user_id=uid).all():
            db.session.delete(inv)
    if 'purchases' in targets:
        for pur in Purchase.query.filter_by(user_id=uid).all():
            db.session.delete(pur)
    if 'items' in targets:
        UserItemDiscount.query.filter_by(user_id=uid).delete()
        Item.query.filter_by(user_id=uid).delete()
    if 'customers' in targets:
        Customer.query.filter_by(user_id=uid).delete()
    if 'suppliers' in targets:
        Supplier.query.filter_by(user_id=uid).delete()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/users/<int:uid>/suspend', methods=['POST'])
def superadmin_suspend_user(uid):
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    user.is_suspended = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/users/<int:uid>/unsuspend', methods=['POST'])
def superadmin_unsuspend_user(uid):
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    user.is_suspended = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/users/<int:uid>/unlock-admin', methods=['POST'])
def superadmin_unlock_admin(uid):
    user = User.query.get(uid)
    if not user or user.is_superadmin:
        return jsonify({'error': 'User not found'}), 404
    s = Settings.query.filter_by(user_id=uid).first()
    if not s:
        return jsonify({'error': 'No settings found for this user'}), 404
    data = request.get_json() or {}
    new_pwd = (data.get('new_password') or '').strip()
    if not new_pwd or len(new_pwd) < 4:
        return jsonify({'error': 'New admin password must be at least 4 characters'}), 400
    s.admin_password_hash = generate_password_hash(new_pwd)
    s.admin_password_is_temp = True
    s.admin_locked_until = None
    s.admin_failed_attempts = 0
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/change-own-password', methods=['POST'])
def superadmin_change_own_password():
    data = request.get_json()
    new_pwd = (data.get('new_password') or '').strip()
    if not new_pwd or len(new_pwd) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    uid = session.get('superadmin_uid')
    user = User.query.get(uid)
    if not user or not user.is_superadmin:
        return jsonify({'error': 'Not found'}), 404
    user.password_hash = generate_password_hash(new_pwd)
    db.session.commit()
    return jsonify({'success': True})

# ── Superadmin recovery email management (requires SA session) ────────────────

@app.route('/api/superadmin/set-recovery-email', methods=['POST'])
def superadmin_set_recovery_email():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    email = (request.get_json() or {}).get('email', '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    user = User.query.get(session['superadmin_uid'])
    user.recovery_email = email
    db.session.commit()
    return jsonify({'success': True, 'masked': _mask_email(email)})

@app.route('/api/superadmin/get-recovery-email')
def superadmin_get_recovery_email():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    user = User.query.get(session['superadmin_uid'])
    return jsonify({'email': user.recovery_email or '', 'masked': _mask_email(user.recovery_email) if user.recovery_email else ''})

# ── System config helpers ─────────────────────────────────────────────────────

def _cfg(key, default='1'):
    row = SystemConfig.query.get(key)
    return row.value if row else default

def _cfg_set(key, value):
    row = SystemConfig.query.get(key)
    if row:
        row.value = value
    else:
        db.session.add(SystemConfig(key=key, value=value))
    db.session.commit()

@app.route('/api/superadmin/system-config', methods=['GET'])
def get_system_config():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    return jsonify({
        'registration_open': _cfg('registration_open', '1') == '1',
        'invoicing_open':    _cfg('invoicing_open',    '1') == '1',
    })

@app.route('/api/superadmin/system-config', methods=['POST'])
def set_system_config():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    data = request.get_json() or {}
    if 'registration_open' in data:
        _cfg_set('registration_open', '1' if data['registration_open'] else '0')
    if 'invoicing_open' in data:
        _cfg_set('invoicing_open', '1' if data['invoicing_open'] else '0')
    return jsonify({'success': True})

# ── Per-user permissions ───────────────────────────────────────────────────────

PERM_FIELDS = ['perm_bill', 'perm_items', 'perm_customers', 'perm_suppliers', 'perm_purchases']

@app.route('/api/superadmin/users/<int:uid>/permissions', methods=['GET'])
def get_user_permissions(uid):
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    u = User.query.get_or_404(uid)
    return jsonify({f: getattr(u, f) for f in PERM_FIELDS})

@app.route('/api/superadmin/users/<int:uid>/permissions', methods=['POST'])
def set_user_permissions(uid):
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    u = User.query.get_or_404(uid)
    data = request.get_json() or {}
    for f in PERM_FIELDS:
        if f in data:
            setattr(u, f, bool(data[f]))
    db.session.commit()
    return jsonify({'success': True})

# ── Superadmin forgot-password flow (public — no session required) ────────────

def _mask_email(email):
    """Return a partially masked email: *********25@gmail.com"""
    try:
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked_local = '*' * len(local)
        else:
            masked_local = '*' * (len(local) - 2) + local[-2:]
        return f'{masked_local}@{domain}'
    except Exception:
        return '***@***'

def _send_reset_email(to_email: str, code: str):
    smtp_user = os.environ.get('SMTP_USER', '')
    smtp_pass = os.environ.get('SMTP_PASS', '').replace(' ', '')
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    if not smtp_user or not smtp_pass:
        raise RuntimeError('SMTP credentials not configured')
    msg = MIMEMultipart('alternative')
    msg['From'] = f'BillMate <{smtp_user}>'
    msg['To'] = to_email
    msg['Subject'] = 'BillMate — Super Admin Reset Code'
    body_text = (
        f'Your Super Admin reset code is:\n\n'
        f'  {code}\n\n'
        f'This code is valid for 24 hours.\n'
        f'You can still log in with your original password if you remember it.\n\n'
        f'If you did not request this, ignore this email.'
    )
    body_html = f'''
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;background:#f8f9fa;border-radius:16px">
      <h2 style="color:#1a1a2e;margin-bottom:8px">🔐 Super Admin Reset Code</h2>
      <p style="color:#555;margin-bottom:24px">Enter this code on the BillMate Super Admin login page:</p>
      <div style="background:#fff;border:2px solid #7c3aed;border-radius:12px;padding:20px 32px;text-align:center;margin-bottom:24px">
        <span style="font-size:2.4em;font-weight:800;letter-spacing:12px;color:#7c3aed;font-family:monospace">{code}</span>
      </div>
      <p style="color:#888;font-size:.85em">Valid for <strong>24 hours</strong>. Your original password still works if you remember it.</p>
      <p style="color:#bbb;font-size:.78em;margin-top:16px">If you did not request this, ignore this email.</p>
    </div>'''
    msg.attach(MIMEText(body_text, 'plain'))
    msg.attach(MIMEText(body_html, 'html'))
    with smtplib.SMTP(smtp_host, smtp_port) as srv:
        srv.ehlo()
        srv.starttls()
        srv.login(smtp_user, smtp_pass)
        srv.sendmail(smtp_user, to_email, msg.as_string())

@app.route('/api/superadmin/recovery-hint')
def superadmin_recovery_hint():
    """Returns masked email hint — safe to call without auth."""
    user = User.query.filter_by(is_superadmin=True).first()
    if not user or not user.recovery_email:
        return jsonify({'hint': None})
    return jsonify({'hint': _mask_email(user.recovery_email)})

@app.route('/api/superadmin/forgot-password', methods=['POST'])
def superadmin_forgot_password():
    global _reset_attempts
    now = datetime.utcnow()
    # Check cooldown
    if _reset_attempts['locked_until'] and now < _reset_attempts['locked_until']:
        remaining = int((_reset_attempts['locked_until'] - now).total_seconds() / 60)
        return jsonify({'locked': True, 'minutes': remaining})
    email = (request.get_json() or {}).get('email', '').strip().lower()
    if not email:
        return jsonify({'match': False})
    user = User.query.filter_by(is_superadmin=True).first()
    if not user or not user.recovery_email:
        return jsonify({'match': False})
    if user.recovery_email.lower() != email:
        _reset_attempts['count'] += 1
        if _reset_attempts['count'] >= 3:
            _reset_attempts['locked_until'] = now + timedelta(hours=2)
            _reset_attempts['count'] = 0
            return jsonify({'locked': True, 'minutes': 120})
        return jsonify({'match': False, 'attempts_left': 3 - _reset_attempts['count']})
    # Correct email — reset counter
    _reset_attempts = {'count': 0, 'locked_until': None}
    code = f'{secrets.randbelow(10000):04d}'
    user.reset_code_hash = generate_password_hash(code)
    user.reset_code_expiry = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()
    try:
        _send_reset_email(user.recovery_email, code)
    except Exception as e:
        app.logger.error(f'Reset email failed: {e}')
    return jsonify({'match': True})

@app.route('/api/superadmin/verify-reset-code', methods=['POST'])
def superadmin_verify_reset_code():
    """Verify the 4-digit code and start a session if valid."""
    code = (request.get_json() or {}).get('code', '').strip()
    if not code:
        return jsonify({'error': 'Code is required'}), 400
    user = User.query.filter_by(is_superadmin=True).first()
    if not user or not user.reset_code_hash or not user.reset_code_expiry:
        return jsonify({'error': 'Invalid or expired code'}), 401
    if datetime.utcnow() > user.reset_code_expiry:
        return jsonify({'error': 'Code has expired. Please request a new one.'}), 401
    if not check_password_hash(user.reset_code_hash, code):
        return jsonify({'error': 'Invalid code'}), 401
    # Valid — log in
    session.clear()
    session.permanent = True
    session['is_superadmin'] = True
    session['superadmin_uid'] = user.id
    session['username'] = user.username
    return jsonify({'success': True})

# ── Password Reset Requests ───────────────────────────────────────────────────

@app.route('/api/forgot-password-request', methods=['POST'])
def forgot_password_request():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    # If username belongs to a superadmin, redirect client to superadmin recovery flow
    if User.query.filter_by(username=username, is_superadmin=True).first():
        return jsonify({'superadmin': True})
    user = User.query.filter_by(username=username, is_superadmin=False).first()
    if not user:
        return jsonify({'error': 'Username not found'}), 404
    # Prevent duplicate pending requests
    existing = PasswordResetRequest.query.filter_by(user_id=user.id, status='pending').first()
    if existing:
        return jsonify({'error': 'A reset request is already pending for this account'}), 400
    req = PasswordResetRequest(username=username, user_id=user.id)
    db.session.add(req)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/superadmin/messages')
def superadmin_messages_page():
    return render_template('superadmin/messages.html')

@app.route('/superadmin/ip-logs')
def superadmin_ip_logs_page():
    if not session.get('is_superadmin'):
        return redirect('/superadmin/users')
    return render_template('superadmin/ip_logs.html')

@app.route('/api/superadmin/ip-logs')
def superadmin_get_ip_logs():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    cutoff = datetime.utcnow() - timedelta(days=5)
    logs = (UserIPLog.query
            .filter(UserIPLog.first_seen_at >= cutoff)
            .order_by(UserIPLog.last_seen_at.desc())
            .all())
    return jsonify([{
        'username': l.username,
        'user_id': l.user_id,
        'ip': l.ip_address,
        'date': l.log_date.isoformat(),
        'first_seen': l.first_seen_at.strftime('%H:%M'),
        'last_seen': l.last_seen_at.strftime('%H:%M'),
        'count': l.request_count,
    } for l in logs])

@app.route('/api/superadmin/messages')
def superadmin_get_messages():
    requests = PasswordResetRequest.query.order_by(
        PasswordResetRequest.status.asc(),
        PasswordResetRequest.requested_at.desc()
    ).all()
    pending_count = PasswordResetRequest.query.filter_by(status='pending').count()
    return jsonify({
        'requests': [{
            'id': r.id,
            'username': r.username,
            'status': r.status,
            'requested_at': r.requested_at.strftime('%Y-%m-%d %H:%M') if r.requested_at else '',
            'resolved_at': r.resolved_at.strftime('%Y-%m-%d %H:%M') if r.resolved_at else None,
        } for r in requests],
        'pending_count': pending_count,
    })

@app.route('/api/superadmin/messages/<int:rid>/resolve', methods=['POST'])
def superadmin_resolve_message(rid):
    data = request.get_json()
    new_pwd = (data.get('new_password') or '').strip()
    if not new_pwd or len(new_pwd) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    req = PasswordResetRequest.query.get_or_404(rid)
    user = User.query.get(req.user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.password_hash = generate_password_hash(new_pwd)
    req.status = 'resolved'
    req.resolved_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/messages/<int:rid>/dismiss', methods=['POST'])
def superadmin_dismiss_message(rid):
    req = PasswordResetRequest.query.get_or_404(rid)
    req.status = 'dismissed'
    req.resolved_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/superadmin/pending-count')
def superadmin_pending_count():
    count = PasswordResetRequest.query.filter_by(status='pending').count()
    return jsonify({'count': count})

@app.route('/api/superadmin/items/bulk-delete', methods=['POST'])
def superadmin_bulk_delete_items():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    scope = (request.get_json() or {}).get('scope', 'all')
    query = Item.query.filter_by(is_global=True, is_active=True)
    if scope == 'recent':
        cutoff = datetime.utcnow() - timedelta(hours=24)
        query = query.filter(Item.created_at >= cutoff)
    items = query.all()
    count = len(items)
    for item in items:
        item.is_active = False
    db.session.commit()
    return jsonify({'deleted': count})

@app.route('/api/superadmin/items/import', methods=['POST'])
def superadmin_import_items():
    if not session.get('is_superadmin'):
        return jsonify({'error': 'Superadmin only'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    try:
        html = f.read().decode('utf-8', errors='replace')
    except Exception:
        return jsonify({'error': 'Could not read file'}), 400

    # Load all existing global items once
    existing = Item.query.filter_by(is_global=True, is_active=True).all()
    existing_map = {item.name.lower(): item for item in existing}
    # Include soft-deleted global items in used_codes to avoid unique constraint violations
    used_codes = {r[0] for r in Item.query.filter_by(is_global=True).with_entities(Item.code).all()}
    code_counter = len(used_codes)

    def _next_code():
        nonlocal code_counter
        while True:
            code_counter += 1
            candidate = f'GITM{code_counter:04d}'
            if candidate not in used_codes:
                used_codes.add(candidate)
                return candidate

    def _clean(s):
        return re.sub(r'\s+', ' ', s).strip() if s else ''

    def _num(s):
        m = re.search(r'[-+]?\d+\.?\d*', _clean(s))
        return float(m.group()) if m else 0.0

    added = updated = skipped = 0

    def _upsert(name, tp, retail, disc_pct, bonus, tax_pct):
        nonlocal added, updated, skipped
        name = _clean(name)
        if not name:
            skipped += 1
            return
        key = name.lower()
        if key in existing_map:
            item = existing_map[key]
            item.tp = tp
            item.retail_price = retail
            item.discount_pct = disc_pct
            if bonus:
                item.bonus_text = bonus
            item.tax_pct = tax_pct
            updated += 1
        else:
            item = Item(
                user_id=None, is_global=True,
                code=_next_code(), name=name,
                retail_price=retail, tp=tp,
                discount_pct=disc_pct, bonus_text=bonus,
                tax_pct=tax_pct, qty=0,
            )
            db.session.add(item)
            existing_map[key] = item
            added += 1

    try:
        soup = BeautifulSoup(html, 'html.parser')
        new_rows = soup.find_all('tr', class_='item-row')
        if new_rows:
            for row in new_rows:
                tds = row.find_all('td')
                if len(tds) < 2:
                    continue
                name = _clean(tds[1].get_text())
                tp = float(row.get('data-tp', 0) or 0)
                disc_pct = float(row.get('data-disc', 0) or 0)
                bonus = _clean(row.get('data-bonus', '') or '')
                tax_pct = float(row.get('data-tax', 0) or 0)
                retail = round(tp / 0.85, 2) if tp > 0 else 0
                _upsert(name, tp, retail, disc_pct, bonus, tax_pct)
        else:
            for row in soup.find_all('tr', class_='item'):
                tds = row.find_all('td')
                if len(tds) < 4:
                    continue
                if len(tds) >= 8:
                    name     = _clean(tds[2].get_text())
                    disc_pct = _num(tds[3].get_text())
                    tp       = _num(tds[4].get_text())
                    bonus    = ''
                else:
                    name     = _clean(tds[1].get_text())
                    disc_pct = _num(tds[3].get_text())
                    bonus    = _clean(tds[4].get_text()) if len(tds) > 4 else ''
                    tp       = _num(tds[-1].get_text())
                retail = round(tp / 0.85, 2) if tp > 0 else 0
                _upsert(name, tp, retail, disc_pct, bonus, tax_pct=0)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

    return jsonify({'added': added, 'updated': updated, 'skipped': skipped})

@app.route('/admin/unlock', methods=['GET', 'POST'])
def admin_unlock():
    s = get_user_settings()
    # No admin password set yet — grant access directly and prompt to set one
    if not s or not s.admin_password_hash:
        session['is_admin'] = True
        session.modified = True
        return redirect('/admin/setup')
    # Check if account is locked (per-user settings, so lock is inherently per-user)
    locked = False
    lock_minutes_left = 0
    if s.admin_locked_until and datetime.utcnow() < s.admin_locked_until:
        locked = True
        remaining = (s.admin_locked_until - datetime.utcnow()).total_seconds()
        lock_minutes_left = max(1, int(remaining // 60))
    elif s.admin_locked_until and datetime.utcnow() >= s.admin_locked_until:
        # Lock expired — clear it
        s.admin_locked_until = None
        s.admin_failed_attempts = 0
        db.session.commit()
    # Check if a reset was requested and 24hrs have passed
    if s.admin_reset_requested_at:
        elapsed = datetime.utcnow() - s.admin_reset_requested_at
        if elapsed >= timedelta(hours=24):
            # Reset admin password to user's login password
            user = User.query.get(session.get('user_id'))
            if user:
                s.admin_password_hash = user.password_hash
                s.admin_reset_requested_at = None
                s.admin_password_is_temp = True
                s.admin_failed_attempts = 0
                s.admin_locked_until = None
                db.session.commit()
                locked = False
    if request.method == 'POST':
        if locked:
            return render_template('admin/unlock.html', error=f'Account locked. Try again in {lock_minutes_left} min',
                                   locked=True, lock_minutes_left=lock_minutes_left)
        pwd = (request.form.get('password') or '').strip()
        if check_password_hash(s.admin_password_hash, pwd):
            # Success — clear failed attempts, cancel any pending reset
            s.admin_failed_attempts = 0
            s.admin_locked_until = None
            if s.admin_reset_requested_at:
                s.admin_reset_requested_at = None
            db.session.commit()
            session['is_admin'] = True
            if s.admin_password_is_temp:
                session['force_admin_pwd_change'] = True
            session.modified = True
            return redirect('/admin/sales')
        # Wrong password — increment failed attempts
        s.admin_failed_attempts = (s.admin_failed_attempts or 0) + 1
        if s.admin_failed_attempts >= 3:
            s.admin_locked_until = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            return render_template('admin/unlock.html', error='Too many failed attempts. Locked for 1 hour.',
                                   locked=True, lock_minutes_left=60)
        db.session.commit()
        attempts_left = 3 - s.admin_failed_attempts
        return render_template('admin/unlock.html', error=f'Wrong password. {attempts_left} attempt(s) left before lockout.')
    # Check if reset is pending
    reset_pending = False
    reset_hours_left = 0
    if s.admin_reset_requested_at:
        elapsed = datetime.utcnow() - s.admin_reset_requested_at
        remaining = timedelta(hours=24) - elapsed
        if remaining.total_seconds() > 0:
            reset_pending = True
            reset_hours_left = max(1, int(remaining.total_seconds() // 3600))
    return render_template('admin/unlock.html', reset_pending=reset_pending, reset_hours_left=reset_hours_left,
                           locked=locked, lock_minutes_left=lock_minutes_left)

@app.route('/admin/forgot-password', methods=['POST'])
def admin_forgot_password():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'You must be logged in to request a reset'}), 401
    s = get_user_settings()
    if not s or not s.admin_password_hash:
        return jsonify({'error': 'No admin password set'}), 400
    if s.admin_reset_requested_at:
        elapsed = datetime.utcnow() - s.admin_reset_requested_at
        remaining = timedelta(hours=24) - elapsed
        if remaining.total_seconds() > 0:
            hrs = int(remaining.total_seconds() // 3600)
            mins = int((remaining.total_seconds() % 3600) // 60)
            return jsonify({'error': f'Reset already requested. Try again in {hrs}h {mins}m'}), 400
    s.admin_reset_requested_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Admin password will reset to your login password after 24 hours'})

@app.route('/api/change-login-password', methods=['POST'])
def change_login_password():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    data = request.get_json()
    current_pwd = (data.get('current_password') or '').strip()
    new_pwd = (data.get('new_password') or '').strip()
    if not current_pwd or not new_pwd:
        return jsonify({'error': 'Both current and new password are required'}), 400
    if len(new_pwd) < 4:
        return jsonify({'error': 'New password must be at least 4 characters'}), 400
    user = User.query.get(user_id)
    if not user or not check_password_hash(user.password_hash, current_pwd):
        return jsonify({'error': 'Current password is incorrect'}), 401
    user.password_hash = generate_password_hash(new_pwd)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/change-admin-password', methods=['POST'])
def change_admin_password():
    if not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    data = request.get_json()
    new_pwd = (data.get('new_password') or '').strip()
    if not new_pwd:
        return jsonify({'error': 'New password is required'}), 400
    if len(new_pwd) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    s = get_user_settings()
    if not s:
        return jsonify({'error': 'Settings not found'}), 400
    s.admin_password_hash = generate_password_hash(new_pwd)
    s.admin_password_is_temp = False
    s.admin_reset_requested_at = None
    db.session.commit()
    session.pop('force_admin_pwd_change', None)
    return jsonify({'success': True})

@app.route('/setup')
def setup_page():
    return render_template('setup.html')

@app.route('/purchase')
def purchase_page():
    return render_template('purchase.html')

@app.route('/items')
def items_page():
    return render_template('items.html',
        can_delete_global=bool(session.get('is_admin') or session.get('is_superadmin')),
        is_guest=bool(session.get('is_guest'))
    )

@app.route('/customers')
def customers_page():
    return render_template('customers.html')

@app.route('/billing')
def billing_page():
    return render_template('billing.html', is_guest=bool(session.get('is_guest')))

@app.route('/payments')
def payments_page():
    return render_template('payments.html')


# ── Settings API ──────────────────────────────────────────────────────────────

@app.route('/api/settings', methods=['GET'])
def get_settings():
    s = get_user_settings()
    if not s:
        return jsonify({})
    return jsonify(s.to_dict())

@app.route('/api/settings', methods=['POST'])
def save_settings():
    data = request.get_json()
    s = get_or_create_user_settings()
    if not s:
        return jsonify({'error': 'Not logged in'}), 401
    s.shop_name = data.get('shop_name', '').strip()
    s.address   = data.get('address', '').strip()
    s.phone     = data.get('phone', '').strip()
    s.whatsapp  = data.get('whatsapp', '').strip()
    s.ntn       = data.get('ntn', '').strip()
    s.invoice_prefix = data.get('invoice_prefix', 'INV').strip() or 'INV'
    admin_pwd = (data.get('admin_password') or '').strip()
    if admin_pwd:
        s.admin_password_hash = generate_password_hash(admin_pwd)
    groq_key = (data.get('groq_api_key') or '').strip()
    if groq_key:
        s.groq_api_key = groq_key
    elif data.get('groq_api_key') == '':
        s.groq_api_key = None
    gemini_key_val = (data.get('gemini_api_key') or '').strip()
    if gemini_key_val:
        s.gemini_api_key = gemini_key_val
    elif data.get('gemini_api_key') == '':
        s.gemini_api_key = None
    db.session.commit()
    return jsonify({'success': True, 'settings': s.to_dict()})


# ── Categories API ─────────────────────────────────────────────────────────────

@app.route('/api/categories', methods=['GET'])
def get_categories():
    cats = Category.query.order_by(Category.name).all()
    return jsonify([c.to_dict() for c in cats])

@app.route('/api/categories', methods=['POST'])
def add_category():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    if Category.query.filter_by(name=name).first():
        return jsonify({'error': 'Category already exists'}), 400
    c = Category(name=name)
    db.session.add(c)
    db.session.commit()
    return jsonify(c.to_dict()), 201

@app.route('/api/categories/<int:cid>', methods=['DELETE'])
def delete_category(cid):
    c = Category.query.get_or_404(cid)
    db.session.delete(c)
    db.session.commit()
    return jsonify({'success': True})


# ── Items API ─────────────────────────────────────────────────────────────────

@app.route('/api/items', methods=['GET'])
def get_items():
    q = request.args.get('q', '').strip()
    uid = session.get('user_id')
    # Superadmin + guests see only global items; regular users see own + global
    if session.get('is_superadmin') or session.get('is_guest') or not uid:
        query = Item.query.filter_by(is_active=True, is_global=True)
    else:
        query = Item.query.filter_by(is_active=True).filter(
            db.or_(Item.user_id == uid, Item.is_global == True)
        )
    if q:
        query = query.filter(Item.name.ilike(f'%{q}%'))
    items = query.order_by(Item.name).all()
    # Load per-user customisations for global items (single queries)
    user_discounts = {}
    user_overrides = {}
    if uid:
        for ud in UserItemDiscount.query.filter_by(user_id=uid).all():
            user_discounts[ud.item_id] = float(ud.discount_pct or 0)
        for ov in UserItemOverride.query.filter_by(user_id=uid).all():
            user_overrides[ov.item_id] = ov
    result = []
    for i in items:
        d = i.to_dict()
        if i.is_global and uid:
            d['discount_pct'] = user_discounts.get(i.id, 0)
            ov = user_overrides.get(i.id)
            if ov:
                if ov.tp is not None:          d['tp']           = float(ov.tp)
                if ov.retail_price is not None: d['retail_price'] = float(ov.retail_price)
                if ov.tax_pct is not None:      d['tax_pct']      = float(ov.tax_pct)
                if ov.bonus_text is not None:   d['bonus_text']   = ov.bonus_text
        result.append(d)
    return jsonify(result)

@app.route('/api/items', methods=['POST'])
def add_item():
    if session.get('is_guest'):
        return jsonify({'error': 'Guest items are stored locally in your browser.'}), 403
    uid = session.get('user_id')
    if uid and not User.query.get(uid).perm_items:
        return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    data = request.get_json()
    name = data.get('name', '').strip()
    code = data.get('code', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    try:
        retail = float(data.get('retail_price', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid retail price'}), 400
    if retail <= 0:
        return jsonify({'error': 'Retail price must be greater than 0'}), 400

    uid = session.get('user_id')
    is_global = bool(data.get('is_global')) and (session.get('is_admin') or session.get('is_superadmin'))

    # Auto-generate code if not provided
    if not code:
        if is_global:
            count = Item.query.filter_by(is_global=True).count()
            code = f'GITM{count + 1:04d}'
            # Ensure uniqueness in case of gaps
            while Item.query.filter_by(code=code, user_id=None).first():
                count += 1
                code = f'GITM{count + 1:04d}'
        else:
            count = Item.query.filter_by(is_global=False, user_id=uid).count()
            code = f'ITM{count + 1:04d}'
            while Item.query.filter_by(code=code, user_id=uid).first():
                count += 1
                code = f'ITM{count + 1:04d}'

    # Prevent duplicate code per owner (global items use user_id=None)
    owner_id = None if is_global else uid
    if Item.query.filter_by(code=code, user_id=owner_id).first():
        return jsonify({'error': f'Item code {code} already exists'}), 400

    tp = float(data.get('tp') or Item.tp_from_retail(retail))
    disc_pct = float(data.get('discount_pct', 0) or 0)

    item = Item(
        user_id=owner_id,
        is_global=is_global,
        code=code,
        name=name,
        retail_price=retail,
        tp=tp,
        discount_pct=disc_pct if not is_global else 0,
        bonus_text=data.get('bonus_text', '').strip(),
        tax_pct=float(data.get('tax_pct', 0) or 0),
        qty=float(data.get('qty', 0) or 0),
        category_id=data.get('category_id') or None,
    )
    db.session.add(item)
    db.session.flush()
    # Per-user discount on global items stored separately
    if is_global and uid and disc_pct:
        ud = UserItemDiscount(user_id=uid, item_id=item.id, discount_pct=disc_pct)
        db.session.add(ud)
    db.session.commit()
    d = item.to_dict()
    d['discount_pct'] = disc_pct
    return jsonify(d), 201

@app.route('/api/items/<int:iid>', methods=['PUT'])
def update_item(iid):
    item = Item.query.get_or_404(iid)
    uid = session.get('user_id')
    is_admin = session.get('is_admin') or session.get('is_superadmin')
    data = request.get_json()

    if item.is_global and not is_admin:
        # Regular user editing a global item → save as per-user override only
        ov = UserItemOverride.query.filter_by(user_id=uid, item_id=iid).first()
        if not ov:
            ov = UserItemOverride(user_id=uid, item_id=iid)
            db.session.add(ov)
        if 'tp' in data:
            ov.tp = float(data['tp'])
        if 'retail_price' in data:
            ov.retail_price = float(data['retail_price'])
        if 'tax_pct' in data:
            ov.tax_pct = float(data['tax_pct'] or 0)
        if 'bonus_text' in data:
            ov.bonus_text = data['bonus_text'].strip()
        # qty is shared stock — update directly on the global item
        if 'qty' in data:
            item.qty = float(data['qty'] or 0)
        # Discount still goes to UserItemDiscount
        if 'discount_pct' in data and uid:
            ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=iid).first()
            disc_val = float(data['discount_pct'] or 0)
            if ud:
                ud.discount_pct = disc_val
            elif disc_val:
                db.session.add(UserItemDiscount(user_id=uid, item_id=iid, discount_pct=disc_val))
        db.session.commit()
        # Return item dict with overrides applied
        d = item.to_dict()
        if ov.tp is not None:           d['tp']           = float(ov.tp)
        if ov.retail_price is not None: d['retail_price'] = float(ov.retail_price)
        if ov.tax_pct is not None:      d['tax_pct']      = float(ov.tax_pct)
        if ov.bonus_text is not None:   d['bonus_text']   = ov.bonus_text
        ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=iid).first()
        d['discount_pct'] = float(ud.discount_pct or 0) if ud else 0
        return jsonify(d)

    # Own private item OR admin editing global item → update the record directly
    if not item.is_global and item.user_id != uid:
        return jsonify({'error': 'Not your item'}), 403
    if 'name' in data:
        item.name = data['name'].strip()
    if 'retail_price' in data:
        item.retail_price = float(data['retail_price'])
    if 'tp' in data:
        item.tp = float(data['tp'])
    if 'discount_pct' in data and uid:
        ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=iid).first()
        disc_val = float(data['discount_pct'] or 0)
        if ud:
            ud.discount_pct = disc_val
        elif disc_val:
            db.session.add(UserItemDiscount(user_id=uid, item_id=iid, discount_pct=disc_val))
    if 'bonus_text' in data:
        item.bonus_text = data['bonus_text'].strip()
    if 'tax_pct' in data:
        item.tax_pct = float(data['tax_pct'] or 0)
    if 'category_id' in data:
        item.category_id = data['category_id'] or None
    if 'qty' in data:
        item.qty = float(data['qty'] or 0)
    db.session.commit()
    d = item.to_dict()
    if uid:
        ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=iid).first()
        d['discount_pct'] = float(ud.discount_pct or 0) if ud else 0
    return jsonify(d)

@app.route('/api/suppliers', methods=['GET'])
def get_suppliers():
    uid = session.get('user_id')
    q = request.args.get('q', '').strip()
    query = Supplier.query.filter_by(is_active=True)
    if uid:
        query = query.filter_by(user_id=uid)
    if q:
        query = query.filter(Supplier.name.ilike(f'%{q}%'))
    return jsonify([s.to_dict() for s in query.order_by(Supplier.name).all()])

@app.route('/api/suppliers', methods=['POST'])
def add_supplier():
    uid = session.get('user_id')
    if uid and not User.query.get(uid).perm_suppliers:
        return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    s = Supplier(user_id=session.get('user_id'), name=name, phone=data.get('phone','').strip(), address=data.get('address','').strip(), notes=data.get('notes','').strip())
    db.session.add(s)
    db.session.commit()
    return jsonify(s.to_dict()), 201

@app.route('/api/suppliers/<int:sid>', methods=['PUT'])
def update_supplier(sid):
    s = Supplier.query.get_or_404(sid)
    uid = session.get('user_id')
    if s.user_id and s.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    data = request.get_json()
    if 'name' in data: s.name = data['name'].strip()
    if 'phone' in data: s.phone = data['phone'].strip()
    if 'address' in data: s.address = data['address'].strip()
    if 'notes' in data: s.notes = data['notes'].strip()
    db.session.commit()
    return jsonify(s.to_dict())

@app.route('/api/suppliers/<int:sid>', methods=['DELETE'])
def delete_supplier(sid):
    s = Supplier.query.get_or_404(sid)
    uid = session.get('user_id')
    if s.user_id and s.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    s.is_active = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/purchases', methods=['GET'])
def get_purchases():
    uid = session.get('user_id')
    query = Purchase.query
    if uid:
        query = query.filter_by(user_id=uid)
    purchases = query.order_by(Purchase.created_at.desc()).all()
    return jsonify([p.to_dict() for p in purchases])

@app.route('/api/purchase', methods=['POST'])
def save_purchase():
    uid = session.get('user_id')
    if uid and not User.query.get(uid).perm_purchases:
        return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    data = request.get_json()
    lines = data.get('lines', [])
    if not lines:
        return jsonify({'error': 'No items'}), 400

    # Generate purchase number
    last = Purchase.query.order_by(Purchase.id.desc()).first()
    num = (last.id + 1) if last else 1
    purchase_number = f'PUR-{num:04d}'

    total_cost = 0
    purchase = Purchase(
        user_id=session.get('user_id'),
        purchase_number=purchase_number,
        supplier_id=data.get('supplier_id'),
        supplier_name=data.get('supplier_name', 'Counter'),
    )
    db.session.add(purchase)
    db.session.flush()

    for line in lines:
        item = Item.query.get(line.get('item_id')) if line.get('item_id') else None
        item_name = line.get('item_name') or (item.name if item else '')
        if not item_name:
            continue
        qty_received = float(line.get('qty', 0))
        tp = float(line.get('tp', 0))
        retail = float(line.get('retail', 0))
        disc = float(line.get('disc', 0))
        tax = float(line.get('tax', 0))
        gross = tp * qty_received
        line_total = round(gross * (1 - disc/100) + qty_received * tax, 2)
        total_cost += line_total

        # Auto-create catalog item if not found (custom item from purchase)
        if not item and item_name:
            cnt = Item.query.filter_by(is_global=False, user_id=uid).count()
            auto_code = f'ITM{cnt + 1:04d}'
            while Item.query.filter_by(code=auto_code, user_id=uid).first():
                cnt += 1
                auto_code = f'ITM{cnt + 1:04d}'
            item = Item(
                user_id=uid,
                code=auto_code,
                name=item_name,
                retail_price=retail if retail > 0 else (tp / 0.85 if tp > 0 else 0),
                tp=tp if tp > 0 else (retail * 0.85 if retail > 0 else 0),
                discount_pct=disc,
                tax_pct=tax,
                qty=0,
            )
            db.session.add(item)
            db.session.flush()  # get item.id

        pl = PurchaseLine(purchase_id=purchase.id, item_id=item.id if item else None, item_name=item_name,
                          qty=qty_received, tp=tp, retail=retail, disc_pct=disc, tax=tax, line_total=line_total)
        db.session.add(pl)

        # Update stock and prices
        if item:
            item.qty = round(float(item.qty or 0) + qty_received, 3)
            if tp > 0: item.tp = tp
            if retail > 0: item.retail_price = retail
            item.tax_pct = tax
            # Save discount per-user
            uid = session.get('user_id')
            if uid and disc:
                ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=item.id).first()
                if ud:
                    ud.discount_pct = disc
                else:
                    db.session.add(UserItemDiscount(user_id=uid, item_id=item.id, discount_pct=disc))

    purchase.total_cost = round(total_cost, 2)
    # Update supplier balance
    if purchase.supplier_id:
        sup = Supplier.query.get(purchase.supplier_id)
        if sup:
            sup.balance = round(float(sup.balance or 0) + float(purchase.total_cost), 2)
    db.session.commit()
    return jsonify(purchase.to_dict())

@app.route('/api/purchases/<int:pid>', methods=['DELETE'])
def delete_purchase(pid):
    p = Purchase.query.get_or_404(pid)
    uid = session.get('user_id')
    if p.user_id and p.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    # Reverse stock qty
    for line in p.lines:
        if line.item_id:
            item = Item.query.get(line.item_id)
            if item:
                item.qty = round(float(item.qty or 0) - float(line.qty), 3)
    # Reverse supplier balance
    if p.supplier_id:
        sup = Supplier.query.get(p.supplier_id)
        if sup:
            sup.balance = round(float(sup.balance or 0) - float(p.total_cost), 2)
    db.session.delete(p)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/purchases/<int:pid>', methods=['PUT'])
def update_purchase(pid):
    p = Purchase.query.get_or_404(pid)
    uid = session.get('user_id')
    if p.user_id and p.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    data = request.get_json()

    # Reverse old stock
    for line in p.lines:
        if line.item_id:
            item = Item.query.get(line.item_id)
            if item:
                item.qty = round(float(item.qty or 0) - float(line.qty), 3)

    # Delete old lines
    for line in list(p.lines):
        db.session.delete(line)
    db.session.flush()

    # Update header
    p.supplier_id = data.get('supplier_id')
    p.supplier_name = data.get('supplier_name', 'Counter')
    if data.get('purchase_date'):
        from datetime import date as _date
        p.purchase_date = _date.fromisoformat(data['purchase_date'])

    # Re-add lines
    total_cost = 0
    for line in data.get('lines', []):
        item = Item.query.get(line.get('item_id')) if line.get('item_id') else None
        item_name = line.get('item_name') or (item.name if item else '')
        if not item_name:
            continue
        qty = float(line.get('qty', 0))
        tp = float(line.get('tp', 0))
        retail = float(line.get('retail', 0))
        disc = float(line.get('disc', 0))
        tax = float(line.get('tax', 0))
        gross = tp * qty
        line_total = round(gross * (1 - disc/100) + qty * tax, 2)
        total_cost += line_total

        # Auto-create catalog item if not found
        if not item and item_name:
            cnt = Item.query.filter_by(is_global=False, user_id=uid).count()
            auto_code = f'ITM{cnt + 1:04d}'
            while Item.query.filter_by(code=auto_code, user_id=uid).first():
                cnt += 1
                auto_code = f'ITM{cnt + 1:04d}'
            item = Item(
                user_id=uid,
                code=auto_code,
                name=item_name,
                retail_price=retail if retail > 0 else (tp / 0.85 if tp > 0 else 0),
                tp=tp if tp > 0 else (retail * 0.85 if retail > 0 else 0),
                discount_pct=disc,
                tax_pct=tax,
                qty=0,
            )
            db.session.add(item)
            db.session.flush()

        pl = PurchaseLine(purchase_id=p.id, item_id=item.id if item else None, item_name=item_name,
                          qty=qty, tp=tp, retail=retail, disc_pct=disc, tax=tax, line_total=line_total)
        db.session.add(pl)

        if item:
            item.qty = round(float(item.qty or 0) + qty, 3)
            if tp > 0: item.tp = tp
            if retail > 0: item.retail_price = retail
            item.tax_pct = tax
            # Save discount per-user
            uid = session.get('user_id')
            if uid and disc:
                ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=item.id).first()
                if ud:
                    ud.discount_pct = disc
                else:
                    db.session.add(UserItemDiscount(user_id=uid, item_id=item.id, discount_pct=disc))

    p.total_cost = round(total_cost, 2)
    db.session.commit()
    return jsonify(p.to_dict())

@app.route('/api/items/<int:iid>', methods=['DELETE'])
def delete_item(iid):
    item = Item.query.get_or_404(iid)
    uid = session.get('user_id')
    # Only owner can delete private items; only admin can delete global items
    if item.is_global and not session.get('is_admin') and not session.get('is_superadmin'):
        return jsonify({'error': 'Only admin can delete global items'}), 403
    if not item.is_global and item.user_id != uid:
        return jsonify({'error': 'Not your item'}), 403
    item.is_active = False
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/items/bulk-delete', methods=['POST'])
def bulk_delete_items():
    if session.get('is_guest'):
        return jsonify({'error': 'Guests cannot delete items.'}), 403
    uid = session.get('user_id')
    data = request.get_json() or {}
    scope = data.get('scope', 'all')  # 'all' or 'recent'

    query = Item.query.filter_by(user_id=uid, is_active=True, is_global=False)

    if scope == 'recent':
        # Items added in the last import session: those created today or
        # during the most recent batch (last 24 hours as a practical window)
        cutoff = datetime.utcnow() - timedelta(hours=24)
        query = query.filter(Item.created_at >= cutoff)

    items = query.all()
    count = len(items)
    for item in items:
        item.is_active = False
    db.session.commit()
    return jsonify({'deleted': count})


@app.route('/api/items/import', methods=['POST'])
def import_items():
    if session.get('is_guest'):
        return jsonify({'error': 'Guests cannot import items.'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    allowed_ext = {'.html', '.htm', '.csv', '.txt'}
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in allowed_ext:
        return jsonify({'error': 'Only .html, .htm, .csv, .txt files are allowed'}), 400
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 4 * 1024 * 1024:  # 4 MB cap
        return jsonify({'error': 'File too large (max 4 MB)'}), 400

    try:
        html = f.read().decode('utf-8', errors='replace')
    except Exception:
        return jsonify({'error': 'Could not read file'}), 400

    uid = session.get('user_id')

    # ── Load all existing user items once (single query) ──────────────────────
    existing_items = Item.query.filter_by(user_id=uid, is_active=True).all()
    # keyed by lowercase name for O(1) lookup
    existing_map = {item.name.lower(): item for item in existing_items}
    # collect ALL codes (including soft-deleted) to avoid unique constraint violations
    used_codes = {r[0] for r in Item.query.filter_by(user_id=uid).with_entities(Item.code).all()}
    # running counter for new codes
    code_counter = len(used_codes)

    # Global item names — used to detect "kept alongside global" items.
    # When an imported item name matches a global item but the user has no
    # private item with that name yet, we always create a new private item
    # (never modify the global). Both coexist in the user's catalogue.
    global_names = {
        r[0].lower()
        for r in Item.query.filter_by(is_global=True, is_active=True).with_entities(Item.name).all()
    }

    def _next_code():
        nonlocal code_counter
        while True:
            code_counter += 1
            candidate = f'ITM{code_counter:04d}'
            if candidate not in used_codes:
                used_codes.add(candidate)
                return candidate

    def _clean(s):
        return re.sub(r'\s+', ' ', s).strip() if s else ''

    def _num(s):
        m = re.search(r'[-+]?\d+\.?\d*', _clean(s))
        return float(m.group()) if m else 0.0

    added = updated = skipped = alongside_global = 0

    def _upsert(name, tp, retail, disc_pct, bonus, tax_pct):
        nonlocal added, updated, skipped, alongside_global
        name = _clean(name)
        if not name:
            skipped += 1
            return
        key = name.lower()
        if key in existing_map:
            # Update the user's existing private item
            item = existing_map[key]
            item.tp = tp
            item.retail_price = retail
            item.discount_pct = disc_pct
            if bonus:
                item.bonus_text = bonus
            item.tax_pct = tax_pct
            updated += 1
        else:
            # Create a new private item for this user.
            # If a global item with the same name exists, we still create the
            # private copy — both will coexist in the user's catalogue.
            item = Item(
                user_id=uid, is_global=False,
                code=_next_code(), name=name,
                retail_price=retail, tp=tp,
                discount_pct=disc_pct, bonus_text=bonus,
                tax_pct=tax_pct, qty=0,
            )
            db.session.add(item)
            existing_map[key] = item  # prevent dupes within same file
            if key in global_names:
                alongside_global += 1
            added += 1

    # ── Parse HTML ─────────────────────────────────────────────────────────────
    try:
        soup = BeautifulSoup(html, 'html.parser')

        new_rows = soup.find_all('tr', class_='item-row')
        if new_rows:
            # Format A: new_pattern — data-tp / data-disc / data-tax attributes
            for row in new_rows:
                tds = row.find_all('td')
                if len(tds) < 2:
                    continue
                name = _clean(tds[1].get_text())
                tp = float(row.get('data-tp', 0) or 0)
                disc_pct = float(row.get('data-disc', 0) or 0)
                bonus = _clean(row.get('data-bonus', '') or '')
                tax_pct = float(row.get('data-tax', 0) or 0)
                retail = round(tp / 0.85, 2) if tp > 0 else 0
                _upsert(name, tp, retail, disc_pct, bonus, tax_pct)
        else:
            # Format B/C: classic HTM — <tr class="item">
            # STOCK (9 cols): SR# | Code | Name | Disc% | TP | Box | Pcs | Cost | Amt
            # CASH  (6 cols): SR# | Name | qty-input | Disc% | Bonus | (empty)
            for row in soup.find_all('tr', class_='item'):
                tds = row.find_all('td')
                if len(tds) < 4:
                    continue
                if len(tds) >= 8:
                    name     = _clean(tds[2].get_text())
                    disc_pct = _num(tds[3].get_text())
                    tp       = _num(tds[4].get_text())
                    bonus    = ''
                else:
                    name     = _clean(tds[1].get_text())
                    disc_pct = _num(tds[3].get_text())
                    bonus    = _clean(tds[4].get_text()) if len(tds) > 4 else ''
                    tp       = _num(tds[-1].get_text())
                retail = round(tp / 0.85, 2) if tp > 0 else 0
                _upsert(name, tp, retail, disc_pct, bonus, tax_pct=0)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

    return jsonify({'added': added, 'updated': updated, 'skipped': skipped, 'alongside_global': alongside_global})


# ── Customers API ─────────────────────────────────────────────────────────────

@app.route('/api/customers', methods=['GET'])
def get_customers():
    uid = session.get('user_id')
    q = request.args.get('q', '').strip()
    query = Customer.query.filter_by(is_active=True)
    if uid:
        query = query.filter_by(user_id=uid)
    if q:
        query = query.filter(
            (Customer.name.ilike(f'{q}%')) | (Customer.phone.ilike(f'%{q}%'))
        )
    customers = query.order_by(Customer.name).all()
    result = []
    for c in customers:
        d = c.to_dict()
        outstanding = db.session.query(func.sum(Invoice.total)).filter(
            Invoice.customer_id == c.id,
            Invoice.status != 'cancelled'
        ).scalar() or 0
        d['outstanding'] = round(float(outstanding), 2)
        result.append(d)
    return jsonify(result)

@app.route('/api/customers', methods=['POST'])
def add_customer():
    uid = session.get('user_id')
    if uid and not User.query.get(uid).perm_customers:
        return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    c = Customer(
        user_id=session.get('user_id'),
        name=name,
        phone=data.get('phone', '').strip(),
        whatsapp=data.get('whatsapp', '').strip(),
        address=data.get('address', '').strip(),
        credit_limit=float(data.get('credit_limit', 0) or 0),
        notes=data.get('notes', '').strip(),
    )
    db.session.add(c)
    db.session.commit()
    return jsonify(c.to_dict()), 201

@app.route('/api/customers/<int:cid>', methods=['PUT'])
def update_customer(cid):
    c = Customer.query.get_or_404(cid)
    uid = session.get('user_id')
    if c.user_id and c.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    data = request.get_json()
    if 'name' in data:       c.name         = data['name'].strip()
    if 'phone' in data:      c.phone        = data['phone'].strip()
    if 'whatsapp' in data:   c.whatsapp     = data['whatsapp'].strip()
    if 'address' in data:    c.address      = data['address'].strip()
    if 'credit_limit' in data: c.credit_limit = float(data['credit_limit'] or 0)
    if 'notes' in data:      c.notes        = data['notes'].strip()
    db.session.commit()
    return jsonify(c.to_dict())

@app.route('/api/customers/<int:cid>', methods=['DELETE'])
def delete_customer(cid):
    c = Customer.query.get_or_404(cid)
    uid = session.get('user_id')
    if c.user_id and c.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    c.is_active = False
    db.session.commit()
    return jsonify({'success': True})


# ── Guest claim endpoint ───────────────────────────────────────────────────────

@app.route('/api/guest/claim-invoice', methods=['POST'])
def guest_claim_invoice():
    """IP-based counter: max 4 invoices per 12 hours for guests."""
    if not session.get('is_guest'):
        return jsonify({'error': 'Not a guest session'}), 403
    ip = get_client_ip()
    now = datetime.utcnow()
    gl = GuestLimit.query.filter_by(ip_address=ip).first()
    if gl:
        if (now - gl.window_start) > timedelta(hours=12):
            gl.invoice_count = 0
            gl.window_start = now
        if gl.invoice_count >= 4:
            return jsonify({'error': 'Guest limit reached (4 invoices per 12 hours). Please register for a free account.'}), 429
        gl.invoice_count += 1
    else:
        gl = GuestLimit(ip_address=ip, invoice_count=1, window_start=now)
        db.session.add(gl)
    db.session.commit()
    return jsonify({'ok': True})


# ── Invoices API ──────────────────────────────────────────────────────────────

def _ensure_item_exists(name, tp, retail_price, tax_pct, discount_pct=0, bonus_text='', user_id=None):
    """Auto-create an item in the user's catalog if it doesn't already exist (by name)."""
    query = Item.query.filter(Item.name.ilike(name), Item.is_active == True)
    if user_id:
        query = query.filter(db.or_(Item.user_id == user_id, Item.is_global == True))
    else:
        query = query.filter(Item.is_global == True)
    existing = query.first()
    if existing:
        return existing
    count = Item.query.filter_by(is_global=False, user_id=user_id).count()
    code = f'ITM{count + 1:04d}'
    while Item.query.filter_by(code=code, user_id=user_id).first():
        count += 1
        code = f'ITM{count + 1:04d}'
    item = Item(
        user_id=user_id,
        code=code,
        name=name,
        retail_price=round(float(retail_price or 0) or (float(tp) / 0.85), 2),
        tp=float(tp),
        tax_pct=float(tax_pct or 0),
        discount_pct=float(discount_pct or 0),
        bonus_text=bonus_text or '',
    )
    db.session.add(item)
    db.session.flush()
    return item

def _adjust_stock(lines, delta):
    """delta = -1 to deduct (on create/update), +1 to restore (on delete/cancel)."""
    for line in lines:
        if line.item_id:
            item = Item.query.get(line.item_id)
            if item:
                item.qty = round(float(item.qty or 0) + delta * float(line.qty), 3)

def next_invoice_number():
    s = get_user_settings()
    prefix = s.invoice_prefix if s and s.invoice_prefix else 'INV'
    # Always use the highest ever-issued number (including cancelled) — numbers are never reused
    all_invs = Invoice.query.filter(
        Invoice.invoice_number.like(f'{prefix}-%')
    ).all()
    num = 1
    for inv in all_invs:
        try:
            n = int(inv.invoice_number.split('-')[-1])
            if n >= num:
                num = n + 1
        except (ValueError, IndexError):
            continue
    return f'{prefix}-{num:04d}'

@app.route('/api/invoices', methods=['GET'])
def get_invoices():
    uid = session.get('user_id')
    if not uid:
        return jsonify({'items': [], 'total': 0, 'offset': 0, 'limit': 100})
    cust_id = request.args.get('customer_id')
    offset = max(0, int(request.args.get('offset', 0)))
    limit = min(max(1, int(request.args.get('limit', 100))), 500)
    query = Invoice.query.filter(Invoice.status != 'deleted').filter_by(user_id=uid)
    query = query.order_by(Invoice.id.desc())
    if cust_id:
        query = query.filter_by(customer_id=int(cust_id)).limit(5)
    else:
        total = query.count()
        query = query.offset(offset).limit(limit)
        invoices = query.all()
        return jsonify({
            'items': [inv.to_dict() for inv in invoices],
            'total': total,
            'offset': offset,
            'limit': limit
        })
    invoices = query.all()
    return jsonify([inv.to_dict() for inv in invoices])

@app.route('/api/invoices', methods=['POST'])
def create_invoice():
    if session.get('is_guest'):
        return jsonify({'error': 'Guest invoices are stored locally in your browser.'}), 403
    if _cfg('invoicing_open', '1') == '0':
        return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    uid = session.get('user_id')
    if uid:
        u = User.query.get(uid)
        if u and not u.perm_bill:
            return jsonify({'error': 'You have been locked for this action. Contact your Admin.', 'locked': True}), 403
    data = request.get_json()
    cust_id = data.get('customer_id') or None
    cust_name = (data.get('customer_name') or '').strip() or 'Walk-in'
    inv = Invoice(
        user_id=session.get('user_id'),
        invoice_number=next_invoice_number(),
        customer_id=cust_id,
        customer_name_snap=cust_name,
        invoice_date=date.today(),
        notes=data.get('notes', '').strip(),
        previous_balance=float(db.session.query(func.sum(Invoice.total)).filter(
            Invoice.customer_id == cust_id, Invoice.status != 'cancelled'
        ).scalar() or 0) if cust_id else 0,
    )
    db.session.add(inv)
    db.session.flush()  # get inv.id

    for line_data in data.get('lines', []):
        item = Item.query.get(line_data.get('item_id')) if line_data.get('item_id') else None
        # Auto-save custom items to catalog
        if not item and line_data.get('item_name', '').strip():
            item = _ensure_item_exists(
                name=line_data['item_name'].strip(),
                tp=float(line_data.get('tp', 0)),
                retail_price=float(line_data.get('retail', 0)),
                tax_pct=float(line_data.get('tax_pct', 0) or 0),
                discount_pct=float(line_data.get('discount_pct', 0) or 0),
                bonus_text=line_data.get('bonus_text', '') or '',
                user_id=session.get('user_id'),
            )
        line = InvoiceLine(
            invoice_id=inv.id,
            item_id=item.id if item else None,
            item_name=line_data.get('item_name', item.name if item else ''),
            item_code=line_data.get('item_code', item.code if item else ''),
            qty=float(line_data.get('qty', 1)),
            tp=float(line_data.get('tp', item.tp if item else 0)),
            discount_pct=float(line_data.get('discount_pct', item.discount_pct if item else 0) or 0),
            bonus_text=line_data.get('bonus_text', item.bonus_text if item else '') or '',
            tax_pct=float(line_data.get('tax_pct', item.tax_pct if item else 0) or 0),
        )
        line.calculate_line_net()
        db.session.add(line)

    inv.recalculate_totals()
    inv.discount_amount = float(data.get('discount_amount', 0) or 0)
    inv.total = round(float(inv.subtotal) + float(inv.tax_amount) - inv.discount_amount, 2)

    db.session.flush()
    _adjust_stock(inv.lines, -1)
    db.session.commit()
    return jsonify(inv.to_dict()), 201

@app.route('/api/invoices/<int:inv_id>', methods=['GET'])
def get_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>', methods=['PUT'])
def update_invoice(inv_id):
    if session.get('is_guest'):
        return jsonify({'error': 'Guests cannot update server invoices.'}), 403
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status in ('finalised', 'cancelled'):
        label = 'Finalised' if inv.status == 'finalised' else 'Cancelled'
        return jsonify({'error': f'Cannot edit a {label} invoice. Unlock it first from Admin page.'}), 400
    data = request.get_json()

    inv.customer_id = data.get('customer_id') or None
    inv.customer_name_snap = (data.get('customer_name') or '').strip() or 'Walk-in'
    inv.notes = data.get('notes', '').strip()
    inv.discount_amount = float(data.get('discount_amount', 0) or 0)

    # Restore stock for old lines before replacing
    _adjust_stock(inv.lines, +1)
    # Replace all lines
    for line in inv.lines:
        db.session.delete(line)
    db.session.flush()

    for line_data in data.get('lines', []):
        item = Item.query.get(line_data.get('item_id')) if line_data.get('item_id') else None
        # Auto-save custom items to catalog
        if not item and line_data.get('item_name', '').strip():
            item = _ensure_item_exists(
                name=line_data['item_name'].strip(),
                tp=float(line_data.get('tp', 0)),
                retail_price=float(line_data.get('retail', 0)),
                tax_pct=float(line_data.get('tax_pct', 0) or 0),
                discount_pct=float(line_data.get('discount_pct', 0) or 0),
                bonus_text=line_data.get('bonus_text', '') or '',
                user_id=session.get('user_id'),
            )
        line = InvoiceLine(
            invoice_id=inv.id,
            item_id=item.id if item else None,
            item_name=line_data.get('item_name', item.name if item else ''),
            item_code=line_data.get('item_code', item.code if item else ''),
            qty=float(line_data.get('qty', 1)),
            tp=float(line_data.get('tp', item.tp if item else 0)),
            discount_pct=float(line_data.get('discount_pct', 0) or 0),
            bonus_text=line_data.get('bonus_text', '') or '',
            tax_pct=float(line_data.get('tax_pct', 0) or 0),
        )
        line.calculate_line_net()
        db.session.add(line)

    db.session.flush()  # write new lines to DB so inv.lines reloads correctly below
    inv.recalculate_totals()
    inv.total = round(float(inv.subtotal) + float(inv.tax_amount) - inv.discount_amount, 2)
    db.session.flush()
    _adjust_stock(inv.lines, -1)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>', methods=['DELETE'])
def delete_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status != 'draft':
        label = {'posted': 'Pending Delivery', 'finalised': 'Finalised', 'cancelled': 'Cancelled'}.get(inv.status, inv.status)
        return jsonify({'error': f'Cannot delete a {label} invoice. Only pending (draft) invoices can be deleted.'}), 400
    # Soft delete — keeps record so invoice number is permanently retired and never reused
    _adjust_stock(inv.lines, +1)
    inv.status = 'deleted'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin')
@app.route('/admin/sales')
def admin_sales():
    return render_template('admin/sales.html')

@app.route('/admin/customers')
def admin_customers():
    return render_template('admin/customers.html')

@app.route('/admin/purchase')
def admin_purchase():
    return render_template('admin/purchase.html')

@app.route('/admin/setup')
def admin_setup():
    return render_template('admin/setup.html')

@app.route('/admin/suppliers')
def admin_suppliers():
    return render_template('admin/suppliers.html')


@app.route('/api/invoices/<int:inv_id>/unpost', methods=['POST'])
def unpost_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status not in ('posted', 'finalised'):
        return jsonify({'error': 'Invoice cannot be unlocked'}), 400
    inv.status = 'draft'
    # Reverse customer balance (only the net due that was added)
    if inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            net_due = round(float(inv.total) - float(inv.amount_paid or 0), 2)
            c.balance = round(float(c.balance or 0) - net_due, 2)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/cancel', methods=['POST'])
def cancel_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status in ('cancelled', 'deleted'):
        return jsonify({'error': 'Already cancelled'}), 400
    was_posted = inv.status == 'posted'
    inv.status = 'cancelled'
    if was_posted and inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            net_due = round(float(inv.total) - float(inv.amount_paid or 0), 2)
            c.balance = round(float(c.balance or 0) - net_due, 2)
    _adjust_stock(inv.lines, +1)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/finalise', methods=['POST'])
def finalise_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status != 'posted':
        return jsonify({'error': 'Only Pending Delivery invoices can be finalised'}), 400
    inv.status = 'finalised'
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/post', methods=['POST'])
def post_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    uid = session.get('user_id')
    if uid and inv.user_id and inv.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if inv.status in ('posted', 'finalised', 'cancelled'):
        return jsonify({'error': 'Invoice is already saved or finalised'}), 400
    data = request.get_json(silent=True) or {}
    amount_paid = round(float(data.get('amount_paid', 0) or 0), 2)
    inv.amount_paid = amount_paid
    inv.status = 'posted'
    # Update customer balance: only net due (total - amount paid at billing)
    if inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            net_due = round(float(inv.total) - amount_paid, 2)
            c.balance = round(float(c.balance or 0) + net_due, 2)
    db.session.commit()
    return jsonify(inv.to_dict())


# ── Payments API ─────────────────────────────────────────────────────────────

@app.route('/api/payments/customers', methods=['GET'])
def get_customers_with_balance():
    uid = session.get('user_id')
    q = request.args.get('q', '').strip()
    query = Customer.query.filter_by(is_active=True)
    if uid:
        query = query.filter_by(user_id=uid)
    if q:
        query = query.filter(
            (Customer.name.ilike(f'%{q}%')) | (Customer.phone.ilike(f'%{q}%'))
        )
    customers = query.order_by(Customer.name).all()
    return jsonify([c.to_dict() for c in customers])


@app.route('/api/payments/billing-customers', methods=['GET'])
def get_billing_customers():
    """Return distinct named walk-in customers from invoices (typed name, no customer record).
    Balance = sum(invoice.total - invoice.amount_paid) - sum(CustomerPayment.amount for this name)
    so cash already received at billing is not double-counted."""
    uid = session.get('user_id')
    # total_billed = net due after subtracting cash already received at billing time
    query = db.session.query(
        Invoice.customer_name_snap,
        func.sum(func.coalesce(Invoice.total, 0) - func.coalesce(Invoice.amount_paid, 0)).label('total_net')
    ).filter(
        Invoice.customer_id.is_(None),
        Invoice.customer_name_snap.isnot(None),
        Invoice.customer_name_snap != '',
        Invoice.customer_name_snap != 'Walk-in',
        Invoice.status.in_(['posted', 'finalised'])
    )
    if uid:
        query = query.filter(Invoice.user_id == uid)
    q = request.args.get('q', '').strip()
    if q:
        query = query.filter(Invoice.customer_name_snap.ilike(f'%{q}%'))
    rows = query.group_by(Invoice.customer_name_snap).order_by(Invoice.customer_name_snap).all()
    result = []
    for name, total_net in rows:
        paid_q = db.session.query(func.sum(CustomerPayment.amount)).filter(
            CustomerPayment.billing_name == name,
            CustomerPayment.customer_id.is_(None)
        )
        if uid:
            paid_q = paid_q.filter(CustomerPayment.user_id == uid)
        total_paid = float(paid_q.scalar() or 0)
        net = round(float(total_net or 0), 2)
        result.append({
            'billing_name': name,
            'total_billed': net,
            'total_paid': round(total_paid, 2),
            'balance': round(net - total_paid, 2),
        })
    return jsonify(result)


@app.route('/api/payments/customer', methods=['POST'])
def add_customer_payment():
    uid = session.get('user_id')
    data = request.get_json()
    cid = data.get('customer_id')  # may be None for walk-in or billing-name
    billing_name = data.get('billing_name', '').strip() or None
    amount = round(float(data.get('amount', 0) or 0), 2)
    if amount <= 0:
        return jsonify({'error': 'Positive amount required'}), 400
    c = None
    if cid:
        c = Customer.query.get_or_404(cid)
        if c.user_id and uid and c.user_id != uid:
            return jsonify({'error': 'Access denied'}), 403
    pmt = CustomerPayment(
        user_id=uid,
        customer_id=cid if cid else None,
        billing_name=billing_name,
        amount=amount,
        payment_date=date.fromisoformat(data['payment_date']) if data.get('payment_date') else date.today(),
        notes=data.get('notes', '').strip(),
    )
    db.session.add(pmt)
    if c:
        c.balance = round(float(c.balance or 0) - amount, 2)
    db.session.commit()
    return jsonify(pmt.to_dict()), 201


@app.route('/api/payments/customer/<int:pid>', methods=['DELETE'])
def delete_customer_payment(pid):
    uid = session.get('user_id')
    pmt = CustomerPayment.query.get_or_404(pid)
    if pmt.user_id and uid and pmt.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if pmt.customer_id:
        c = Customer.query.get(pmt.customer_id)
        if c:
            c.balance = round(float(c.balance or 0) + float(pmt.amount), 2)
    db.session.delete(pmt)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/payments/customer-history', methods=['GET'])
def get_customer_payment_history():
    uid = session.get('user_id')
    cid_raw = request.args.get('customer_id', '')
    bname = request.args.get('billing_name', '').strip()
    query = CustomerPayment.query
    if uid:
        query = query.filter_by(user_id=uid)
    if bname:
        # History for a named billing customer (no customer record)
        query = query.filter(CustomerPayment.billing_name == bname, CustomerPayment.customer_id.is_(None))
    elif cid_raw == 'walkin':
        # True walk-ins: no customer_id and no billing_name
        query = query.filter(CustomerPayment.customer_id.is_(None), CustomerPayment.billing_name.is_(None))
    elif cid_raw:
        query = query.filter_by(customer_id=int(cid_raw))
    payments = query.order_by(CustomerPayment.payment_date.desc(), CustomerPayment.id.desc()).limit(100).all()
    return jsonify([p.to_dict() for p in payments])


@app.route('/api/payments/suppliers', methods=['GET'])
def get_suppliers_with_balance():
    uid = session.get('user_id')
    q = request.args.get('q', '').strip()
    query = Supplier.query.filter_by(is_active=True)
    if uid:
        query = query.filter_by(user_id=uid)
    if q:
        query = query.filter(Supplier.name.ilike(f'%{q}%'))
    suppliers = query.order_by(Supplier.name).all()
    return jsonify([s.to_dict() for s in suppliers])


@app.route('/api/payments/billing-suppliers', methods=['GET'])
def get_billing_suppliers():
    """Return distinct named suppliers from purchases that have no Supplier record."""
    uid = session.get('user_id')
    query = db.session.query(
        Purchase.supplier_name,
        func.sum(Purchase.total_cost).label('total_purchased')
    ).filter(
        Purchase.supplier_id.is_(None),
        Purchase.supplier_name.isnot(None),
        Purchase.supplier_name != '',
        Purchase.supplier_name != 'Counter'
    )
    if uid:
        query = query.filter(Purchase.user_id == uid)
    q = request.args.get('q', '').strip()
    if q:
        query = query.filter(Purchase.supplier_name.ilike(f'%{q}%'))
    rows = query.group_by(Purchase.supplier_name).order_by(Purchase.supplier_name).all()
    result = []
    for name, total_purchased in rows:
        paid_q = db.session.query(func.sum(SupplierPayment.amount)).filter(
            SupplierPayment.billing_name == name,
            SupplierPayment.supplier_id.is_(None)
        )
        if uid:
            paid_q = paid_q.filter(SupplierPayment.user_id == uid)
        total_paid = float(paid_q.scalar() or 0)
        net = round(float(total_purchased or 0), 2)
        result.append({
            'billing_name': name,
            'total_purchased': net,
            'total_paid': round(total_paid, 2),
            'balance': round(net - total_paid, 2),
        })
    return jsonify(result)


@app.route('/api/payments/supplier', methods=['POST'])
def add_supplier_payment():
    uid = session.get('user_id')
    data = request.get_json()
    sid = data.get('supplier_id')
    billing_name = data.get('billing_name', '').strip() or None
    amount = round(float(data.get('amount', 0) or 0), 2)
    if amount <= 0:
        return jsonify({'error': 'Positive amount required'}), 400
    s = None
    if sid:
        s = Supplier.query.get_or_404(sid)
        if s.user_id and uid and s.user_id != uid:
            return jsonify({'error': 'Access denied'}), 403
    pmt = SupplierPayment(
        user_id=uid,
        supplier_id=sid if sid else None,
        billing_name=billing_name,
        amount=amount,
        payment_date=date.fromisoformat(data['payment_date']) if data.get('payment_date') else date.today(),
        notes=data.get('notes', '').strip(),
    )
    db.session.add(pmt)
    if s:
        s.balance = round(float(s.balance or 0) - amount, 2)
    db.session.commit()
    return jsonify(pmt.to_dict()), 201


@app.route('/api/payments/supplier/<int:pid>', methods=['DELETE'])
def delete_supplier_payment(pid):
    uid = session.get('user_id')
    pmt = SupplierPayment.query.get_or_404(pid)
    if pmt.user_id and uid and pmt.user_id != uid:
        return jsonify({'error': 'Access denied'}), 403
    if pmt.supplier_id:
        s = Supplier.query.get(pmt.supplier_id)
        if s:
            s.balance = round(float(s.balance or 0) + float(pmt.amount), 2)
    db.session.delete(pmt)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/payments/supplier-history', methods=['GET'])
def get_supplier_payment_history():
    uid = session.get('user_id')
    sid_raw = request.args.get('supplier_id', '')
    bname = request.args.get('billing_name', '').strip()
    query = SupplierPayment.query
    if uid:
        query = query.filter_by(user_id=uid)
    if bname:
        query = query.filter(SupplierPayment.billing_name == bname, SupplierPayment.supplier_id.is_(None))
    elif sid_raw:
        query = query.filter_by(supplier_id=int(sid_raw))
    payments = query.order_by(SupplierPayment.payment_date.desc(), SupplierPayment.id.desc()).limit(100).all()
    return jsonify([p.to_dict() for p in payments])


@app.route('/api/payments/customer-invoices', methods=['GET'])
def get_customer_invoices():
    """Return all posted invoices for a customer with FIFO payment allocation (oldest first)."""
    uid = session.get('user_id')
    cid_raw = request.args.get('customer_id', '').strip()
    bname = request.args.get('billing_name', '').strip()
    if not cid_raw and not bname:
        return jsonify([])
    q = Invoice.query.filter(Invoice.status.in_(['posted', 'finalised']))
    if uid:
        q = q.filter_by(user_id=uid)
    if bname:
        q = q.filter(Invoice.customer_id.is_(None), Invoice.customer_name_snap == bname)
    else:
        q = q.filter_by(customer_id=int(cid_raw))
    invoices = q.order_by(Invoice.invoice_date.asc(), Invoice.id.asc()).all()
    # Total payments received via CustomerPayment records
    pq = db.session.query(func.sum(CustomerPayment.amount))
    if uid:
        pq = pq.filter(CustomerPayment.user_id == uid)
    if bname:
        pq = pq.filter(CustomerPayment.billing_name == bname, CustomerPayment.customer_id.is_(None))
    else:
        pq = pq.filter(CustomerPayment.customer_id == int(cid_raw))
    total_paid = float(pq.scalar() or 0)
    # FIFO: apply payments to oldest invoices first
    pool = round(total_paid, 2)
    result = []
    for inv in invoices:
        net_due = round(float(inv.total or 0) - float(inv.amount_paid or 0), 2)
        if net_due <= 0:
            remaining, pay_status = 0.0, 'paid'
        elif pool >= net_due:
            remaining, pay_status = 0.0, 'paid'
            pool = round(pool - net_due, 2)
        elif pool > 0:
            remaining = round(net_due - pool, 2)
            pay_status = 'partial'
            pool = 0.0
        else:
            remaining, pay_status = net_due, 'unpaid'
        result.append({
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'invoice_date': inv.invoice_date.isoformat(),
            'total': float(inv.total or 0),
            'amount_paid_at_billing': float(inv.amount_paid or 0),
            'net_due': net_due,
            'remaining': remaining,
            'pay_status': pay_status,
        })
    return jsonify(result)


@app.route('/api/payments/supplier-purchases', methods=['GET'])
def get_supplier_purchases():
    """Return all purchases for a supplier with FIFO payment allocation (oldest first)."""
    uid = session.get('user_id')
    sid_raw = request.args.get('supplier_id', '').strip()
    bname = request.args.get('billing_name', '').strip()
    if not sid_raw and not bname:
        return jsonify([])
    q = Purchase.query
    if uid:
        q = q.filter_by(user_id=uid)
    if bname:
        q = q.filter(Purchase.supplier_id.is_(None), Purchase.supplier_name == bname)
    else:
        q = q.filter_by(supplier_id=int(sid_raw))
    purchases = q.order_by(Purchase.purchase_date.asc(), Purchase.id.asc()).all()
    # Total payments made via SupplierPayment records
    pq = db.session.query(func.sum(SupplierPayment.amount))
    if uid:
        pq = pq.filter(SupplierPayment.user_id == uid)
    if bname:
        pq = pq.filter(SupplierPayment.billing_name == bname, SupplierPayment.supplier_id.is_(None))
    else:
        pq = pq.filter(SupplierPayment.supplier_id == int(sid_raw))
    total_paid = float(pq.scalar() or 0)
    # FIFO: apply payments to oldest purchases first
    pool = round(total_paid, 2)
    result = []
    for p in purchases:
        cost = round(float(p.total_cost or 0), 2)
        if cost <= 0:
            remaining, pay_status = 0.0, 'paid'
        elif pool >= cost:
            remaining, pay_status = 0.0, 'paid'
            pool = round(pool - cost, 2)
        elif pool > 0:
            remaining = round(cost - pool, 2)
            pay_status = 'partial'
            pool = 0.0
        else:
            remaining, pay_status = cost, 'unpaid'
        result.append({
            'id': p.id,
            'purchase_number': p.purchase_number,
            'purchase_date': p.purchase_date.isoformat(),
            'total_cost': cost,
            'remaining': remaining,
            'pay_status': pay_status,
        })
    return jsonify(result)


@app.route('/api/payments/all-customer-payments', methods=['GET'])
def get_all_customer_payments():
    uid = session.get('user_id')
    query = CustomerPayment.query
    if uid:
        query = query.filter_by(user_id=uid)
    payments = query.order_by(CustomerPayment.payment_date.desc(), CustomerPayment.id.desc()).limit(200).all()
    return jsonify([p.to_dict() for p in payments])


@app.route('/api/payments/all-supplier-payments', methods=['GET'])
def get_all_supplier_payments():
    uid = session.get('user_id')
    query = SupplierPayment.query
    if uid:
        query = query.filter_by(user_id=uid)
    payments = query.order_by(SupplierPayment.payment_date.desc(), SupplierPayment.id.desc()).limit(200).all()
    return jsonify([p.to_dict() for p in payments])


_scan_usage = {}  # {user_id_or_ip: [timestamps]}

@app.route('/api/scan-bill', methods=['POST'])
def scan_bill():
    import base64 as _b64, json as _json, time as _time

    uid = session.get('user_id') or get_client_ip()
    s = get_user_settings()

    # Resolve Gemini key: user's dedicated field → .env fallback
    gemini_key = (s.gemini_api_key or '').strip() if s else ''
    if not gemini_key:
        gemini_key = os.environ.get('GEMINI_API_KEY', '').strip()

    # Resolve Groq key: user's dedicated field → .env fallback
    groq_key = (s.groq_api_key or '').strip() if s else ''
    if not groq_key:
        groq_key = os.environ.get('GROQ_API_KEY', '').strip()

    if not gemini_key and not groq_key:
        return jsonify({'error': 'No scan API key configured. Add a Gemini (AIza...) or Groq (gsk_...) key in Admin → Setup.'}), 503

    # Rate limit on shared keys
    using_shared = (gemini_key == os.environ.get('GEMINI_API_KEY','').strip()) or \
                   (groq_key == os.environ.get('GROQ_API_KEY','').strip())
    if using_shared:
        now = _time.time()
        hits = [t for t in _scan_usage.get(uid, []) if now - t < 3600]
        if len(hits) >= 20:
            return jsonify({'error': 'Hourly scan limit reached (20/hr). Add your own free key in Admin → Setup.'}), 429
        hits.append(now)
        _scan_usage[uid] = hits

    if 'file' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400

    raw = f.read()
    if len(raw) > 10 * 1024 * 1024:
        return jsonify({'error': 'Image too large (max 10 MB)'}), 400

    # Preprocess image: auto-rotate (EXIF), enhance contrast & sharpness
    try:
        from PIL import Image as _PILImage, ImageEnhance as _PILEnhance, ImageOps as _PILOps
        import io as _io
        pil_img = _PILImage.open(_io.BytesIO(raw))
        pil_img = _PILOps.exif_transpose(pil_img)          # fix rotation from phone camera
        pil_img = pil_img.convert('RGB')
        pil_img = _PILEnhance.Contrast(pil_img).enhance(1.6)
        pil_img = _PILEnhance.Sharpness(pil_img).enhance(2.0)
        buf = _io.BytesIO()
        pil_img.save(buf, format='JPEG', quality=92)
        raw = buf.getvalue()
    except Exception:
        pass  # if preprocessing fails, send original

    media_type = 'image/jpeg'
    img_b64 = _b64.standard_b64encode(raw).decode('utf-8')

    system_msg = (
        'You are an expert Pakistani pharmacy and medical supplier bill parser. '
        'Your job is to read supplier estimate/invoice images and extract structured data with 100% accuracy. '
        'Bills are printed thermal receipts with columns: Quantity | Item Description | Packing | S.# | Tax | Retail | Rate | Disc% | Net Amount. '
        'Always return valid JSON only — no explanation, no markdown, no extra text. '
        'Read the bill correctly even if it is rotated, sideways, or partially blurry.'
    )

    prompt = (
        'Extract ALL data from this pharmacy supplier bill image.\n'
        'Return ONLY this exact JSON structure with no extra text:\n'
        '{\n'
        '  "supplier_name": "name printed on bill or null",\n'
        '  "invoice_number": "invoice/estimate number or null",\n'
        '  "date": "date as printed or null",\n'
        '  "items": [\n'
        '    {\n'
        '      "item_name": "medicine name EXACTLY as printed",\n'
        '      "qty": <integer>,\n'
        '      "retail": <retail price number or null>,\n'
        '      "rate": <rate/TP number or null>,\n'
        '      "disc_pct": <discount percentage number or null>,\n'
        '      "amount": <net amount number or null>\n'
        '    }\n'
        '  ],\n'
        '  "total": <total amount or null>,\n'
        '  "previous_balance": <previous balance or null>\n'
        '}\n\n'
        'RULES:\n'
        '- Include EVERY single item row visible — never skip any\n'
        '- qty=1 only if truly unreadable\n'
        '- item_name must be the exact medicine name, clean and complete\n'
        '- Numbers must be actual numbers, not strings\n'
        '- null for any field not visible in the bill'
    )

    raw_text = None

    # Try Gemini first (better vision quality)
    if gemini_key:
        try:
            from google import genai as _genai
            from google.genai import types as _gtypes
            _gc = _genai.Client(api_key=gemini_key)
            full_prompt = system_msg + '\n\n' + prompt
            _gr = _gc.models.generate_content(
                model='gemini-2.0-flash',
                contents=[
                    _gtypes.Part.from_bytes(data=raw, mime_type=media_type),
                    full_prompt
                ]
            )
            raw_text = _gr.text.strip()
            print('[ScanBill] Used Gemini')
        except Exception as e:
            print(f'[ScanBill] Gemini failed: {e}, trying Groq...')
            raw_text = None

    # Fallback to Groq
    if not raw_text and groq_key:
        try:
            from groq import Groq as _Groq
            client = _Groq(api_key=groq_key)
            resp = client.chat.completions.create(
                model='meta-llama/llama-4-scout-17b-16e-instruct',
                messages=[
                    {'role': 'system', 'content': system_msg},
                    {
                        'role': 'user',
                        'content': [
                            {'type': 'image_url', 'image_url': {'url': f'data:{media_type};base64,{img_b64}'}},
                            {'type': 'text', 'text': prompt}
                        ]
                    }
                ],
                max_tokens=2048,
                temperature=0.1
            )
            raw_text = resp.choices[0].message.content.strip()
            print('[ScanBill] Used Groq')
        except Exception as e:
            err_str = str(e)
            if '429' in err_str:
                return jsonify({'error': 'Rate limit hit. Please wait 30 seconds and try again.'}), 429
            return jsonify({'error': f'AI service error: {err_str[:200]}'}), 502

    if not raw_text:
        return jsonify({'error': 'All scan engines failed. Check your API keys.'}), 502

    # Strip markdown code fences if present
    if '```' in raw_text:
        parts = raw_text.split('```')
        for p in parts:
            p = p.strip()
            if p.startswith('json'):
                p = p[4:].strip()
            if p.startswith('{'):
                raw_text = p
                break

    try:
        data = _json.loads(raw_text)
    except Exception:
        return jsonify({'error': 'Could not read bill data from image. Try a clearer photo.'}), 422

    uid = session.get('user_id')

    # Match customer
    matched_customer = None
    cname = (data.get('customer_name') or '').strip()
    if cname:
        # Try customers table first
        cust = Customer.query.filter(
            Customer.name.ilike(f'%{cname}%'),
            db.or_(Customer.user_id == uid, Customer.user_id == None)
        ).first()
        if cust:
            matched_customer = cust.to_dict()

    # Load per-user item customisations for matching
    user_discounts = {}
    user_overrides = {}
    if uid:
        for ud in UserItemDiscount.query.filter_by(user_id=uid).all():
            user_discounts[ud.item_id] = float(ud.discount_pct or 0)
        for ov in UserItemOverride.query.filter_by(user_id=uid).all():
            user_overrides[ov.item_id] = ov

    def _item_dict(item):
        d = item.to_dict()
        if item.is_global and uid:
            d['discount_pct'] = user_discounts.get(item.id, 0)
            ov = user_overrides.get(item.id)
            if ov:
                if ov.tp is not None:           d['tp']           = float(ov.tp)
                if ov.retail_price is not None: d['retail_price'] = float(ov.retail_price)
                if ov.tax_pct is not None:      d['tax_pct']      = float(ov.tax_pct)
                if ov.bonus_text is not None:   d['bonus_text']   = ov.bonus_text
        return d

    matched_items = []
    unmatched = []

    # Also match supplier name (new schema uses supplier_name)
    if not matched_customer:
        sname = (data.get('supplier_name') or '').strip()
        if sname:
            cust = Customer.query.filter(
                Customer.name.ilike(f'%{sname}%'),
                db.or_(Customer.user_id == uid, Customer.user_id == None)
            ).first()
            if cust:
                matched_customer = cust.to_dict()

    for bill_item in data.get('items', []):
        # Support both new schema (item_name) and old (name)
        iname = (bill_item.get('item_name') or bill_item.get('name') or '').strip()
        if not iname:
            continue
        try:
            qty = max(1, int(float(bill_item.get('qty') or bill_item.get('quantity') or 1)))
        except (ValueError, TypeError):
            qty = 1
        bill_retail = bill_item.get('retail') or bill_item.get('rate') or None
        bill_rate   = bill_item.get('rate')   or bill_item.get('retail') or None
        try:
            bill_retail = round(float(bill_retail), 2) if bill_retail else None
            bill_rate   = round(float(bill_rate),   2) if bill_rate   else None
        except (ValueError, TypeError):
            bill_retail = bill_rate = None

        if session.get('is_superadmin') or session.get('is_guest') or not uid:
            base_q = Item.query.filter_by(is_active=True, is_global=True)
        else:
            base_q = Item.query.filter_by(is_active=True).filter(
                db.or_(Item.user_id == uid, Item.is_global == True)
            )

        import re as _re
        def _clean(s):
            return _re.sub(r'[^a-z0-9 ]', '', s.lower().strip())

        clean_name = _clean(iname)

        # 1. Full cleaned name substring match
        item = base_q.filter(Item.name.ilike(f'%{iname}%')).first()

        # 2. Try each consecutive pair of significant words
        if not item:
            words = [w for w in clean_name.split() if len(w) > 2]
            for i in range(len(words) - 1):
                item = base_q.filter(
                    Item.name.ilike(f'%{words[i]}%'),
                    Item.name.ilike(f'%{words[i+1]}%')
                ).first()
                if item:
                    break

        # 3. Best single-word match (longest word first for precision)
        if not item:
            for w in sorted(words, key=len, reverse=True):
                if len(w) > 3:
                    item = base_q.filter(Item.name.ilike(f'%{w}%')).first()
                    if item:
                        break

        if item:
            d = _item_dict(item)
            d['qty'] = qty
            # Override catalog values with bill values where available
            if bill_retail:
                d['retail_price'] = bill_retail
            if bill_rate:
                d['tp'] = bill_rate
            try:
                bill_disc = float(bill_item.get('disc_pct') or 0)
                if bill_disc:
                    d['discount_pct'] = bill_disc
            except (ValueError, TypeError):
                pass
            matched_items.append(d)
        else:
            try:
                bill_disc = float(bill_item.get('disc_pct') or 0)
            except (ValueError, TypeError):
                bill_disc = 0
            unmatched.append({
                'name': iname, 'qty': qty,
                'retail': bill_retail,
                'rate': bill_rate,
                'disc_pct': bill_disc
            })

    return jsonify({
        'customer': matched_customer,
        'items': matched_items,
        'unmatched': unmatched
    })


import click

@app.cli.command('create-superadmin')
def create_superadmin_cmd():
    """Create the super admin user (Admin / 2525)."""
    existing = User.query.filter_by(username='Admin').first()
    if existing:
        if not existing.is_superadmin:
            existing.is_superadmin = True
            db.session.commit()
            click.echo('Updated existing Admin user → superadmin.')
        else:
            click.echo('Superadmin already exists.')
        return
    sa = User(username='Admin', password_hash=generate_password_hash('2525'), is_superadmin=True)
    db.session.add(sa)
    db.session.commit()
    click.echo('Superadmin created: username=Admin  password=2525')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
