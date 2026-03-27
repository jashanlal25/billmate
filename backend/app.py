import os
import sys

# Ensure backend/ is on the path so `models` can be imported on Vercel
base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from flask import Flask, render_template, request, jsonify, redirect, session, url_for
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
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # 7 days

# Database — must be set via DATABASE_URL environment variable
_db_url = os.environ.get('DATABASE_URL', '')
if not _db_url:
    raise RuntimeError('DATABASE_URL environment variable is not set')
# SQLAlchemy requires postgresql:// not postgres://
if _db_url.startswith('postgres://'):
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
from models import db, Settings, Category, Item, Customer, Invoice, InvoiceLine, Supplier, Purchase, PurchaseLine, User, GuestLimit, UserItemDiscount, PasswordResetRequest
db.init_app(app)
migrate = Migrate(app, db)

# ── Auth helpers ───────────────────────────────────────────────────────────────

GUEST_ALLOWED_PREFIXES = ['/billing', '/items', '/api/invoices', '/api/items',
                           '/api/settings', '/static']

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

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
    # Superadmin login page — always accessible
    if path == '/superadmin/login':
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
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
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
    return jsonify({'success': True, 'needs_setup': True})

@app.route('/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid username or password'}), 401
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
    data = request.get_json()
    password = (data.get('password') or '').strip()

    # Verify admin credentials against user's settings
    s = get_user_settings()
    if not s or not s.admin_password_hash:
        return jsonify({'error': 'Admin password not set'}), 401

    # Check the password against the admin password hash
    if check_password_hash(s.admin_password_hash, password):
        session['is_admin'] = True
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Invalid admin password'}), 401

@app.route('/auth/logout')
def auth_logout():
    session.clear()
    return redirect('/')

@app.route('/auth/superadmin-login', methods=['POST'])
def auth_superadmin_login():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    user = User.query.filter_by(username=username, is_superadmin=True).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid super admin credentials'}), 401
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

# ── Password Reset Requests ───────────────────────────────────────────────────

@app.route('/api/forgot-password-request', methods=['POST'])
def forgot_password_request():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400
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
    return render_template('items.html')

@app.route('/customers')
def customers_page():
    return render_template('customers.html')

@app.route('/billing')
def billing_page():
    return render_template('billing.html')


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
    # Superadmin sees only global items; regular users see own + global
    if session.get('is_superadmin'):
        query = Item.query.filter_by(is_active=True, is_global=True)
    else:
        query = Item.query.filter_by(is_active=True).filter(
            db.or_(Item.user_id == uid, Item.is_global == True)
        )
    if q:
        query = query.filter(Item.name.ilike(f'%{q}%'))
    items = query.order_by(Item.name).all()
    # Per-user discounts apply only to global items
    user_discounts = {}
    if uid:
        uds = UserItemDiscount.query.filter_by(user_id=uid).all()
        user_discounts = {ud.item_id: float(ud.discount_pct or 0) for ud in uds}
    result = []
    for i in items:
        d = i.to_dict()
        if i.is_global:
            d['discount_pct'] = user_discounts.get(i.id, 0)
        result.append(d)
    return jsonify(result)

@app.route('/api/items', methods=['POST'])
def add_item():
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
    data = request.get_json()
    if 'name' in data:
        item.name = data['name'].strip()
    if 'retail_price' in data:
        item.retail_price = float(data['retail_price'])
    if 'tp' in data:
        item.tp = float(data['tp'])
    if 'discount_pct' in data:
        # Save discount per-user, not on the shared item
        uid = session.get('user_id')
        if uid:
            ud = UserItemDiscount.query.filter_by(user_id=uid, item_id=iid).first()
            disc_val = float(data['discount_pct'] or 0)
            if ud:
                ud.discount_pct = disc_val
            elif disc_val:
                ud = UserItemDiscount(user_id=uid, item_id=iid, discount_pct=disc_val)
                db.session.add(ud)
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
    uid = session.get('user_id')
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
    db.session.commit()
    return jsonify(purchase.to_dict())

@app.route('/api/purchases/<int:pid>', methods=['DELETE'])
def delete_purchase(pid):
    p = Purchase.query.get_or_404(pid)
    # Reverse stock qty
    for line in p.lines:
        if line.item_id:
            item = Item.query.get(line.item_id)
            if item:
                item.qty = round(float(item.qty or 0) - float(line.qty), 3)
    db.session.delete(p)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/purchases/<int:pid>', methods=['PUT'])
def update_purchase(pid):
    p = Purchase.query.get_or_404(pid)
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
    c.is_active = False
    db.session.commit()
    return jsonify({'success': True})


# ── Invoices API ──────────────────────────────────────────────────────────────

def _ensure_item_exists(name, tp, retail_price, tax_pct):
    """Auto-create an item in the catalog if it doesn't already exist (by name)."""
    existing = Item.query.filter(Item.name.ilike(name), Item.is_active == True).first()
    if existing:
        return existing
    last = Item.query.order_by(Item.id.desc()).first()
    code = f'ITM{(last.id + 1 if last else 1):04d}'
    while Item.query.filter_by(code=code).first():
        code = code[:-4] + str(int(code[-4:]) + 1).zfill(4)
    item = Item(
        code=code,
        name=name,
        retail_price=round(float(retail_price or 0) or (float(tp) / 0.85), 2),
        tp=float(tp),
        tax_pct=float(tax_pct or 0),
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
    cust_id = request.args.get('customer_id')
    offset = max(0, int(request.args.get('offset', 0)))
    limit = min(max(1, int(request.args.get('limit', 100))), 500)
    query = Invoice.query.filter(Invoice.status != 'deleted')
    if uid:
        query = query.filter_by(user_id=uid)
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
    # Guest invoice limit: 3 per IP per 12 hours
    if session.get('is_guest'):
        ip = get_client_ip()
        now = datetime.utcnow()
        gl = GuestLimit.query.filter_by(ip_address=ip).first()
        if gl:
            if (now - gl.window_start) > timedelta(hours=12):
                gl.invoice_count = 0
                gl.window_start = now
            if gl.invoice_count >= 3:
                return jsonify({'error': 'Guest limit reached. Max 3 invoices per 12 hours. Please register for full access.'}), 403
            gl.invoice_count += 1
        else:
            gl = GuestLimit(ip_address=ip, invoice_count=1, window_start=now)
            db.session.add(gl)
        db.session.flush()
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
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>', methods=['PUT'])
def update_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
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

    inv.recalculate_totals()
    inv.total = round(float(inv.subtotal) + float(inv.tax_amount) - inv.discount_amount, 2)
    db.session.flush()
    _adjust_stock(inv.lines, -1)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>', methods=['DELETE'])
def delete_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
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
    if inv.status not in ('posted', 'finalised'):
        return jsonify({'error': 'Invoice cannot be unlocked'}), 400
    inv.status = 'draft'
    # Reverse customer balance
    if inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            c.balance = round(float(c.balance or 0) - float(inv.total), 2)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/cancel', methods=['POST'])
def cancel_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    if inv.status in ('cancelled', 'deleted'):
        return jsonify({'error': 'Already cancelled'}), 400
    was_posted = inv.status == 'posted'
    inv.status = 'cancelled'
    if was_posted and inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            c.balance = round(float(c.balance or 0) - float(inv.total), 2)
    _adjust_stock(inv.lines, +1)
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/finalise', methods=['POST'])
def finalise_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    if inv.status != 'posted':
        return jsonify({'error': 'Only Pending Delivery invoices can be finalised'}), 400
    inv.status = 'finalised'
    db.session.commit()
    return jsonify(inv.to_dict())

@app.route('/api/invoices/<int:inv_id>/post', methods=['POST'])
def post_invoice(inv_id):
    inv = Invoice.query.get_or_404(inv_id)
    if inv.status in ('posted', 'finalised', 'cancelled'):
        return jsonify({'error': 'Invoice is already saved or finalised'}), 400
    inv.status = 'posted'
    # Update customer balance
    if inv.customer_id:
        c = Customer.query.get(inv.customer_id)
        if c:
            c.balance = round(float(c.balance or 0) + float(inv.total), 2)
    db.session.commit()
    return jsonify(inv.to_dict())


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
