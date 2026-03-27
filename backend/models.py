from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy
from decimal import Decimal

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    is_suspended = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'username': self.username}


class PasswordResetRequest(db.Model):
    __tablename__ = 'password_reset_requests'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending / resolved / dismissed
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)


class GuestLimit(db.Model):
    __tablename__ = 'guest_limits'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, index=True)
    invoice_count = db.Column(db.Integer, default=0)
    window_start = db.Column(db.DateTime, default=datetime.utcnow)


class Settings(db.Model):
    __tablename__ = 'settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    shop_name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(30))
    whatsapp = db.Column(db.String(30))
    ntn = db.Column(db.String(30))
    default_discount_pct = db.Column(db.Numeric(5, 2), default=0)
    invoice_prefix = db.Column(db.String(10), default='INV')
    admin_password_hash = db.Column(db.String(200))
    admin_reset_requested_at = db.Column(db.DateTime, nullable=True)
    admin_password_is_temp = db.Column(db.Boolean, default=False)
    admin_failed_attempts = db.Column(db.Integer, default=0)
    admin_locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'shop_name': self.shop_name,
            'address': self.address,
            'phone': self.phone,
            'whatsapp': self.whatsapp,
            'ntn': self.ntn,
            'default_discount_pct': float(self.default_discount_pct or 0),
            'invoice_prefix': self.invoice_prefix,
            'admin_password_set': bool(self.admin_password_hash),
            'setup_completed': bool(self.shop_name and self.address and self.phone and self.whatsapp),
        }


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship('Item', backref='category', lazy=True)

    def to_dict(self):
        return {'id': self.id, 'name': self.name}


class Item(db.Model):
    __tablename__ = 'items'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)  # NULL = global
    is_global = db.Column(db.Boolean, default=False)  # True = admin-added, shared with all
    code = db.Column(db.String(30), nullable=False)
    name = db.Column(db.String(200), nullable=False, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    retail_price = db.Column(db.Numeric(10, 2), nullable=False)
    tp = db.Column(db.Numeric(10, 2), nullable=False)          # Trade Price (retail - 15% by default)
    discount_pct = db.Column(db.Numeric(5, 2), default=0)     # Extra discount on top of TP
    bonus_text = db.Column(db.String(100))                     # e.g. "5+5", "1 free on 10"
    tax_pct = db.Column(db.Numeric(5, 2), default=0)
    qty = db.Column(db.Numeric(10, 3), default=0)   # Stock quantity
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'code', name='uq_item_user_code'),)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'is_global': bool(self.is_global),
            'code': self.code,
            'name': self.name,
            'category_id': self.category_id,
            'category': self.category.name if self.category else None,
            'retail_price': float(self.retail_price),
            'tp': float(self.tp),
            'discount_pct': float(self.discount_pct or 0),
            'bonus_text': self.bonus_text or '',
            'tax_pct': float(self.tax_pct or 0),
            'qty': float(self.qty or 0),
            'is_active': self.is_active,
        }

    @staticmethod
    def tp_from_retail(retail_price):
        """Calculate default TP: retail minus 15%"""
        return round(float(retail_price) * 0.85, 2)


class UserItemDiscount(db.Model):
    """Per-user discount rates for shared items"""
    __tablename__ = 'user_item_discounts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    discount_pct = db.Column(db.Numeric(5, 2), default=0)

    __table_args__ = (db.UniqueConstraint('user_id', 'item_id'),)


class Customer(db.Model):
    __tablename__ = 'customers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(30))
    whatsapp = db.Column(db.String(30))
    address = db.Column(db.Text)
    credit_limit = db.Column(db.Numeric(10, 2), default=0)
    balance = db.Column(db.Numeric(10, 2), default=0)   # positive = customer owes you
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    invoices = db.relationship('Invoice', backref='customer', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone or '',
            'whatsapp': self.whatsapp or '',
            'address': self.address or '',
            'credit_limit': float(self.credit_limit or 0),
            'balance': float(self.balance or 0),
            'notes': self.notes or '',
            'is_active': self.is_active,
        }


class Supplier(db.Model):
    __tablename__ = 'suppliers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(30))
    address = db.Column(db.Text)
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone or '',
            'address': self.address or '',
            'notes': self.notes or '',
        }


class Purchase(db.Model):
    __tablename__ = 'purchases'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    purchase_number = db.Column(db.String(30), unique=True, nullable=False)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=True)
    supplier_name = db.Column(db.String(150), default='Counter')
    purchase_date = db.Column(db.Date, nullable=False, default=date.today)
    total_cost = db.Column(db.Numeric(10, 2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    lines = db.relationship('PurchaseLine', backref='purchase', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'purchase_number': self.purchase_number,
            'supplier_name': self.supplier_name,
            'purchase_date': self.purchase_date.isoformat(),
            'total_cost': float(self.total_cost or 0),
            'lines': [l.to_dict() for l in self.lines],
        }


class PurchaseLine(db.Model):
    __tablename__ = 'purchase_lines'

    id = db.Column(db.Integer, primary_key=True)
    purchase_id = db.Column(db.Integer, db.ForeignKey('purchases.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=True)
    item_name = db.Column(db.String(200), nullable=False)
    qty = db.Column(db.Numeric(10, 3), nullable=False)
    tp = db.Column(db.Numeric(10, 2), default=0)
    retail = db.Column(db.Numeric(10, 2), default=0)
    disc_pct = db.Column(db.Numeric(5, 2), default=0)
    tax = db.Column(db.Numeric(10, 2), default=0)
    line_total = db.Column(db.Numeric(10, 2), default=0)

    def to_dict(self):
        return {
            'item_id': self.item_id,
            'item_name': self.item_name,
            'qty': float(self.qty),
            'tp': float(self.tp or 0),
            'retail': float(self.retail or 0),
            'disc_pct': float(self.disc_pct or 0),
            'tax': float(self.tax or 0),
            'line_total': float(self.line_total or 0),
        }


class Invoice(db.Model):
    __tablename__ = 'invoices'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    invoice_number = db.Column(db.String(30), unique=True, nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=True)
    customer_name_snap = db.Column(db.String(150))   # stored at invoice time
    invoice_date = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(20), default='draft')   # draft / posted / cancelled
    previous_balance = db.Column(db.Numeric(10, 2), default=0)  # customer balance before this invoice
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    discount_amount = db.Column(db.Numeric(10, 2), default=0)
    tax_amount = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    lines = db.relationship('InvoiceLine', backref='invoice', lazy=True,
                            cascade='all, delete-orphan')

    def recalculate_totals(self):
        """Recalculate and store subtotal, tax, and total from lines.
        tax_pct stores a fixed Rs. amount per unit (not a percentage)."""
        subtotal = sum(float(line.line_net) for line in self.lines)
        tax = sum(float(line.qty) * float(line.tax_pct or 0) for line in self.lines)
        self.subtotal = round(subtotal, 2)
        self.tax_amount = round(tax, 2)
        self.total = round(subtotal + tax - float(self.discount_amount or 0), 2)

    def to_dict(self):
        return {
            'id': self.id,
            'invoice_number': self.invoice_number,
            'customer_id': self.customer_id,
            'customer_name': self.customer_name_snap or 'Walk-in',
            'invoice_date': self.invoice_date.isoformat(),
            'status': self.status,
            'previous_balance': float(self.previous_balance or 0),
            'subtotal': float(self.subtotal or 0),
            'discount_amount': float(self.discount_amount or 0),
            'tax_amount': float(self.tax_amount or 0),
            'total': float(self.total or 0),
            'notes': self.notes or '',
            'lines': [line.to_dict() for line in self.lines],
        }


class InvoiceLine(db.Model):
    __tablename__ = 'invoice_lines'

    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=True)

    # Snapshots — preserve values at time of invoicing
    item_name = db.Column(db.String(200), nullable=False)
    item_code = db.Column(db.String(30))
    qty = db.Column(db.Numeric(10, 3), nullable=False)
    tp = db.Column(db.Numeric(10, 2), nullable=False)
    discount_pct = db.Column(db.Numeric(5, 2), default=0)
    bonus_text = db.Column(db.String(100))
    tax_pct = db.Column(db.Numeric(5, 2), default=0)
    line_net = db.Column(db.Numeric(10, 2), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def calculate_line_net(self):
        """qty × tp × (1 - disc%) — call this before saving."""
        gross = float(self.qty) * float(self.tp)
        disc = gross * float(self.discount_pct or 0) / 100
        self.line_net = round(gross - disc, 2)

    def to_dict(self):
        return {
            'id': self.id,
            'item_id': self.item_id,
            'item_name': self.item_name,
            'item_code': self.item_code or '',
            'qty': float(self.qty),
            'tp': float(self.tp),
            'discount_pct': float(self.discount_pct or 0),
            'bonus_text': self.bonus_text or '',
            'tax_pct': float(self.tax_pct or 0),
            'line_net': float(self.line_net),
        }
