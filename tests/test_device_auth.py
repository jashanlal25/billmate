"""Exercise real login/admin routes with an isolated SQLite database."""
import os
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['SECRET_KEY'] = 'test-only-device-auth-secret'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
_init = SQLAlchemy.init_app
def sqlite_init(self, app):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    _init(self, app)
with patch.object(SQLAlchemy, 'init_app', sqlite_init):
    import app as service
from models import db, User, Settings
from device_auth import TOKEN_MAX_AGE
service._defaults_seeded = True

class DeviceAuthTest(unittest.TestCase):
    def setUp(self):
        self.ctx = service.app.app_context(); self.ctx.push()
        db.create_all()
        for uid, name in ((1, 'first'), (2, 'second')):
            db.session.add(User(id=uid, username=name, password_hash=generate_password_hash('account-password')))
            db.session.add(Settings(user_id=uid, shop_name='Shop', address='A', phone='1', whatsapp='1',
                                    admin_password_hash=generate_password_hash('admin-password')))
        db.session.commit()
        service._login_attempts.clear()
        self.client = service.app.test_client()

    def tearDown(self):
        db.session.remove(); db.drop_all(); self.ctx.pop()

    def login(self, enroll=True, username='first'):
        response = self.client.post('/auth/login', json={'username': username, 'password': 'account-password', 'enroll_fingerprint': enroll})
        self.assertEqual(response.status_code, 200)
        return response.json

    def admin(self, enroll=True, route='/admin/unlock', password='admin-password'):
        return self.client.post(route, json={'password': password, 'enroll_fingerprint': enroll})

    def unlock(self, token, kind='login'):
        return self.client.post('/auth/device-login', json={'kind': kind, 'token': token})

    def test_opt_in_and_logout_never_silently_restore_session(self):
        self.assertNotIn('device_token', self.login(False))
        token = self.login()['device_token']
        self.client.get('/auth/logout')
        with self.client.session_transaction() as session:
            self.assertNotIn('user_id', session)
            self.assertNotIn('is_admin', session)
        self.assertIn('formLogin', self.client.get('/').get_data(as_text=True))
        self.assertEqual(self.unlock(token).status_code, 200)
        with self.client.session_transaction() as session:
            self.assertEqual(session['user_id'], 1)
            self.assertFalse(session.get('is_admin'))

    def test_admin_is_bound_to_current_account_and_separate_from_login(self):
        login_token = self.login()['device_token']
        result = self.admin()
        self.assertEqual(result.status_code, 200)
        admin_token = result.json['device_token']
        self.assertEqual(self.unlock(login_token, 'admin').status_code, 401)
        self.assertEqual(self.unlock(admin_token, 'login').status_code, 401)
        self.client.get('/auth/logout')
        self.assertEqual(self.unlock(admin_token, 'admin').status_code, 401)
        self.login(username='second')
        self.assertEqual(self.unlock(admin_token, 'admin').status_code, 401)
        self.login()
        self.assertEqual(self.unlock(admin_token, 'admin').status_code, 200)

    def test_password_changes_invalidate_existing_enrollment(self):
        token = self.login()['device_token']
        admin_token = self.admin().json['device_token']
        settings = Settings.query.filter_by(user_id=1).one()
        settings.admin_password_hash = generate_password_hash('new-admin'); db.session.commit()
        response = self.unlock(admin_token, 'admin')
        self.assertEqual(response.status_code, 401); self.assertTrue(response.json['forget'])
        self.assertEqual(self.unlock(token).status_code, 200)
        db.session.get(User, 1).password_hash = generate_password_hash('new-account'); db.session.commit()
        self.assertEqual(self.unlock(token).status_code, 401)

    def test_tamper_expiry_and_suspension(self):
        token = self.login()['device_token']
        self.assertEqual(self.unlock(token + 'tampered').status_code, 401)
        with patch('time.time', return_value=__import__('time').time() + TOKEN_MAX_AGE + 5):
            self.assertEqual(self.unlock(token).status_code, 401)
        db.session.get(User, 1).is_suspended = True; db.session.commit()
        self.assertEqual(self.unlock(token).status_code, 403)

    def test_admin_lockout_is_shared_by_all_entry_points(self):
        self.assertEqual(self.admin(route='/auth/admin-login').status_code, 401)
        self.login()
        token = self.admin().json['device_token']
        self.assertEqual(self.admin(False, password='wrong').status_code, 401)
        self.assertEqual(self.admin(False, route='/auth/admin-login', password='wrong').status_code, 401)
        self.assertEqual(self.admin(False, password='wrong').status_code, 429)
        self.assertEqual(self.admin(False, route='/auth/admin-login').status_code, 429)
        self.assertEqual(self.unlock(token, 'admin').status_code, 429)
        settings = Settings.query.filter_by(user_id=1).one()
        settings.admin_locked_until = datetime.utcnow() - timedelta(seconds=1); db.session.commit()
        self.assertEqual(self.unlock(token, 'admin').status_code, 200)

    def test_autofill_forms_and_stable_secret_requirement(self):
        page = self.client.get('/').get_data(as_text=True)
        self.assertIn('name="username"', page)
        self.assertIn('name="password"', page)
        self.assertIn('autocomplete="current-password"', page)
        self.login()
        page = self.client.get('/admin/unlock').get_data(as_text=True)
        self.assertIn('autocomplete="section-admin current-password"', page)
        self.assertIn('value="first (admin)"', page)
        with patch.dict(os.environ, {'SECRET_KEY': ''}):
            result = self.login()
            self.assertNotIn('device_token', result)
            self.assertIn('fingerprint_error', result)

    def test_separate_setup_requires_current_account_password_and_preserves_session(self):
        self.assertEqual(self.client.post('/auth/fingerprint/token', json={'kind': 'login', 'password': 'account-password'}).status_code, 401)
        self.login(enroll=False)
        response = self.client.post('/auth/fingerprint/token', json={'kind': 'login', 'password': 'wrong', 'username': 'second'})
        self.assertEqual(response.status_code, 401)
        response = self.client.post('/auth/fingerprint/token', json={'kind': 'login', 'password': 'account-password'})
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess: self.assertEqual(sess['user_id'], 1)
        self.assertEqual(self.unlock(response.json['device_token']).status_code, 200)
        self.assertEqual(self.client.get('/auth/fingerprint/setup').status_code, 200)

    def test_separate_admin_setup_observes_lockout_and_public_association(self):
        self.login(enroll=False)
        for _ in range(3):
            self.client.post('/auth/fingerprint/token', json={'kind': 'admin', 'password': 'wrong', 'enroll_fingerprint': True})
        response = self.client.post('/auth/fingerprint/token', json={'kind': 'admin', 'password': 'admin-password', 'enroll_fingerprint': True})
        self.assertEqual(response.status_code, 429)
        self.client.get('/auth/logout')
        response = self.client.get('/.well-known/assetlinks.json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json[0]['target']['package_name'], 'com.billmate.nativeapp')

if __name__ == '__main__':
    unittest.main()
