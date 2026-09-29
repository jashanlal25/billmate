"""Password-bound device tokens, stored only in the APK's biometric vault."""
import hashlib
import hmac
import secrets
from itsdangerous import URLSafeTimedSerializer, BadData

TOKEN_MAX_AGE = 90 * 24 * 60 * 60

def _stamp(secret, user, kind, admin_hash=''):
    value = f'{user.id}\0{kind}\0{user.password_hash}\0{admin_hash}'
    return hmac.new(str(secret).encode(), value.encode(), hashlib.sha256).hexdigest()

def issue_token(secret, user, kind, admin_hash=''):
    if kind not in ('login', 'admin') or not secret:
        raise ValueError('Device login is not configured')
    return URLSafeTimedSerializer(secret, salt='billmate-device-v1').dumps({
        'uid': user.id, 'kind': kind, 'stamp': _stamp(secret, user, kind, admin_hash),
        'nonce': secrets.token_urlsafe(24),
    })

def read_token(secret, token):
    if not secret or not isinstance(token, str) or len(token) > 4096:
        raise ValueError('Invalid device token')
    try:
        payload = URLSafeTimedSerializer(secret, salt='billmate-device-v1').loads(
            token, max_age=TOKEN_MAX_AGE)
    except BadData as exc:
        raise ValueError('Expired or invalid device token') from exc
    if not isinstance(payload, dict) or type(payload.get('uid')) is not int or payload.get('kind') not in ('login', 'admin'):
        raise ValueError('Invalid device token')
    return payload

def matches_token(secret, payload, user, kind, admin_hash=''):
    return (payload.get('uid') == user.id and payload.get('kind') == kind
            and hmac.compare_digest(str(payload.get('stamp', '')),
                                    _stamp(secret, user, kind, admin_hash)))
