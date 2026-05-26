from flask_mail import Mail, Message
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from functools import wraps
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix  # ADDED for Render/Railway HTTPS
from dotenv import load_dotenv
import os
import pyotp
import qrcode
import qrcode.image.svg
import io
import json
import base64
import secrets
import re

from datetime import datetime, timedelta

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

if not os.getenv("SECRET_KEY"):
    raise Exception("SECRET_KEY not found in .env file or environment")


app = Flask(__name__)

# ADDED — tells Flask it sits behind 1 reverse proxy (Render/Railway edge)
# Without this, url_for(_external=True) generates http:// instead of https://
# which breaks Google OAuth and any absolute URL generation
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ─────────────────────────────────────────────────────────────
# Environment Flag
# ─────────────────────────────────────────────────────────────

# CHANGED — replaces the old fragile check
# Set FLASK_ENV=production in your Render/Railway environment variables
IS_PRODUCTION = os.getenv('FLASK_ENV', 'development') == 'production'

# ─────────────────────────────────────────────────────────────
# App Config
# ─────────────────────────────────────────────────────────────

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY not set in environment")

# ─────────────────────────────────────────────────────────────
# Database
# CHANGED — switched from hardcoded SQLite to environment-driven URL
# Render/Railway inject DATABASE_URL automatically when you add PostgreSQL
# Falls back to SQLite for local development when DATABASE_URL is not set
# ─────────────────────────────────────────────────────────────

_db_url = os.getenv('DATABASE_URL', 'sqlite:///vaultkey.db')
if _db_url.startswith('postgres://'):
    # Render provides 'postgres://' but SQLAlchemy requires 'postgresql://'
    _db_url = _db_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI']        = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ─────────────────────────────────────────────────────────────
# Session / Cookie Security
# CHANGED — replaced the old fragile os.getenv() != 'development' check
# ─────────────────────────────────────────────────────────────

app.config['SESSION_COOKIE_SECURE']          = IS_PRODUCTION  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY']         = True           # JS cannot read cookie
app.config['SESSION_COOKIE_SAMESITE']         = 'Lax'         # CSRF protection
app.config['SESSION_COOKIE_NAME']             = 'vk_session'  # non-obvious cookie name
app.config['PERMANENT_SESSION_LIFETIME']      = timedelta(days=7)

# ─────────────────────────────────────────────────────────────
# Google OAuth Config
# ─────────────────────────────────────────────────────────────

app.config['GOOGLE_CLIENT_ID']     = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ─────────────────────────────────────────────────────────────
# Mail Config
# ─────────────────────────────────────────────────────────────

_mail_password_raw = os.getenv('MAIL_PASSWORD', '')
_mail_password     = _mail_password_raw.replace(' ', '')

app.config['MAIL_SERVER']         = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT']           = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS']        = True
app.config['MAIL_USE_SSL']        = False
app.config['MAIL_USERNAME']       = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD']       = _mail_password
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# ─────────────────────────────────────────────────────────────
# Vault Lock Config
# ─────────────────────────────────────────────────────────────

VAULT_LOCK_TIMEOUT = int(os.getenv('VAULT_LOCK_TIMEOUT', 900))

# ─────────────────────────────────────────────────────────────
# Extensions
# ─────────────────────────────────────────────────────────────

db      = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt  = Bcrypt(app)
mail    = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# ─────────────────────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://'
)

# ─────────────────────────────────────────────────────────────
# OTP Storage (in-memory)
# ─────────────────────────────────────────────────────────────

reset_otps = {}

# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):

    __tablename__ = 'users'

    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(80),  unique=True, nullable=False)
    email               = db.Column(db.String(120), unique=True, nullable=False)
    password_hash       = db.Column(db.String(200), nullable=True)
    salt                = db.Column(db.String(64),  nullable=False)
    created_at          = db.Column(db.DateTime, default=datetime.utcnow)

    encrypted_vault_key = db.Column(db.Text, nullable=True)
    escrow_vault_key    = db.Column(db.Text, nullable=True)
    is_migrated         = db.Column(db.Boolean, default=False, nullable=False)

    google_id       = db.Column(db.String(128), unique=True, nullable=True)
    profile_picture = db.Column(db.String(500), nullable=True)

    totp_secret   = db.Column(db.String(64),  nullable=True)
    totp_enabled  = db.Column(db.Boolean, default=False, nullable=False)
    backup_codes  = db.Column(db.Text, nullable=True)

    notebooks = db.relationship(
        'Notebook',
        backref='owner',
        lazy=True,
        cascade='all, delete-orphan'
    )

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

    @property
    def is_google_user(self):
        return self.google_id is not None and self.password_hash is None

    @property
    def has_password(self):
        return self.password_hash is not None

    def get_backup_codes(self):
        if not self.backup_codes:
            return []
        try:
            return json.loads(self.backup_codes)
        except Exception:
            return []

    def set_backup_codes(self, codes_hashed):
        self.backup_codes = json.dumps(codes_hashed)

    def verify_backup_code(self, code):
        code = code.strip().upper().replace('-', '').replace(' ', '')
        hashed_list = self.get_backup_codes()
        for i, hashed in enumerate(hashed_list):
            if bcrypt.check_password_hash(hashed, code):
                hashed_list.pop(i)
                self.set_backup_codes(hashed_list)
                db.session.commit()
                return True
        return False


class PasswordResetOTP(db.Model):
    __tablename__ = 'password_reset_otps'

    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(120), nullable=False, index=True)
    otp        = db.Column(db.String(6),   nullable=False)
    expires_at = db.Column(db.DateTime,    nullable=False)


class Notebook(db.Model):

    __tablename__ = 'notebooks'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    icon        = db.Column(db.String(50),  default='shield')
    color       = db.Column(db.String(20),  default='#4f8ef7')
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    entries = db.relationship(
        'PasswordEntry',
        backref='notebook',
        lazy=True,
        cascade='all, delete-orphan'
    )


class PasswordEntry(db.Model):

    __tablename__ = 'password_entries'

    id                 = db.Column(db.Integer, primary_key=True)
    title              = db.Column(db.String(200), nullable=False)
    username           = db.Column(db.String(200), nullable=True)
    encrypted_password = db.Column(db.Text, nullable=False)
    url                = db.Column(db.String(500), nullable=True)
    notes              = db.Column(db.Text, nullable=True)
    notebook_id        = db.Column(db.Integer, db.ForeignKey('notebooks.id'), nullable=False)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at         = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


# ─────────────────────────────────────────────────────────────
# Multi-Account Session Helpers
# ─────────────────────────────────────────────────────────────

def get_accounts():
    return session.get('accounts', [])


def get_active_user_id():
    return session.get('active_user')


def get_active_account_data():
    active_id = get_active_user_id()
    if active_id is None:
        return None
    for acc in get_accounts():
        if acc['user_id'] == active_id:
            return acc
    return None


def get_active_user():
    active_id = get_active_user_id()
    if active_id is None:
        return None
    return User.query.get(active_id)


def multi_account_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if get_active_user_id() is None:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Not authenticated'}), 401
            return redirect(url_for('login_page'))
        _migrate_session_if_needed()
        return f(*args, **kwargs)
    return decorated


def _add_account_to_session(user, master_password=None):
    accounts = get_accounts()
    accounts = [a for a in accounts if a['user_id'] != user.id]

    vault_key_b64 = None
    if master_password and user.encrypted_vault_key:
        try:
            kek             = derive_kek(master_password, user.salt)
            vault_key_bytes = decrypt_vault_key(user.encrypted_vault_key, kek)
            vault_key_b64   = base64.b64encode(vault_key_bytes).decode('ascii')
        except Exception as e:
            print(f"[session] Could not derive vault key for user {user.id}: {e}")

    lock_deadline = (
        (datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)).isoformat()
        if vault_key_b64 else None
    )

    accounts.append({
        'user_id':         user.id,
        'username':        user.username,
        'email':           user.email,
        'is_google':       user.google_id is not None,
        'has_password':    user.has_password,
        'profile_picture': user.profile_picture or '',
        'vault_key':       vault_key_b64,
        'lock_deadline':   lock_deadline,
    })

    session['accounts']    = accounts
    session['active_user'] = user.id
    session.permanent      = True
    session.modified       = True


def _remove_account_from_session(user_id):
    accounts = [a for a in get_accounts() if a['user_id'] != user_id]
    session['accounts'] = accounts
    session.modified    = True

    if get_active_user_id() == user_id:
        if accounts:
            session['active_user'] = accounts[-1]['user_id']
        else:
            session.pop('active_user', None)

    return session.get('active_user')


def _migrate_session_if_needed():
    accounts = get_accounts()
    modified = False

    for acc in accounts:
        if 'master_password' in acc:
            raw_pw = acc.pop('master_password', None)
            if raw_pw:
                user = User.query.get(acc['user_id'])
                if user and user.encrypted_vault_key:
                    try:
                        kek             = derive_kek(raw_pw, user.salt)
                        vault_key_bytes = decrypt_vault_key(user.encrypted_vault_key, kek)
                        acc['vault_key']     = base64.b64encode(vault_key_bytes).decode('ascii')
                        acc['lock_deadline'] = (
                            datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)
                        ).isoformat()
                    except Exception as ex:
                        print(f"[migrate_session] user {acc['user_id']}: {ex}")
                        acc['vault_key']     = None
                        acc['lock_deadline'] = None
                else:
                    acc['vault_key']     = None
                    acc['lock_deadline'] = None
            else:
                if 'vault_key' not in acc:
                    acc['vault_key']     = None
                    acc['lock_deadline'] = None
            if 'has_password' not in acc:
                user = User.query.get(acc['user_id'])
                acc['has_password'] = user.has_password if user else False
            modified = True

        elif 'has_password' not in acc:
            user = User.query.get(acc['user_id'])
            acc['has_password'] = user.has_password if user else False
            modified = True

    if modified:
        session['accounts'] = accounts
        session.modified    = True


# ─────────────────────────────────────────────────────────────
# Vault Lock Helpers
# ─────────────────────────────────────────────────────────────

def _is_vault_locked(acc_data: dict) -> bool:
    if not acc_data or not acc_data.get('vault_key'):
        return True
    deadline_str = acc_data.get('lock_deadline')
    if deadline_str:
        try:
            deadline = datetime.fromisoformat(deadline_str)
            if datetime.utcnow() > deadline:
                return True
        except Exception:
            return True
    return False


def _refresh_lock_timer(user_id: int):
    accounts = get_accounts()
    for acc in accounts:
        if acc['user_id'] == user_id:
            acc['lock_deadline'] = (
                datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)
            ).isoformat()
    session['accounts'] = accounts
    session.modified    = True


def vault_access_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        acc_data = get_active_account_data()
        if _is_vault_locked(acc_data):
            return jsonify({'error': 'Vault is locked', 'locked': True}), 423
        _refresh_lock_timer(get_active_user_id())
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────
# Vault-Key Encryption Architecture
# ─────────────────────────────────────────────────────────────

def generate_vault_key() -> bytes:
    return Fernet.generate_key()


def derive_kek(master_password: str, salt: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)


def encrypt_vault_key(vault_key: bytes, kek: Fernet) -> str:
    return kek.encrypt(vault_key).decode()


def decrypt_vault_key(encrypted_vault_key: str, kek: Fernet) -> bytes:
    return kek.decrypt(encrypted_vault_key.encode())


def get_user_vault_fernet(user: User, master_password: str) -> Fernet | None:
    if not master_password or not user.encrypted_vault_key:
        return None
    try:
        kek       = derive_kek(master_password, user.salt)
        vault_key = decrypt_vault_key(user.encrypted_vault_key, kek)
        return Fernet(vault_key)
    except Exception as e:
        print(f"[vault_fernet] Failed for user {user.id}: {e}")
        return None


def migrate_legacy_user(user: User, master_password: str) -> bool:
    try:
        old_fernet = _derive_legacy_fernet(master_password, user.salt)
        vault_key  = generate_vault_key()
        kek        = derive_kek(master_password, user.salt)
        new_fernet = Fernet(vault_key)

        notebooks      = Notebook.query.filter_by(user_id=user.id).all()
        migrated_count = 0
        failed_count   = 0

        for nb in notebooks:
            for entry in nb.entries:
                try:
                    plain = old_fernet.decrypt(entry.encrypted_password.encode()).decode()
                    entry.encrypted_password = new_fernet.encrypt(plain.encode()).decode()
                    migrated_count += 1
                except Exception as e:
                    print(f"[migration] Entry {entry.id} failed: {e}")
                    failed_count += 1

        user.encrypted_vault_key = encrypt_vault_key(vault_key, kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, user.salt)
        user.is_migrated         = True
        db.session.commit()

        print(f"[migration] User {user.id}: {migrated_count} ok, {failed_count} failed.")
        return True

    except Exception as e:
        print(f"[migration] Failed for user {user.id}: {e}")
        db.session.rollback()
        return False


def _derive_legacy_fernet(master_password: str, salt: str) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)


def encrypt_password(plain_text: str, fernet: Fernet) -> str:
    return fernet.encrypt(plain_text.encode()).decode()


def decrypt_password(cipher_text: str, fernet: Fernet) -> str:
    return fernet.decrypt(cipher_text.encode()).decode()


def _get_fernet_from_session(user: User) -> Fernet | None:
    acc_data = get_active_account_data()
    if not acc_data:
        return None
    vault_key_b64 = acc_data.get('vault_key')
    if not vault_key_b64:
        return None
    try:
        vault_key_bytes = base64.b64decode(vault_key_b64.encode('ascii'))
        return Fernet(vault_key_bytes)
    except Exception as e:
        print(f"[fernet] Failed to reconstruct Fernet for user {user.id}: {e}")
        return None


def get_fernet(master_password: str, user: User) -> Fernet | None:
    if not master_password:
        return None
    if user.encrypted_vault_key:
        return get_user_vault_fernet(user, master_password)
    return None


# ─────────────────────────────────────────────────────────────
# Server-side Vault Key Escrow
# ─────────────────────────────────────────────────────────────

def _get_escrow_fernet(salt: str) -> Fernet:
    secret = app.config['SECRET_KEY'].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=(salt + '_escrow').encode(),
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret))
    return Fernet(key)


def _escrow_encrypt_vault_key(vault_key: bytes, salt: str) -> str:
    escrow = _get_escrow_fernet(salt)
    return escrow.encrypt(vault_key).decode()


def _escrow_decrypt_vault_key(user: User) -> bytes | None:
    if not user.escrow_vault_key:
        return None
    try:
        escrow = _get_escrow_fernet(user.salt)
        return escrow.decrypt(user.escrow_vault_key.encode())
    except Exception as e:
        print(f"[escrow] Failed for user {user.id}: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# 2FA Helpers
# ─────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(user: User) -> str:
    totp = pyotp.TOTP(user.totp_secret)
    return totp.provisioning_uri(
        name=user.email,
        issuer_name='VaultKey'
    )


def verify_totp_code(user: User, code: str) -> bool:
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code.replace(' ', ''), valid_window=1)


def generate_backup_codes(count: int = 8) -> tuple[list[str], list[str]]:
    plain_codes  = []
    hashed_codes = []
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    for _ in range(count):
        raw   = ''.join(secrets.choice(alphabet) for _ in range(16))
        plain = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
        plain_codes.append(plain)
        hashed_codes.append(bcrypt.generate_password_hash(raw).decode('utf-8'))
    return plain_codes, hashed_codes


def generate_qr_svg(uri: str) -> str:
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory, box_size=8)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode('utf-8')


# ─────────────────────────────────────────────────────────────
# Security Headers
# ─────────────────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = _CSP
    return response


# ─────────────────────────────────────────────────────────────
# Rate-limit error handler
# ─────────────────────────────────────────────────────────────

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error':   'Too many attempts. Please wait a minute and try again.',
        'limited': True
    }), 429


# ─────────────────────────────────────────────────────────────
# Google OAuth Username Generator
# ─────────────────────────────────────────────────────────────

def _generate_unique_username(base: str) -> str:
    clean     = re.sub(r'[^a-zA-Z0-9_]', '', base)[:30].strip('_') or 'user'
    candidate = clean
    attempts  = 0
    while User.query.filter_by(username=candidate).first():
        candidate = f"{clean}{secrets.randbelow(9000) + 1000}"
        attempts += 1
        if attempts > 20:
            candidate = 'user' + secrets.token_hex(4)
            break
    return candidate


# ─────────────────────────────────────────────────────────────
# Login Manager
# ─────────────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─────────────────────────────────────────────────────────────
# Page Routes
# ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')


@app.route('/2fa')
def two_fa_page():
    if not session.get('2fa_pending_user_id'):
        return redirect(url_for('login_page'))
    return render_template('2fa.html')


@app.route('/dashboard')
@multi_account_required
def dashboard():
    user = get_active_user()
    if user is None:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', user=user)


@app.route('/profile')
@multi_account_required
def profile():
    user = get_active_user()
    if user is None:
        return redirect(url_for('login_page'))
    return render_template('profile.html', user=user)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ─────────────────────────────────────────────────────────────
# Google OAuth Routes
# ─────────────────────────────────────────────────────────────

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/login/google/authorized')
def google_authorized():
    try:
        token = google.authorize_access_token()
    except Exception as e:
        print(f"[Google OAuth] token exchange failed: {e}")
        return redirect(url_for('login_page') + '?error=oauth_failed')

    user_info = token.get('userinfo')

    if not user_info or not user_info.get('email'):
        return redirect(url_for('login_page') + '?error=no_email')

    google_id = user_info.get('sub')
    email     = user_info['email'].lower().strip()
    name      = user_info.get('name', '')
    picture   = user_info.get('picture', '')

    user = User.query.filter_by(google_id=google_id).first()

    if user:
        user.profile_picture = picture
        db.session.commit()
        if user.totp_enabled:
            session['2fa_pending_user_id']   = user.id
            session['2fa_pending_vault_key'] = None
            session['2fa_pending_remember']  = True
            return redirect(url_for('two_fa_page'))
        _add_account_to_session(user, master_password=None)
        login_user(user, remember=True)
        return redirect(url_for('dashboard'))

    user = User.query.filter_by(email=email).first()

    if user:
        user.google_id       = google_id
        user.profile_picture = picture
        db.session.commit()

        if user.totp_enabled:
            session['2fa_pending_user_id']  = user.id
            session['2fa_pending_vault_key'] = None
            session['2fa_pending_remember']  = True
            return redirect(url_for('two_fa_page'))

        _add_account_to_session(user, master_password=None)
        login_user(user, remember=True)
        return redirect(url_for('dashboard'))

    base_username = name.split()[0] if name else email.split('@')[0]
    username      = _generate_unique_username(base_username)
    salt          = secrets.token_hex(32)

    new_user = User(
        username            = username,
        email               = email,
        salt                = salt,
        google_id           = google_id,
        profile_picture     = picture,
        is_migrated         = True,
        encrypted_vault_key = None
    )
    db.session.add(new_user)
    db.session.commit()

    _add_account_to_session(new_user, master_password=None)
    login_user(new_user, remember=True)
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────
# Auth API
# ─────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
@limiter.limit('10 per hour')
def api_register():
    data     = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    salt                = secrets.token_hex(32)
    vault_key           = generate_vault_key()
    kek                 = derive_kek(password, salt)
    encrypted_vault_key = encrypt_vault_key(vault_key, kek)
    escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, salt)

    user = User(
        username            = username,
        email               = email,
        salt                = salt,
        encrypted_vault_key = encrypted_vault_key,
        escrow_vault_key    = escrow_vault_key,
        is_migrated         = True
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Account created successfully'}), 201


@app.route('/api/login', methods=['POST'])
@limiter.limit('20 per minute')
def api_login():
    data       = request.get_json()
    identifier = data.get('identifier', '').strip()
    password   = data.get('password', '')

    user = User.query.filter(
        (User.username == identifier) |
        (User.email == identifier.lower())
    ).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if user.has_password and not user.encrypted_vault_key and not user.is_migrated:
        print(f"[login] Triggering legacy migration for user {user.id}")
        success = migrate_legacy_user(user, password)
        if not success:
            return jsonify({'error': 'Account migration failed. Please contact support.'}), 500

    if user.has_password and not user.encrypted_vault_key:
        vault_key                = generate_vault_key()
        kek                      = derive_kek(password, user.salt)
        user.encrypted_vault_key = encrypt_vault_key(vault_key, kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, user.salt)
        user.is_migrated         = True
        db.session.commit()

    if user.totp_enabled:
        pending_vault_key_b64 = None
        if user.encrypted_vault_key:
            try:
                kek             = derive_kek(password, user.salt)
                vault_key_bytes = decrypt_vault_key(user.encrypted_vault_key, kek)
                pending_vault_key_b64 = base64.b64encode(vault_key_bytes).decode('ascii')
            except Exception as e:
                print(f"[login] 2FA vault key derive failed: {e}")

        session['2fa_pending_user_id']   = user.id
        session['2fa_pending_vault_key'] = pending_vault_key_b64
        session['2fa_pending_remember']  = data.get('remember', False)
        return jsonify({'requires_2fa': True}), 200

    _add_account_to_session(user, password)
    login_user(user, remember=data.get('remember', False))

    return jsonify({
        'message':  'Login successful',
        'username': user.username,
        'user_id':  user.id
    }), 200


@app.route('/api/logout', methods=['POST'])
def api_logout():
    active_id = get_active_user_id()
    if active_id:
        _remove_account_from_session(active_id)
    logout_user()

    if not get_accounts():
        session.clear()

    return jsonify({'message': 'Logged out'}), 200


# ─────────────────────────────────────────────────────────────
# Vault Lock / Unlock APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/vault/lock', methods=['POST'])
@multi_account_required
def lock_vault():
    user_id  = get_active_user_id()
    accounts = get_accounts()
    for acc in accounts:
        if acc['user_id'] == user_id:
            acc['vault_key']     = None
            acc['lock_deadline'] = None
    session['accounts'] = accounts
    session.modified    = True
    return jsonify({'message': 'Vault locked'}), 200


@app.route('/api/vault/unlock', methods=['POST'])
@multi_account_required
@limiter.limit('10 per minute')
def unlock_vault():
    user     = get_active_user()
    data     = request.get_json()
    password = data.get('password', '')

    if not user.has_password:
        return jsonify({
            'error':          'No master password set for this account.',
            'needs_password': True
        }), 400

    if not user.check_password(password):
        return jsonify({'error': 'Incorrect master password'}), 401

    try:
        kek             = derive_kek(password, user.salt)
        vault_key_bytes = decrypt_vault_key(user.encrypted_vault_key, kek)
        vault_key_b64   = base64.b64encode(vault_key_bytes).decode('ascii')
    except Exception as e:
        print(f"[unlock_vault] Failed for user {user.id}: {e}")
        return jsonify({'error': 'Failed to unlock vault'}), 500

    accounts = get_accounts()
    for acc in accounts:
        if acc['user_id'] == user.id:
            acc['vault_key']     = vault_key_b64
            acc['has_password']  = True
            acc['lock_deadline'] = (
                datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)
            ).isoformat()
    session['accounts'] = accounts
    session.modified    = True

    return jsonify({'message': 'Vault unlocked'}), 200


@app.route('/api/vault/status', methods=['GET'])
@multi_account_required
def vault_status():
    acc_data = get_active_account_data()
    locked   = _is_vault_locked(acc_data) if acc_data else True
    user     = get_active_user()
    return jsonify({
        'locked':       locked,
        'lock_timeout': VAULT_LOCK_TIMEOUT,
        'has_password': user.has_password if user else False,
        'is_google':    user.is_google_user if user else False,
    }), 200


# ─────────────────────────────────────────────────────────────
# 2FA APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/2fa/setup', methods=['POST'])
@multi_account_required
def setup_2fa():
    user = get_active_user()

    if user.totp_enabled:
        return jsonify({'error': '2FA is already enabled'}), 400

    secret           = generate_totp_secret()
    user.totp_secret = secret
    db.session.commit()

    uri    = get_totp_uri(user)
    qr_svg = generate_qr_svg(uri)

    return jsonify({
        'secret': secret,
        'uri':    uri,
        'qr_svg': qr_svg
    }), 200


@app.route('/api/2fa/confirm', methods=['POST'])
@multi_account_required
def confirm_2fa():
    user = get_active_user()
    data = request.get_json()
    code = data.get('code', '').strip()

    if not user.totp_secret:
        return jsonify({'error': 'No 2FA setup in progress. Start setup first.'}), 400

    if not verify_totp_code(user, code):
        return jsonify({'error': 'Invalid code. Please try again.'}), 400

    plain_codes, hashed_codes = generate_backup_codes()
    user.set_backup_codes(hashed_codes)
    user.totp_enabled = True
    db.session.commit()

    return jsonify({
        'message':      '2FA enabled successfully',
        'backup_codes': plain_codes
    }), 200


@app.route('/api/2fa/disable', methods=['POST'])
@multi_account_required
def disable_2fa():
    user     = get_active_user()
    data     = request.get_json()
    password = data.get('password', '')

    if not user.totp_enabled:
        return jsonify({'error': '2FA is not enabled'}), 400

    if user.has_password and not user.check_password(password):
        return jsonify({'error': 'Incorrect password'}), 400

    user.totp_enabled = False
    user.totp_secret  = None
    user.backup_codes = None
    db.session.commit()

    return jsonify({'message': '2FA disabled successfully'}), 200


@app.route('/api/2fa/status', methods=['GET'])
@multi_account_required
def get_2fa_status():
    user = get_active_user()
    return jsonify({
        'totp_enabled':       user.totp_enabled,
        'backup_codes_count': len(user.get_backup_codes())
    }), 200


@app.route('/api/2fa/verify-login', methods=['POST'])
@limiter.limit('10 per minute')
def verify_2fa_login():
    pending_id = session.get('2fa_pending_user_id')
    if not pending_id:
        return jsonify({'error': 'No pending 2FA session'}), 401

    user = User.query.get(pending_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    code = data.get('code', '').strip()

    if not verify_totp_code(user, code):
        return jsonify({'error': 'Invalid authentication code'}), 401

    pending_vault_key_b64 = session.pop('2fa_pending_vault_key', None)
    remember              = session.pop('2fa_pending_remember', False)
    session.pop('2fa_pending_user_id', None)

    _complete_2fa_login(user, pending_vault_key_b64, remember)

    return jsonify({'message': 'Login successful', 'username': user.username}), 200


@app.route('/api/2fa/verify-backup', methods=['POST'])
@limiter.limit('10 per minute')
def verify_2fa_backup():
    pending_id = session.get('2fa_pending_user_id')
    if not pending_id:
        return jsonify({'error': 'No pending 2FA session'}), 401

    user = User.query.get(pending_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    code = data.get('code', '').strip()

    if not user.verify_backup_code(code):
        return jsonify({'error': 'Invalid or already-used backup code'}), 401

    pending_vault_key_b64 = session.pop('2fa_pending_vault_key', None)
    remember              = session.pop('2fa_pending_remember', False)
    session.pop('2fa_pending_user_id', None)

    _complete_2fa_login(user, pending_vault_key_b64, remember)

    remaining = len(user.get_backup_codes())
    return jsonify({
        'message':                'Login successful',
        'username':               user.username,
        'backup_codes_remaining': remaining
    }), 200


def _complete_2fa_login(user: User, vault_key_b64: str | None, remember: bool):
    accounts = get_accounts()
    accounts = [a for a in accounts if a['user_id'] != user.id]

    lock_deadline = (
        (datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)).isoformat()
        if vault_key_b64 else None
    )

    accounts.append({
        'user_id':         user.id,
        'username':        user.username,
        'email':           user.email,
        'is_google':       user.google_id is not None,
        'has_password':    user.has_password,
        'profile_picture': user.profile_picture or '',
        'vault_key':       vault_key_b64,
        'lock_deadline':   lock_deadline,
    })

    session['accounts']    = accounts
    session['active_user'] = user.id
    session.permanent      = True
    session.modified       = True

    login_user(user, remember=remember)


@app.route('/api/2fa/regenerate-backup', methods=['POST'])
@multi_account_required
def regenerate_backup_codes():
    user     = get_active_user()
    data     = request.get_json()
    password = data.get('password', '')

    if not user.totp_enabled:
        return jsonify({'error': '2FA is not enabled'}), 400

    if user.has_password and not user.check_password(password):
        return jsonify({'error': 'Incorrect password'}), 400

    plain_codes, hashed_codes = generate_backup_codes()
    user.set_backup_codes(hashed_codes)
    db.session.commit()

    return jsonify({
        'message':      'Backup codes regenerated',
        'backup_codes': plain_codes
    }), 200


# ─────────────────────────────────────────────────────────────
# Multi-Account APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/accounts', methods=['GET'])
def get_accounts_api():
    accounts = get_accounts()
    safe_accounts = [
        {
            'user_id':         a['user_id'],
            'username':        a['username'],
            'email':           a['email'],
            'is_google':       a.get('is_google', False),
            'has_password':    a.get('has_password', False),
            'profile_picture': a.get('profile_picture', '')
        }
        for a in accounts
    ]
    return jsonify({
        'accounts':    safe_accounts,
        'active_user': get_active_user_id()
    })


@app.route('/api/switch-account', methods=['POST'])
def switch_account():
    data    = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    accounts = get_accounts()
    target   = next((a for a in accounts if a['user_id'] == user_id), None)

    if not target:
        return jsonify({'error': 'Account not found in session'}), 404

    session['active_user'] = user_id
    session.modified       = True

    user = User.query.get(user_id)
    if user:
        login_user(user)

    return jsonify({
        'message':  'Switched account',
        'user_id':  user_id,
        'username': target['username'],
        'email':    target['email']
    }), 200


@app.route('/api/logout-current', methods=['POST'])
def logout_current():
    active_id = get_active_user_id()
    if not active_id:
        return jsonify({'error': 'No active account'}), 400

    new_active = _remove_account_from_session(active_id)
    logout_user()

    if new_active:
        new_user = User.query.get(new_active)
        if new_user:
            login_user(new_user)
        return jsonify({
            'message':         'Logged out current account',
            'new_active_user': new_active
        }), 200
    else:
        session.clear()
        return jsonify({
            'message':         'Logged out — no remaining accounts',
            'new_active_user': None
        }), 200


@app.route('/api/logout-all', methods=['POST'])
def logout_all():
    logout_user()
    session.clear()
    return jsonify({'message': 'All accounts logged out'}), 200


# ─────────────────────────────────────────────────────────────
# OTP / Password Reset APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/send-reset-otp', methods=['POST'])
@limiter.limit('5 per hour')
def send_reset_otp():
    data  = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'No account found with this email'}), 404

    if user.is_google_user:
        return jsonify({'error': 'Use Google login for this account'}), 400

    otp = str(secrets.randbelow(900000) + 100000)

    reset_otps[email] = {
        'otp':        otp,
        'expires_at': datetime.utcnow() + timedelta(minutes=10)
    }

    try:
        msg = Message(
            subject    = 'VaultKey — Your Password Reset Code',
            recipients = [email]
        )
        msg.body = (
            f"Hello {user.username},\n\n"
            f"Your VaultKey one-time reset code is:\n\n"
            f"  {otp}\n\n"
            f"This code expires in 10 minutes.\n\n"
            f"If you did not request a password reset, you can safely ignore this email.\n\n"
            f"— The VaultKey Team"
        )
        mail.send(msg)
        print(f"[OTP] Sent to {email}")
        return jsonify({'message': 'Reset code sent. Check your inbox.'}), 200

    except Exception as e:
        reset_otps.pop(email, None)
        print(f"[OTP] Email failed for {email}: {e}")
        return jsonify({'error': 'Failed to send email. Please try again later.'}), 500


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit('10 per hour')
def reset_password():
    data     = request.get_json()
    email    = data.get('email', '').strip().lower()
    otp      = data.get('otp', '').strip()
    password = data.get('password', '')

    stored = reset_otps.get(email)

    if not stored:
        return jsonify({'error': 'No reset code found. Please request a new one.'}), 400

    if stored['otp'] != otp:
        return jsonify({'error': 'Invalid verification code.'}), 400

    if datetime.utcnow() > stored['expires_at']:
        reset_otps.pop(email, None)
        return jsonify({'error': 'Verification code has expired. Please request a new one.'}), 400

    if not password or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    vault_key = _escrow_decrypt_vault_key(user)

    if vault_key:
        new_kek                  = derive_kek(password, user.salt)
        user.encrypted_vault_key = encrypt_vault_key(vault_key, new_kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, user.salt)
    else:
        print(f"[reset_password] No escrow for user {user.id}; generating fresh vault key.")
        new_vault_key            = generate_vault_key()
        new_kek                  = derive_kek(password, user.salt)
        user.encrypted_vault_key = encrypt_vault_key(new_vault_key, new_kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(new_vault_key, user.salt)

    user.is_migrated = True
    user.set_password(password)
    db.session.commit()

    reset_otps.pop(email, None)

    return jsonify({'message': 'Password reset successfully.'}), 200


# ─────────────────────────────────────────────────────────────
# Notebook APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/notebooks', methods=['GET'])
@multi_account_required
def get_notebooks():
    user = get_active_user()
    nbs  = Notebook.query.filter_by(
        user_id=user.id
    ).order_by(Notebook.created_at).all()

    return jsonify([{
        'id':          n.id,
        'name':        n.name,
        'description': n.description,
        'icon':        n.icon,
        'color':       n.color,
        'entry_count': len(n.entries),
        'created_at':  n.created_at.isoformat()
    } for n in nbs])


@app.route('/api/notebooks', methods=['POST'])
@multi_account_required
def create_notebook():
    user = get_active_user()
    data = request.get_json()
    name = data.get('name', '').strip()

    if not name:
        return jsonify({'error': 'Notebook name is required'}), 400

    notebook_exists = Notebook.query.filter(
        Notebook.user_id == user.id,
        db.func.lower(Notebook.name) == name.lower()
    ).first()

    entry_exists = PasswordEntry.query.join(Notebook).filter(
        Notebook.user_id == user.id,
        db.func.lower(PasswordEntry.title) == name.lower()
    ).first()

    if notebook_exists or entry_exists:
        return jsonify({'error': f'"{name}" already exists as a notebook or entry'}), 400

    nb = Notebook(
        name        = name,
        description = data.get('description', ''),
        icon        = data.get('icon', 'shield'),
        color       = data.get('color', '#4f8ef7'),
        user_id     = user.id
    )
    db.session.add(nb)
    db.session.commit()

    return jsonify({'id': nb.id, 'name': nb.name, 'message': 'Notebook created'}), 201


@app.route('/api/notebooks/<int:notebook_id>/duplicate', methods=['POST'])
@multi_account_required
@vault_access_required
def duplicate_notebook(notebook_id):
    user = get_active_user()
    nb   = Notebook.query.filter_by(id=notebook_id, user_id=user.id).first_or_404()

    fernet = _get_fernet_from_session(user)
    if not fernet:
        return jsonify({'error': 'Vault is locked', 'locked': True}), 423

    base               = nb.name + ' (copy)'
    existing_notebooks = Notebook.query.filter_by(user_id=user.id).all()
    taken              = set()
    for n in existing_notebooks:
        if n.name.lower() == base.lower():
            taken.add(0)
        elif n.name.lower().startswith(base.lower() + ' '):
            suffix = n.name[len(base) + 1:]
            if suffix.isdigit():
                taken.add(int(suffix))

    slot     = 0
    while slot in taken:
        slot += 1
    new_name = base if slot == 0 else f'{base} {slot}'

    new_nb = Notebook(
        name        = new_name,
        description = nb.description or '',
        icon        = nb.icon,
        color       = nb.color,
        user_id     = user.id
    )
    db.session.add(new_nb)
    db.session.flush()

    all_existing_entries = PasswordEntry.query.join(Notebook).filter(
        Notebook.user_id == user.id
    ).all()
    existing_titles = {e.title.lower(): e.title for e in all_existing_entries}

    for entry in nb.entries:
        original_title = entry.title
        new_title      = original_title
        if new_title.lower() in existing_titles:
            counter = 1
            while True:
                candidate = f"{original_title} copy {counter}"
                if candidate.lower() not in existing_titles:
                    new_title = candidate
                    break
                counter += 1
        existing_titles[new_title.lower()] = new_title

        try:
            plain     = decrypt_password(entry.encrypted_password, fernet)
            encrypted = encrypt_password(plain, fernet)
        except Exception:
            encrypted = entry.encrypted_password

        new_entry = PasswordEntry(
            title              = new_title,
            username           = entry.username,
            encrypted_password = encrypted,
            url                = entry.url,
            notes              = entry.notes,
            notebook_id        = new_nb.id
        )
        db.session.add(new_entry)

    db.session.commit()
    return jsonify({'id': new_nb.id, 'name': new_nb.name, 'message': 'Notebook duplicated'}), 201


@app.route('/api/notebooks/<int:notebook_id>', methods=['PUT'])
@multi_account_required
def update_notebook(notebook_id):
    user = get_active_user()
    nb   = Notebook.query.filter_by(id=notebook_id, user_id=user.id).first_or_404()
    data = request.get_json()

    if 'name' in data and data['name'].strip():
        new_name = data['name'].strip()

        conflict_notebook = Notebook.query.filter(
            Notebook.user_id == user.id,
            Notebook.id != notebook_id,
            db.func.lower(Notebook.name) == new_name.lower()
        ).first()
        conflict_entry = PasswordEntry.query.join(Notebook).filter(
            Notebook.user_id == user.id,
            db.func.lower(PasswordEntry.title) == new_name.lower()
        ).first()

        if conflict_notebook or conflict_entry:
            return jsonify({'error': f'"{new_name}" already exists as a notebook or entry'}), 400

        nb.name = new_name

    if 'description' in data:
        nb.description = data['description']
    if 'icon' in data:
        nb.icon = data['icon']
    if 'color' in data and data['color']:
        nb.color = data['color']

    db.session.commit()
    return jsonify({'message': 'Notebook updated'})


@app.route('/api/notebooks/<int:notebook_id>', methods=['DELETE'])
@multi_account_required
def delete_notebook(notebook_id):
    user = get_active_user()
    nb   = Notebook.query.filter_by(id=notebook_id, user_id=user.id).first_or_404()
    db.session.delete(nb)
    db.session.commit()
    return jsonify({'message': 'Notebook deleted'})


# ─────────────────────────────────────────────────────────────
# Entry APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/notebooks/<int:notebook_id>/entries', methods=['GET'])
@multi_account_required
def get_entries(notebook_id):
    user = get_active_user()
    nb   = Notebook.query.filter_by(id=notebook_id, user_id=user.id).first_or_404()
    return jsonify([{
        'id':         e.id,
        'title':      e.title,
        'username':   e.username,
        'url':        e.url,
        'notes':      e.notes,
        'created_at': e.created_at.isoformat(),
        'updated_at': e.updated_at.isoformat()
    } for e in nb.entries])


@app.route('/api/notebooks/<int:notebook_id>/entries', methods=['POST'])
@multi_account_required
@vault_access_required
def create_entry(notebook_id):
    user = get_active_user()
    nb   = Notebook.query.filter_by(id=notebook_id, user_id=user.id).first_or_404()
    data = request.get_json()

    title    = data.get('title', '').strip()
    password = data.get('password', '')

    if not title or not password:
        return jsonify({'error': 'Title and password are required'}), 400

    entry_exists = PasswordEntry.query.join(Notebook).filter(
        Notebook.user_id == user.id,
        db.func.lower(PasswordEntry.title) == title.lower()
    ).first()
    notebook_exists = Notebook.query.filter(
        Notebook.user_id == user.id,
        db.func.lower(Notebook.name) == title.lower()
    ).first()

    if entry_exists or notebook_exists:
        return jsonify({'error': f'"{title}" already exists as a notebook or entry'}), 400

    fernet = _get_fernet_from_session(user)
    if not fernet:
        return jsonify({'error': 'Vault is locked', 'locked': True}), 423

    entry = PasswordEntry(
        title              = title,
        username           = data.get('username', ''),
        encrypted_password = encrypt_password(password, fernet),
        url                = data.get('url', ''),
        notes              = data.get('notes', ''),
        notebook_id        = nb.id
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({'id': entry.id, 'message': 'Entry created'}), 201


@app.route('/api/entries/<int:entry_id>/password', methods=['GET'])
@multi_account_required
@vault_access_required
def get_password(entry_id):
    user  = get_active_user()
    entry = PasswordEntry.query.join(Notebook).filter(
        PasswordEntry.id == entry_id,
        Notebook.user_id == user.id
    ).first_or_404()

    fernet = _get_fernet_from_session(user)
    if not fernet:
        return jsonify({'error': 'Vault is locked', 'locked': True}), 423

    try:
        return jsonify({'password': decrypt_password(entry.encrypted_password, fernet)})
    except Exception:
        return jsonify({'error': 'Failed to decrypt password'}), 500


@app.route('/api/entries/<int:entry_id>', methods=['PUT'])
@multi_account_required
@vault_access_required
def update_entry(entry_id):
    user  = get_active_user()
    entry = PasswordEntry.query.join(Notebook).filter(
        PasswordEntry.id == entry_id,
        Notebook.user_id == user.id
    ).first_or_404()

    data      = request.get_json()
    new_title = data.get('title', entry.title).strip()

    if new_title.lower() != entry.title.lower():
        entry_exists = PasswordEntry.query.join(Notebook).filter(
            Notebook.user_id == user.id,
            PasswordEntry.id != entry_id,
            db.func.lower(PasswordEntry.title) == new_title.lower()
        ).first()
        notebook_exists = Notebook.query.filter(
            Notebook.user_id == user.id,
            db.func.lower(Notebook.name) == new_title.lower()
        ).first()
        if entry_exists or notebook_exists:
            return jsonify({'error': f'"{new_title}" already exists as a notebook or entry'}), 400

    entry.title      = new_title
    entry.username   = data.get('username', entry.username)
    entry.url        = data.get('url', entry.url)
    entry.notes      = data.get('notes', entry.notes)
    entry.updated_at = datetime.utcnow()

    new_password = data.get('password', '').strip()
    if new_password:
        fernet = _get_fernet_from_session(user)
        if not fernet:
            return jsonify({'error': 'Vault is locked', 'locked': True}), 423
        entry.encrypted_password = encrypt_password(new_password, fernet)

    db.session.commit()
    return jsonify({'message': 'Entry updated'})


@app.route('/api/entries/<int:entry_id>', methods=['DELETE'])
@multi_account_required
def delete_entry(entry_id):
    user  = get_active_user()
    entry = PasswordEntry.query.join(Notebook).filter(
        PasswordEntry.id == entry_id,
        Notebook.user_id == user.id
    ).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'Entry deleted'})


# ─────────────────────────────────────────────────────────────
# Search API
# ─────────────────────────────────────────────────────────────

@app.route('/api/search', methods=['GET'])
@multi_account_required
def search():
    user = get_active_user()
    q    = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    nb_ids  = [n.id for n in Notebook.query.filter_by(user_id=user.id).all()]
    entries = PasswordEntry.query.filter(
        PasswordEntry.notebook_id.in_(nb_ids),
        (
            PasswordEntry.title.ilike(f'%{q}%')    |
            PasswordEntry.username.ilike(f'%{q}%') |
            PasswordEntry.url.ilike(f'%{q}%')
        )
    ).all()

    return jsonify([{
        'id':          e.id,
        'title':       e.title,
        'username':    e.username,
        'url':         e.url,
        'notebook_id': e.notebook_id
    } for e in entries])


# ─────────────────────────────────────────────────────────────
# Stats API
# ─────────────────────────────────────────────────────────────

@app.route('/api/stats', methods=['GET'])
@multi_account_required
def stats():
    user = get_active_user()
    nbs  = Notebook.query.filter_by(user_id=user.id).all()
    return jsonify({
        'notebooks':    len(nbs),
        'entries':      sum(len(n.entries) for n in nbs),
        'member_since': user.created_at.strftime('%b %Y')
    })


# ─────────────────────────────────────────────────────────────
# Profile APIs
# ─────────────────────────────────────────────────────────────

@app.route('/api/profile/update-account', methods=['PUT'])
@multi_account_required
def update_account():
    user     = get_active_user()
    data     = request.get_json()
    username = data.get('username', '').strip()

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    existing = User.query.filter(
        User.username == username,
        User.id != user.id
    ).first()
    if existing:
        return jsonify({'error': 'Username already taken'}), 400

    user.username = username
    db.session.commit()

    accounts = get_accounts()
    for acc in accounts:
        if acc['user_id'] == user.id:
            acc['username'] = username
    session['accounts'] = accounts
    session.modified    = True

    return jsonify({'message': 'Account updated successfully'})


@app.route('/api/profile/change-password', methods=['PUT'])
@multi_account_required
@limiter.limit('10 per hour')
def change_password():
    user = get_active_user()
    data = request.get_json()

    current_password = data.get('current_password', '')
    new_password     = data.get('new_password', '')

    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    if not user.has_password:
        vault_key                = generate_vault_key()
        new_kek                  = derive_kek(new_password, user.salt)
        user.encrypted_vault_key = encrypt_vault_key(vault_key, new_kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, user.salt)
        user.is_migrated         = True
        user.set_password(new_password)
        db.session.commit()
        _update_session_vault_key(user.id, vault_key)
        return jsonify({'message': 'Master password set successfully', 'password_set': True})

    if not user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400

    try:
        old_kek   = derive_kek(current_password, user.salt)
        vault_key = decrypt_vault_key(user.encrypted_vault_key, old_kek)

        new_kek                  = derive_kek(new_password, user.salt)
        user.encrypted_vault_key = encrypt_vault_key(vault_key, new_kek)
        user.escrow_vault_key    = _escrow_encrypt_vault_key(vault_key, user.salt)
    except Exception as e:
        print(f"[change_password] Vault key re-wrap failed: {e}")
        return jsonify({'error': 'Failed to update vault key. Please try again.'}), 500

    user.set_password(new_password)
    db.session.commit()

    _update_session_vault_key(user.id, vault_key)
    return jsonify({'message': 'Password updated successfully'})


def _update_session_vault_key(user_id: int, vault_key: bytes):
    accounts = get_accounts()
    for acc in accounts:
        if acc['user_id'] == user_id:
            acc['vault_key']     = base64.b64encode(vault_key).decode('ascii')
            acc['has_password']  = True
            acc['lock_deadline'] = (
                datetime.utcnow() + timedelta(seconds=VAULT_LOCK_TIMEOUT)
            ).isoformat()
            acc.pop('master_password', None)
    session['accounts'] = accounts
    session.modified    = True


@app.route('/api/profile/export', methods=['GET'])
@multi_account_required
def export_vault():
    user      = get_active_user()
    notebooks = Notebook.query.filter_by(user_id=user.id).all()
    data = []
    for nb in notebooks:
        entries = []
        for e in nb.entries:
            entries.append({
                'title':      e.title,
                'username':   e.username,
                'url':        e.url,
                'notes':      e.notes,
                'created_at': e.created_at.isoformat()
            })
        data.append({'name': nb.name, 'description': nb.description, 'entries': entries})

    return jsonify({
        'user':        user.username,
        'exported_at': datetime.utcnow().isoformat(),
        'vault':       data
    })


@app.route('/api/profile/delete-all-notebooks', methods=['DELETE'])
@multi_account_required
def delete_all_notebooks():
    user      = get_active_user()
    notebooks = Notebook.query.filter_by(user_id=user.id).all()
    for nb in notebooks:
        db.session.delete(nb)
    db.session.commit()
    return jsonify({'message': 'All notebooks deleted successfully'})


@app.route('/api/profile/delete-account', methods=['DELETE'])
@multi_account_required
def delete_account():
    user     = get_active_user()
    data     = request.get_json()
    password = data.get('password', '')

    if not user.has_password:
        if not password:
            return jsonify({'error': 'Please type your username to confirm deletion'}), 400
        if password.strip().lower() != user.username.lower():
            return jsonify({'error': 'Username does not match'}), 400
    else:
        if not user.check_password(password):
            return jsonify({'error': 'Incorrect password'}), 400

    user_id = user.id
    _remove_account_from_session(user_id)
    logout_user()
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Account deleted successfully'})



# ─────────────────────────────────────────────────────────────
# Run
# CHANGED — removed debug=True, reads PORT from environment
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("DB initialized")

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)